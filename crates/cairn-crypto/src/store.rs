//! Durable client state: MLS group state, key package secrets, and the device key.
//!
//! ## Why this exists
//!
//! Until this module, a Cairn client held all MLS state in memory. Restarting the process
//! destroyed the group, the device's identity key, and the secrets behind any key package
//! it had already published. That is not a missing convenience — a client that cannot
//! resume is not a client, and `docs/10-roadmap.md` M1 names it the blocker everything
//! else waits on.
//!
//! ## What `mls-rs` does and does not do for us
//!
//! `mls-rs` does **not** persist automatically. `process_incoming_message`,
//! `commit`, and `encrypt_application_message` all mutate group state in memory and leave
//! it there until [`Group::write_to_storage`](mls_rs::Group::write_to_storage) is called.
//! Forgetting that call does not fail loudly; it rewinds the group on the next start.
//!
//! For an encrypt in particular, rewinding is worse than lost state. MLS derives message
//! keys from a per-sender generation counter, so a group that resumes from state saved
//! *before* an encrypt sends its next message at a generation it has already spent.
//! Probing that case (two handles loaded from one saved state, each encrypting once) the
//! receiver accepts the first message and rejects the second with `KeyMissing`: it has
//! already consumed and deleted the key for that generation. The message is silently
//! undeliverable, and the sender has no way to tell.
//!
//! It is **not** an AEAD nonce collision. RFC 9420 §7.3.1 anticipates exactly this and
//! mixes a fresh random 4-byte reuse guard into the nonce, which `mls-rs` implements — so
//! the two messages share a key but not a nonce. Thirty-two bits is a bound, not a
//! guarantee, and it is a mitigation for an accident rather than a licence to cause one.
//!
//! [`crate::mls::GroupHandle`] therefore persists after *every* state-changing operation
//! rather than exposing a `save()` for callers to forget.
//!
//! ## What is stored, and in the clear
//!
//! Group state and key package data contain secret key material, and this module writes
//! them to disk **unencrypted**, restricted to the owning user on Unix. That is consistent
//! with `docs/01-threat-model.md` §3.4 — a compromised endpoint is an explicit non-goal —
//! but it is weaker than the platform keystores a shipping client should use, and it is
//! recorded as a gap rather than implied away. Anyone who can read the directory can read
//! the conversation.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use mls_rs::error::IntoAnyError;
use mls_rs::mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs::storage_provider::in_memory::{InMemoryGroupStateStorage, InMemoryKeyPackageStorage};
use mls_rs::{GroupStateStorage, KeyPackageStorage};
use mls_rs_core::group::{EpochRecord, GroupState};
use mls_rs_core::key_package::KeyPackageData;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("client store i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("stored MLS data is malformed: {0}")]
    Codec(#[from] mls_rs::mls_rs_codec::Error),
    #[error("stored device key is corrupt or from an incompatible version: {0}")]
    CorruptDeviceKey(#[from] serde_json::Error),
    #[error("stored device key is malformed")]
    BadDeviceKey,
    #[error(
        "this store holds the device key for a different identity; \
         opening it under another identity would mint a second key for the same directory"
    )]
    IdentityMismatch,
    #[error("could not generate a device key: {0}")]
    KeyGeneration(String),
}

impl IntoAnyError for StoreError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

/// Write via a temporary file and rename.
///
/// `rename` is atomic within a filesystem, so a crash mid-write leaves either the old
/// bytes or the new ones — never a truncated file that fails to decode on the next start
/// and takes the group with it.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    restrict_permissions(&tmp)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Restrict a secret file to its owner.
#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// No portable equivalent on Windows.
///
/// The default ACL on a user-profile directory is usually adequate, but this is weaker
/// than the Unix path and a user should know it. Tracked as a gap rather than silently
/// ignored — the same position `cairn-server`'s storage takes.
#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

/// Discharge a `Result` that cannot fail, without introducing a panic path.
///
/// The in-memory providers declare `Infallible`; `unwrap` would still compile a panic
/// branch into a crate that forbids surprises. Callers name the trait explicitly
/// (`GroupStateStorage::state(s, ..)`) because these types also carry inherent methods of
/// the same name with different return types, and which one method resolution picks has
/// varied between toolchains.
fn infallible<T>(result: Result<T, core::convert::Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(never) => match never {},
    }
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

// ---------------------------------------------------------------------------
// Group state
// ---------------------------------------------------------------------------

/// File-backed MLS group state.
///
/// Layout, rooted at the store directory:
///
/// ```text
/// groups/<hex group id>/state
/// groups/<hex group id>/epochs/<zero-padded epoch id>
/// ```
///
/// Group ids are hex-encoded because MLS chooses them and they are arbitrary bytes; a raw
/// id is not a legal path component on any platform Cairn targets.
#[derive(Clone, Debug)]
pub struct FileGroupStateStorage {
    root: PathBuf,
}

impl FileGroupStateStorage {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn group_dir(&self, group_id: &[u8]) -> PathBuf {
        self.root.join(hex::encode(group_id))
    }

    fn state_path(&self, group_id: &[u8]) -> PathBuf {
        self.group_dir(group_id).join("state")
    }

    fn epoch_dir(&self, group_id: &[u8]) -> PathBuf {
        self.group_dir(group_id).join("epochs")
    }

    /// Zero-padded so that lexical directory order matches epoch order, which makes the
    /// directory readable by a human debugging a stuck client.
    fn epoch_path(&self, group_id: &[u8], epoch_id: u64) -> PathBuf {
        self.epoch_dir(group_id).join(format!("{epoch_id:020}"))
    }

    fn write_epoch(&self, group_id: &[u8], record: &EpochRecord) -> Result<(), StoreError> {
        write_atomic(&self.epoch_path(group_id, record.id), &record.data)
    }
}

impl GroupStateStorage for FileGroupStateStorage {
    type Error = StoreError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        Ok(read_optional(&self.state_path(group_id))?.map(Zeroizing::new))
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        Ok(read_optional(&self.epoch_path(group_id, epoch_id))?.map(Zeroizing::new))
    }

    /// Epochs are written before the state that refers to them.
    ///
    /// A crash between the two leaves epoch records the state does not yet mention, which
    /// is inert. The reverse order would leave a state referring to epoch secrets that
    /// were never written — a group that loads and then fails to decrypt.
    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        fs::create_dir_all(self.epoch_dir(&state.id))?;

        for record in epoch_inserts.iter().chain(epoch_updates.iter()) {
            self.write_epoch(&state.id, record)?;
        }

        write_atomic(&self.state_path(&state.id), &state.data)
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        let dir = match fs::read_dir(self.epoch_dir(group_id)) {
            Ok(dir) => dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let mut max = None;
        for entry in dir {
            let name = entry?.file_name();
            // A `.tmp` left by an interrupted write is not an epoch. Skipping unparseable
            // names rather than erroring keeps a torn write from bricking the group.
            if let Some(id) = name.to_str().and_then(|n| n.parse::<u64>().ok()) {
                max = Some(max.map_or(id, |m: u64| m.max(id)));
            }
        }
        Ok(max)
    }
}

/// The group state backend a [`crate::mls::Session`] uses.
///
/// A single concrete type so that ephemeral and persistent sessions share one
/// `Client` configuration. Making [`crate::mls::Session`] generic over its storage would
/// push that parameter through `cairn-client-core` and out to every caller, for no gain.
#[derive(Clone, Debug)]
pub struct GroupStore(GroupBackend);

#[derive(Clone, Debug)]
enum GroupBackend {
    Memory(InMemoryGroupStateStorage),
    File(FileGroupStateStorage),
}

impl GroupStore {
    /// State that dies with the process. For tests and one-shot tools.
    pub fn in_memory() -> Self {
        Self(GroupBackend::Memory(InMemoryGroupStateStorage::new()))
    }

    pub fn file(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        Ok(Self(GroupBackend::File(FileGroupStateStorage::new(root)?)))
    }
}

impl GroupStateStorage for GroupStore {
    type Error = StoreError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        match &self.0 {
            GroupBackend::Memory(s) => Ok(infallible(GroupStateStorage::state(s, group_id))),
            GroupBackend::File(s) => s.state(group_id),
        }
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        match &self.0 {
            GroupBackend::Memory(s) => {
                Ok(infallible(GroupStateStorage::epoch(s, group_id, epoch_id)))
            }
            GroupBackend::File(s) => s.epoch(group_id, epoch_id),
        }
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        match &mut self.0 {
            GroupBackend::Memory(s) => {
                infallible(GroupStateStorage::write(s, state, epoch_inserts, epoch_updates));
                Ok(())
            }
            GroupBackend::File(s) => s.write(state, epoch_inserts, epoch_updates),
        }
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        match &self.0 {
            GroupBackend::Memory(s) => Ok(infallible(GroupStateStorage::max_epoch_id(s, group_id))),
            GroupBackend::File(s) => s.max_epoch_id(group_id),
        }
    }
}

// ---------------------------------------------------------------------------
// Key packages
// ---------------------------------------------------------------------------

/// File-backed key package secrets.
///
/// A key package is published to the server so others can add this device to a group. The
/// *secrets* behind it stay here. Losing them means every already-published key package is
/// undeadable: a welcome addressed to it can never be opened, and the invitation silently
/// fails. That is why this has to persist alongside group state and not only in memory.
#[derive(Clone, Debug)]
pub struct FileKeyPackageStorage {
    root: PathBuf,
}

impl FileKeyPackageStorage {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn path(&self, id: &[u8]) -> PathBuf {
        self.root.join(hex::encode(id))
    }
}

impl KeyPackageStorage for FileKeyPackageStorage {
    type Error = StoreError;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        match fs::remove_file(self.path(id)) {
            Ok(()) => Ok(()),
            // `mls-rs` deletes a key package once it has been used to join. Doing that
            // twice is not an error, and treating it as one would fail a legitimate join.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        write_atomic(&self.path(&id), &pkg.mls_encode_to_vec()?)
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        match read_optional(&self.path(id))? {
            Some(bytes) => Ok(Some(KeyPackageData::mls_decode(&mut bytes.as_slice())?)),
            None => Ok(None),
        }
    }
}

/// The key package backend a [`crate::mls::Session`] uses. See [`GroupStore`].
#[derive(Clone, Debug)]
pub struct KeyPackageStore(KeyPackageBackend);

#[derive(Clone, Debug)]
enum KeyPackageBackend {
    Memory(InMemoryKeyPackageStorage),
    File(FileKeyPackageStorage),
}

impl KeyPackageStore {
    pub fn in_memory() -> Self {
        Self(KeyPackageBackend::Memory(InMemoryKeyPackageStorage::new()))
    }

    pub fn file(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        Ok(Self(KeyPackageBackend::File(FileKeyPackageStorage::new(root)?)))
    }
}

impl KeyPackageStorage for KeyPackageStore {
    type Error = StoreError;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        match &mut self.0 {
            KeyPackageBackend::Memory(s) => {
                infallible(KeyPackageStorage::delete(s, id));
                Ok(())
            }
            KeyPackageBackend::File(s) => s.delete(id),
        }
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        match &mut self.0 {
            KeyPackageBackend::Memory(s) => {
                infallible(KeyPackageStorage::insert(s, id, pkg));
                Ok(())
            }
            KeyPackageBackend::File(s) => s.insert(id, pkg),
        }
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        match &self.0 {
            KeyPackageBackend::Memory(s) => Ok(infallible(KeyPackageStorage::get(s, id))),
            KeyPackageBackend::File(s) => s.get(id),
        }
    }
}

// ---------------------------------------------------------------------------
// Device identity
// ---------------------------------------------------------------------------

/// A device's long-term signature keypair.
///
/// This is the key the server has on file for the device, so regenerating it does not
/// produce a fresh start — it produces a device the server will not authenticate and a
/// safety number every contact reads as *changed*, which is the same signal a malicious
/// server's key substitution produces (`docs/01-threat-model.md` §4). Losing this file is
/// therefore not recoverable in place, and this module never silently replaces one.
pub struct DeviceKey {
    pub identity: Vec<u8>,
    pub public: Vec<u8>,
    secret: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceKey")
            .field("identity", &hex::encode(&self.identity))
            .field("public", &hex::encode(&self.public))
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct DeviceKeyFile {
    /// Hex throughout, so a user can inspect and back the file up without tooling.
    identity: String,
    public: String,
    secret: String,
}

impl DeviceKey {
    pub fn new(identity: Vec<u8>, public: Vec<u8>, secret: Vec<u8>) -> Self {
        Self { identity, public, secret: Zeroizing::new(secret) }
    }

    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Read the device key at `path`, or `None` if there is none yet.
    ///
    /// Only a genuinely absent file yields `None`. A permission error or a corrupt file
    /// surfaces, because the caller's next move on `None` is to mint a replacement key,
    /// and doing that over a key that merely could not be read would lock the device out
    /// of its own account.
    pub fn load(path: &Path) -> Result<Option<Self>, StoreError> {
        let Some(bytes) = read_optional(path)? else {
            return Ok(None);
        };
        let file: DeviceKeyFile = serde_json::from_slice(&bytes)?;
        let identity = hex::decode(&file.identity).map_err(|_| StoreError::BadDeviceKey)?;
        let public = hex::decode(&file.public).map_err(|_| StoreError::BadDeviceKey)?;
        let secret = hex::decode(&file.secret).map_err(|_| StoreError::BadDeviceKey)?;
        if public.is_empty() || secret.is_empty() {
            return Err(StoreError::BadDeviceKey);
        }
        Ok(Some(Self { identity, public, secret: Zeroizing::new(secret) }))
    }

    pub fn save(&self, path: &Path) -> Result<(), StoreError> {
        let file = DeviceKeyFile {
            identity: hex::encode(&self.identity),
            public: hex::encode(&self.public),
            secret: hex::encode(&self.secret),
        };
        write_atomic(path, &serde_json::to_vec(&file)?)
    }
}

/// The on-disk home of one device's client state.
///
/// One directory per device, holding everything that must survive a restart. Two devices
/// must not share one: they would overwrite each other's device key and interleave their
/// group state.
#[derive(Clone, Debug)]
pub struct ClientStore {
    root: PathBuf,
}

impl ClientStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        restrict_dir_permissions(&root)?;
        Ok(Self { root })
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn device_key_path(&self) -> PathBuf {
        self.root.join("device.key")
    }

    pub fn group_store(&self) -> Result<GroupStore, StoreError> {
        GroupStore::file(self.root.join("groups"))
    }

    pub fn key_package_store(&self) -> Result<KeyPackageStore, StoreError> {
        KeyPackageStore::file(self.root.join("key-packages"))
    }

    /// Load this device's key, or mint and persist one on first run.
    ///
    /// Refuses to hand back a key stored under a different identity. Without that check,
    /// pointing two accounts at one directory would have the second silently adopt the
    /// first's key, and every message it sent would be attributed to the first account.
    pub fn load_or_create_device_key(
        &self,
        identity: &[u8],
        generate: impl FnOnce() -> Result<(Vec<u8>, Vec<u8>), StoreError>,
    ) -> Result<DeviceKey, StoreError> {
        let path = self.device_key_path();
        if let Some(existing) = DeviceKey::load(&path)? {
            if existing.identity != identity {
                return Err(StoreError::IdentityMismatch);
            }
            return Ok(existing);
        }

        let (public, secret) = generate()?;
        let key = DeviceKey::new(identity.to_vec(), public, secret);
        key.save(&path)?;
        Ok(key)
    }
}

/// Keep the store directory itself owner-only.
///
/// The individual files are already 0600, but a permissive directory still leaks the group
/// ids and the number of conversations to anyone on the machine.
#[cfg(unix)]
fn restrict_dir_permissions(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_dir_permissions(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("cairn-store-tests")
            .join(format!("{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn group_state_survives_a_new_storage_handle() {
        let dir = scratch("group-state");
        let mut store = FileGroupStateStorage::new(&dir).unwrap();

        let state = GroupState { id: b"group-1".to_vec(), data: Zeroizing::new(vec![1, 2, 3]) };
        store.write(state, vec![EpochRecord::new(0, Zeroizing::new(vec![9]))], Vec::new()).unwrap();

        // A fresh handle is what a restarted process gets.
        let reopened = FileGroupStateStorage::new(&dir).unwrap();
        assert_eq!(reopened.state(b"group-1").unwrap().map(|s| s.to_vec()), Some(vec![1, 2, 3]));
        assert_eq!(reopened.epoch(b"group-1", 0).unwrap().map(|s| s.to_vec()), Some(vec![9]));
        assert_eq!(reopened.max_epoch_id(b"group-1").unwrap(), Some(0));
    }

    #[test]
    fn an_absent_group_reads_as_absent_not_as_an_error() {
        let dir = scratch("absent-group");
        let store = FileGroupStateStorage::new(&dir).unwrap();
        assert!(store.state(b"never-written").unwrap().is_none());
        assert!(store.epoch(b"never-written", 7).unwrap().is_none());
        assert!(store.max_epoch_id(b"never-written").unwrap().is_none());
    }

    #[test]
    fn max_epoch_id_is_numeric_not_lexical() {
        // `9` vs `10` sorts the wrong way as text, and mls-rs uses this value to decide
        // which epoch secrets it may still need.
        let dir = scratch("max-epoch");
        let mut store = FileGroupStateStorage::new(&dir).unwrap();
        let inserts: Vec<_> = [0u64, 9, 10, 2]
            .iter()
            .map(|i| EpochRecord::new(*i, Zeroizing::new(vec![0])))
            .collect();
        let state = GroupState { id: b"g".to_vec(), data: Zeroizing::new(vec![0]) };
        store.write(state, inserts, Vec::new()).unwrap();
        assert_eq!(store.max_epoch_id(b"g").unwrap(), Some(10));
    }

    #[test]
    fn a_key_package_round_trips_and_deletes_idempotently() {
        let dir = scratch("key-packages");
        let mut store = FileKeyPackageStorage::new(&dir).unwrap();

        let data = KeyPackageData::new(vec![1, 2, 3], vec![4, 5].into(), vec![6, 7].into(), 42);
        store.insert(b"kp-1".to_vec(), data).unwrap();

        let reopened = FileKeyPackageStorage::new(&dir).unwrap();
        let loaded = reopened.get(b"kp-1").unwrap().expect("key package must survive a restart");
        assert_eq!(loaded.key_package_bytes, vec![1, 2, 3]);
        assert_eq!(loaded.expiration, 42);

        store.delete(b"kp-1").unwrap();
        assert!(store.get(b"kp-1").unwrap().is_none());
        // mls-rs deletes on a successful join; a second delete must not fail.
        store.delete(b"kp-1").unwrap();
    }

    #[test]
    fn a_device_key_round_trips() {
        let dir = scratch("device-key");
        let store = ClientStore::open(&dir).unwrap();

        let created = store
            .load_or_create_device_key(b"alice@instance", || Ok((vec![1; 32], vec![2; 32])))
            .unwrap();
        assert_eq!(created.public, vec![1; 32]);

        // The second call must not mint a new key: the server has the first one on file.
        let reopened = ClientStore::open(&dir).unwrap();
        let loaded = reopened
            .load_or_create_device_key(b"alice@instance", || {
                panic!("must not regenerate a key that already exists")
            })
            .unwrap();
        assert_eq!(loaded.public, created.public);
        assert_eq!(loaded.secret(), created.secret());
    }

    #[test]
    fn a_store_refuses_a_second_identity() {
        let dir = scratch("identity-mismatch");
        let store = ClientStore::open(&dir).unwrap();
        store.load_or_create_device_key(b"alice", || Ok((vec![1; 32], vec![2; 32]))).unwrap();

        let err = store
            .load_or_create_device_key(b"bob", || Ok((vec![3; 32], vec![4; 32])))
            .expect_err("bob must not inherit alice's device key");
        assert!(matches!(err, StoreError::IdentityMismatch));
    }

    #[test]
    fn a_corrupt_device_key_is_an_error_not_a_fresh_start() {
        // Minting a replacement over an unreadable key would lock the device out of its
        // own account and read to every contact as a key change.
        let dir = scratch("corrupt-device-key");
        let store = ClientStore::open(&dir).unwrap();
        fs::write(store.device_key_path(), b"not json").unwrap();

        let err = store
            .load_or_create_device_key(b"alice", || panic!("must not regenerate over a bad key"))
            .expect_err("a corrupt key file must surface");
        assert!(matches!(err, StoreError::CorruptDeviceKey(_)));
    }

    #[test]
    fn a_device_key_does_not_print_its_secret() {
        let key = DeviceKey::new(b"alice".to_vec(), vec![1; 32], vec![0xAB; 32]);
        let printed = format!("{key:?}");
        assert!(printed.contains("<redacted>"));
        assert!(!printed.contains("abab"), "the secret must not reach a log: {printed}");
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch("permissions");
        let store = ClientStore::open(&dir).unwrap();
        store.load_or_create_device_key(b"alice", || Ok((vec![1; 32], vec![2; 32]))).unwrap();

        let mode = fs::metadata(store.device_key_path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the device key must not be world-readable");

        let dir_mode = fs::metadata(store.path()).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700);
    }
}
