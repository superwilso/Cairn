//! Durable instance state.
//!
//! ## Why this exists
//!
//! Two properties, and the first is the one that bites silently. The franking key must
//! survive a restart: regenerating it does not merely inconvenience anyone, it invalidates
//! **every franking tag the instance ever issued**, so a report a user filed yesterday
//! cannot be verified today. A moderation mechanism that forgets its own evidence on
//! restart does not work.
//!
//! The second is cost. The previous implementation held a JSON snapshot and rewrote all of
//! it on every message, which is O(messages) per message and therefore quadratic over a
//! conversation's life. See [ADR-007](../../../docs/adr/007-server-storage.md).
//!
//! ## Shape
//!
//! The trait is deliberately **not** `save_state(&Everything)`. That signature is what
//! made the old design quadratic, and any implementation behind it would have inherited
//! the same cost — the seam has to expose *what changed*, not the whole world, or the
//! database underneath cannot help.
//!
//! So: [`Write`] records one changed thing, and [`Storage::commit`] applies a batch
//! atomically. Callers that must not be torn apart by a crash — advancing a room's
//! sequence number and storing the message that consumed it — pass both in one batch.
//!
//! The message log is **not** loaded into memory. Everything else is: accounts, devices,
//! rooms, invites, and key packages are bounded by how many people use the instance, while
//! messages grow without bound and will hold attachment bytes.
//!
//! ## The franking key stays a file
//!
//! Not a row. It is the one piece of state whose loss is unrecoverable, so keeping it
//! outside the database keeps the backup instruction simple and the blast radius of a
//! corrupt database smaller.

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use redb::{Database, Error as RedbError, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};

use cairn_crypto::franking::ServerFrankingKey;
use cairn_proto::{BlobId, DeviceId, RoomId, UserId, Username};

use crate::state::{
    AccountRecord, BlobRecord, DeviceRecord, InviteRecord, RegistrationPolicy, Room, StoredMessage,
};

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("storage i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("stored state is corrupt or from an incompatible version: {0}")]
    Corrupt(#[from] serde_json::Error),
    #[error("stored franking key is malformed: expected 32 bytes")]
    BadKey,
    /// Boxed because `redb::Error` is large, and this variant is reachable from
    /// `ServerError`, which is the `Err` half of nearly every call in `state.rs` — an
    /// unboxed one makes every `Result` in the server that size.
    #[error("database error: {0}")]
    Db(#[source] Box<RedbError>),
    /// A database written by a future version. Refusing is the point: opening it anyway
    /// would mean interpreting records under the wrong rules.
    #[error("database schema version {found} is newer than this build understands ({known})")]
    SchemaTooNew { found: u32, known: u32 },
    #[error(
        "the franking key is missing but this instance already holds data; \
         restore franking.key from backup — starting without it would invalidate \
         every abuse report this instance has ever issued"
    )]
    FrankingKeyMissing,
}

impl From<RedbError> for StorageError {
    fn from(e: RedbError) -> Self {
        Self::Db(Box::new(e))
    }
}

/// What this build writes and can read.
const SCHEMA_VERSION: u32 = 1;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const ROOMS: TableDefinition<&str, &[u8]> = TableDefinition::new("rooms");
const ACCOUNTS: TableDefinition<&str, &[u8]> = TableDefinition::new("accounts");
const DEVICES: TableDefinition<&str, &[u8]> = TableDefinition::new("devices");
const INVITES: TableDefinition<&str, &[u8]> = TableDefinition::new("invites");
const KEY_PACKAGES: TableDefinition<&str, &[u8]> = TableDefinition::new("key_packages");
/// Handle → account. Keyed by the *normalised* username, so the table cannot hold two rows
/// that a user would read as the same name.
const USERNAMES: TableDefinition<&str, &[u8]> = TableDefinition::new("usernames");
/// Keyed by `(room id, server_seq)` so a room's messages are contiguous and a fetch after
/// a cursor is a range scan rather than a filter over everything.
const MESSAGES: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("messages");
/// Attachment metadata — which room a blob belongs to, and who uploaded it.
///
/// Split from the bytes so an access check does not have to load the payload. Answering
/// "may this account read this blob?" by first reading 25 MiB off disk would make the
/// check itself a denial-of-service vector.
const BLOB_META: TableDefinition<&str, &[u8]> = TableDefinition::new("blob_meta");
/// Attachment ciphertext. Opaque to the server, which never holds the key.
const BLOB_BYTES: TableDefinition<&str, &[u8]> = TableDefinition::new("blob_bytes");

/// Everything an instance holds except the message log.
///
/// Bounded by the number of people and rooms on the instance rather than by traffic, which
/// is why it is loaded into memory at start and the message log is not.
#[derive(Debug, Default)]
pub struct Directory {
    pub rooms: Vec<(RoomId, Room)>,
    pub devices: Vec<(DeviceId, DeviceRecord)>,
    pub accounts: Vec<(UserId, AccountRecord)>,
    pub invites: Vec<(String, InviteRecord)>,
    pub key_packages: Vec<(DeviceId, VecDeque<String>)>,
    pub usernames: Vec<(Username, UserId)>,
    pub registration_policy: RegistrationPolicy,
}

/// One changed record.
///
/// Deliberately fine-grained. A coarser API — "save the world" — is what made the previous
/// storage quadratic, and no database behind the seam can fix a caller that hands it
/// everything on every write.
#[derive(Debug, Clone)]
pub enum Write {
    Room(RoomId, Room),
    Account(UserId, AccountRecord),
    Device(DeviceId, DeviceRecord),
    Invite(String, InviteRecord),
    KeyPackages(DeviceId, VecDeque<String>),
    Policy(RegistrationPolicy),
    Username(Username, UserId),
    Message(RoomId, StoredMessage),
    /// Metadata and ciphertext together: a blob whose bytes landed without its metadata
    /// would be unreachable and unattributable, and one whose metadata landed without its
    /// bytes would be a dangling reference a member could fetch and get nothing for.
    Blob(BlobId, BlobRecord, Vec<u8>),
}

/// Where an instance keeps what must survive a restart.
pub trait Storage: Send + Sync + std::fmt::Debug {
    /// Load the franking key, generating and persisting one on first run.
    ///
    /// Generating a *new* key when one should exist would silently invalidate history, so
    /// implementations must distinguish "no key yet" from "could not read the key" and
    /// fail loudly on the latter.
    fn load_or_create_franking_key(&self) -> Result<ServerFrankingKey, StorageError>;

    /// Everything except messages, read once at start.
    fn load_directory(&self) -> Result<Directory, StorageError>;

    /// Apply a batch atomically. Either every write lands or none does.
    fn commit(&self, writes: &[Write]) -> Result<(), StorageError>;

    /// Messages in a room with `server_seq` strictly greater than `after`, in order.
    fn messages_since(&self, room: RoomId, after: u64) -> Result<Vec<StoredMessage>, StorageError>;

    /// A blob's metadata, without its bytes. Used for the access check.
    fn blob_meta(&self, id: BlobId) -> Result<Option<BlobRecord>, StorageError>;

    /// A blob's ciphertext. Call only after the access check has passed.
    fn blob_bytes(&self, id: BlobId) -> Result<Option<Vec<u8>>, StorageError>;
}

/// A `redb`-backed store.
#[derive(Debug)]
pub struct DbStorage {
    dir: PathBuf,
    db: Database,
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    /// Hex, so the file is inspectable by an operator who needs to back it up.
    franking_key: String,
}

impl DbStorage {
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let db = Database::create(dir.join("cairn.redb")).map_err(RedbError::from)?;

        let store = Self { dir, db };
        store.check_schema_version()?;
        store.import_legacy_snapshot()?;
        Ok(store)
    }

    /// Refuse a database from a future build rather than misinterpreting its records.
    fn check_schema_version(&self) -> Result<(), StorageError> {
        let tx = self.db.begin_write().map_err(RedbError::from)?;
        {
            let mut meta = tx.open_table(META).map_err(RedbError::from)?;
            let found = meta
                .get("schema_version")
                .map_err(RedbError::from)?
                .map(|v| serde_json::from_slice::<u32>(v.value()))
                .transpose()?;
            match found {
                Some(v) if v > SCHEMA_VERSION => {
                    return Err(StorageError::SchemaTooNew { found: v, known: SCHEMA_VERSION });
                }
                Some(_) => {}
                None => {
                    let bytes = serde_json::to_vec(&SCHEMA_VERSION)?;
                    meta.insert("schema_version", bytes.as_slice()).map_err(RedbError::from)?;
                }
            }
        }
        tx.commit().map_err(RedbError::from)?;
        Ok(())
    }

    fn key_path(&self) -> PathBuf {
        self.dir.join("franking.key")
    }

    /// Has anyone used this instance?
    ///
    /// Accounts and rooms rather than messages: an instance can hold accounts and no
    /// traffic, and it has still issued identities worth protecting. Only a database with
    /// neither counts as new.
    fn holds_data(&self) -> Result<bool, StorageError> {
        let tx = self.db.begin_read().map_err(RedbError::from)?;
        for table in [ACCOUNTS, ROOMS] {
            match tx.open_table(table) {
                Ok(t) => {
                    if t.len().map_err(RedbError::from)? > 0 {
                        return Ok(true);
                    }
                }
                Err(redb::TableError::TableDoesNotExist(_)) => {}
                Err(e) => return Err(RedbError::from(e).into()),
            }
        }
        Ok(false)
    }

    /// Write via a temporary file and rename.
    ///
    /// `rename` is atomic within a filesystem, so a crash mid-write leaves either the old
    /// file or the new one — never a half-written file that fails to parse on restart and
    /// takes the instance's history with it.
    fn write_atomic(path: &Path, bytes: &[u8], secret: bool) -> Result<(), StorageError> {
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, bytes)?;
        if secret {
            restrict_permissions(&tmp)?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// Restrict a secret file to its owner.
#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// No portable equivalent on Windows.
///
/// The default ACL on a user-profile directory is usually adequate, but this is weaker
/// than the Unix path and an operator should know it. Tracked as a gap rather than
/// silently ignored.
#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<(), StorageError> {
    Ok(())
}

/// Apply a batch inside one already-open write transaction.
fn apply(tx: &redb::WriteTransaction, writes: &[Write]) -> Result<(), StorageError> {
    for write in writes {
        match write {
            Write::Room(id, room) => {
                let mut t = tx.open_table(ROOMS).map_err(RedbError::from)?;
                t.insert(id.to_string().as_str(), serde_json::to_vec(room)?.as_slice())
                    .map_err(RedbError::from)?;
            }
            Write::Account(id, rec) => {
                let mut t = tx.open_table(ACCOUNTS).map_err(RedbError::from)?;
                t.insert(id.to_string().as_str(), serde_json::to_vec(rec)?.as_slice())
                    .map_err(RedbError::from)?;
            }
            Write::Device(id, rec) => {
                let mut t = tx.open_table(DEVICES).map_err(RedbError::from)?;
                t.insert(id.to_string().as_str(), serde_json::to_vec(rec)?.as_slice())
                    .map_err(RedbError::from)?;
            }
            Write::Invite(token, rec) => {
                let mut t = tx.open_table(INVITES).map_err(RedbError::from)?;
                t.insert(token.as_str(), serde_json::to_vec(rec)?.as_slice())
                    .map_err(RedbError::from)?;
            }
            Write::KeyPackages(device, packages) => {
                let mut t = tx.open_table(KEY_PACKAGES).map_err(RedbError::from)?;
                t.insert(device.to_string().as_str(), serde_json::to_vec(packages)?.as_slice())
                    .map_err(RedbError::from)?;
            }
            Write::Username(name, user) => {
                let mut t = tx.open_table(USERNAMES).map_err(RedbError::from)?;
                t.insert(name.as_str(), serde_json::to_vec(user)?.as_slice())
                    .map_err(RedbError::from)?;
            }
            Write::Policy(policy) => {
                let mut t = tx.open_table(META).map_err(RedbError::from)?;
                t.insert("registration_policy", serde_json::to_vec(policy)?.as_slice())
                    .map_err(RedbError::from)?;
            }
            Write::Blob(id, record, bytes) => {
                let key = id.to_string();
                let mut meta = tx.open_table(BLOB_META).map_err(RedbError::from)?;
                meta.insert(key.as_str(), serde_json::to_vec(record)?.as_slice())
                    .map_err(RedbError::from)?;
                let mut payload = tx.open_table(BLOB_BYTES).map_err(RedbError::from)?;
                payload.insert(key.as_str(), bytes.as_slice()).map_err(RedbError::from)?;
            }
            Write::Message(room, message) => {
                let mut t = tx.open_table(MESSAGES).map_err(RedbError::from)?;
                t.insert(
                    (room.to_string().as_str(), message.server_seq),
                    serde_json::to_vec(message)?.as_slice(),
                )
                .map_err(RedbError::from)?;
            }
        }
    }
    Ok(())
}

impl Storage for DbStorage {
    fn load_or_create_franking_key(&self) -> Result<ServerFrankingKey, StorageError> {
        let path = self.key_path();
        match fs::read_to_string(&path) {
            Ok(contents) => {
                let parsed: KeyFile = serde_json::from_str(&contents)?;
                let bytes = hex::decode(&parsed.franking_key).map_err(|_| StorageError::BadKey)?;
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| StorageError::BadKey)?;
                Ok(ServerFrankingKey::from_bytes(bytes))
            }
            // Only a genuinely absent file justifies minting a new key. Any other error —
            // permissions, a corrupt file, a full disk — must surface, because silently
            // generating a replacement would discard the ability to verify past reports.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // And "absent" is only innocent on a genuinely new instance. A missing key
                // beside a populated database means the operator lost it — restoring the
                // data volume without `franking.key`, most likely, which
                // `docs/11-self-hosting.md` warns about. Minting a replacement there looks
                // exactly like a working instance while every report filed before the loss
                // silently stops verifying, so it is refused instead.
                if self.holds_data()? {
                    return Err(StorageError::FrankingKeyMissing);
                }
                let key = ServerFrankingKey::generate();
                let file = KeyFile { franking_key: hex::encode(key.to_bytes()) };
                Self::write_atomic(&path, serde_json::to_string(&file)?.as_bytes(), true)?;
                Ok(key)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn load_directory(&self) -> Result<Directory, StorageError> {
        let tx = self.db.begin_read().map_err(RedbError::from)?;
        let mut dir = Directory::default();

        // A table that was never written does not exist yet, which is not an error — it is
        // an instance nobody has used. Distinguished from a genuine failure below.
        macro_rules! read_all {
            ($table:expr, $out:expr, $parse:expr) => {
                match tx.open_table($table) {
                    Ok(t) => {
                        for entry in t.iter().map_err(RedbError::from)? {
                            let (k, v) = entry.map_err(RedbError::from)?;
                            #[allow(clippy::redundant_closure_call)]
                            if let Some(key) = ($parse)(k.value()) {
                                $out.push((key, serde_json::from_slice(v.value())?));
                            }
                        }
                    }
                    Err(redb::TableError::TableDoesNotExist(_)) => {}
                    Err(e) => return Err(RedbError::from(e).into()),
                }
            };
        }

        read_all!(ROOMS, dir.rooms, |s: &str| s.parse::<RoomId>().ok());
        read_all!(ACCOUNTS, dir.accounts, |s: &str| s.parse::<UserId>().ok());
        read_all!(DEVICES, dir.devices, |s: &str| s.parse::<DeviceId>().ok());
        read_all!(INVITES, dir.invites, |s: &str| Some(s.to_string()));
        read_all!(KEY_PACKAGES, dir.key_packages, |s: &str| s.parse::<DeviceId>().ok());
        read_all!(USERNAMES, dir.usernames, |s: &str| Username::parse(s).ok());

        if let Ok(meta) = tx.open_table(META) {
            if let Some(v) = meta.get("registration_policy").map_err(RedbError::from)? {
                dir.registration_policy = serde_json::from_slice(v.value())?;
            }
        }

        Ok(dir)
    }

    fn blob_meta(&self, id: BlobId) -> Result<Option<BlobRecord>, StorageError> {
        match self.read_blob_table(BLOB_META, id)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    fn blob_bytes(&self, id: BlobId) -> Result<Option<Vec<u8>>, StorageError> {
        self.read_blob_table(BLOB_BYTES, id)
    }

    fn commit(&self, writes: &[Write]) -> Result<(), StorageError> {
        let tx = self.db.begin_write().map_err(RedbError::from)?;
        apply(&tx, writes)?;
        tx.commit().map_err(RedbError::from)?;
        Ok(())
    }

    fn messages_since(&self, room: RoomId, after: u64) -> Result<Vec<StoredMessage>, StorageError> {
        let tx = self.db.begin_read().map_err(RedbError::from)?;
        let table = match tx.open_table(MESSAGES) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(RedbError::from(e).into()),
        };
        let key = room.to_string();
        // Bounded by the room, so a cursor read costs the messages it returns rather than
        // the size of the instance.
        let range = (key.as_str(), after.saturating_add(1))..=(key.as_str(), u64::MAX);
        let mut out = Vec::new();
        for entry in table.range(range).map_err(RedbError::from)? {
            let (_, v) = entry.map_err(RedbError::from)?;
            out.push(serde_json::from_slice(v.value())?);
        }
        Ok(out)
    }
}

impl DbStorage {
    fn read_blob_table(
        &self,
        table: TableDefinition<&'static str, &'static [u8]>,
        id: BlobId,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let tx = self.db.begin_read().map_err(RedbError::from)?;
        let t = match tx.open_table(table) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(RedbError::from(e).into()),
        };
        Ok(t.get(id.to_string().as_str()).map_err(RedbError::from)?.map(|v| v.value().to_vec()))
    }
}

/// Non-persistent storage, for tests and ephemeral instances.
///
/// It really does store, unlike its predecessor: messages no longer live in
/// [`crate::state::Instance`], so a store that discarded them would make an in-memory
/// instance unable to read back its own log.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    inner: Mutex<MemoryInner>,
}

#[derive(Debug, Default)]
struct MemoryInner {
    directory: Directory,
    messages: Vec<(RoomId, StoredMessage)>,
    blobs: Vec<(BlobId, BlobRecord, Vec<u8>)>,
}

impl Storage for MemoryStorage {
    fn load_or_create_franking_key(&self) -> Result<ServerFrankingKey, StorageError> {
        Ok(ServerFrankingKey::generate())
    }

    fn load_directory(&self) -> Result<Directory, StorageError> {
        let inner = self.inner.lock().expect("memory storage mutex poisoned");
        Ok(Directory {
            rooms: inner.directory.rooms.clone(),
            devices: inner.directory.devices.clone(),
            accounts: inner.directory.accounts.clone(),
            invites: inner.directory.invites.clone(),
            key_packages: inner.directory.key_packages.clone(),
            usernames: inner.directory.usernames.clone(),
            registration_policy: inner.directory.registration_policy,
        })
    }

    fn commit(&self, writes: &[Write]) -> Result<(), StorageError> {
        let mut inner = self.inner.lock().expect("memory storage mutex poisoned");
        for write in writes {
            match write {
                Write::Room(id, room) => upsert(&mut inner.directory.rooms, *id, room.clone()),
                Write::Account(id, r) => upsert(&mut inner.directory.accounts, *id, r.clone()),
                Write::Device(id, r) => upsert(&mut inner.directory.devices, *id, r.clone()),
                Write::Invite(t, r) => upsert(&mut inner.directory.invites, t.clone(), r.clone()),
                Write::KeyPackages(d, p) => {
                    upsert(&mut inner.directory.key_packages, *d, p.clone())
                }
                Write::Username(n, u) => upsert(&mut inner.directory.usernames, n.clone(), *u),
                Write::Policy(p) => inner.directory.registration_policy = *p,
                Write::Message(room, m) => inner.messages.push((*room, m.clone())),
                Write::Blob(id, r, b) => inner.blobs.push((*id, r.clone(), b.clone())),
            }
        }
        Ok(())
    }

    fn blob_meta(&self, id: BlobId) -> Result<Option<BlobRecord>, StorageError> {
        Ok(self.blob(id, |(_, r, _)| r.clone()))
    }

    fn blob_bytes(&self, id: BlobId) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.blob(id, |(_, _, b)| b.clone()))
    }

    fn messages_since(&self, room: RoomId, after: u64) -> Result<Vec<StoredMessage>, StorageError> {
        let inner = self.inner.lock().expect("memory storage mutex poisoned");
        let mut out: Vec<StoredMessage> = inner
            .messages
            .iter()
            .filter(|(r, m)| *r == room && m.server_seq > after)
            .map(|(_, m)| m.clone())
            .collect();
        out.sort_by_key(|m| m.server_seq);
        Ok(out)
    }
}

impl MemoryStorage {
    fn blob<T>(&self, id: BlobId, pick: impl Fn(&(BlobId, BlobRecord, Vec<u8>)) -> T) -> Option<T> {
        let inner = self.inner.lock().expect("memory storage mutex poisoned");
        inner.blobs.iter().find(|(b, _, _)| *b == id).map(pick)
    }
}

fn upsert<K: PartialEq, V>(list: &mut Vec<(K, V)>, key: K, value: V) {
    match list.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 = value,
        None => list.push((key, value)),
    }
}

// ---------------------------------------------------------------------------
// Migration from the JSON snapshot
// ---------------------------------------------------------------------------

/// The previous on-disk format, kept only to import it.
///
/// Existing instances hold real state and `docs/11-self-hosting.md` told operators to back
/// up `state.json`, so dropping it on upgrade would be data loss delivered as a release
/// note. Declared here rather than in `state.rs` so the live types are not held hostage to
/// a format nothing writes any more.
#[derive(Deserialize)]
struct LegacyState {
    #[serde(default)]
    rooms: Vec<LegacyRoom>,
    #[serde(default)]
    devices: Vec<LegacyDevice>,
    #[serde(default)]
    accounts: Vec<LegacyAccount>,
    #[serde(default)]
    invites: Vec<LegacyInvite>,
    #[serde(default)]
    key_packages: Vec<LegacyKeyPackages>,
    #[serde(default)]
    registration_policy: RegistrationPolicy,
}

#[derive(Deserialize)]
struct LegacyRoom {
    id: RoomId,
    room: LegacyRoomBody,
}

/// The old `Room`, which carried its whole log inline. Splitting the log back out is the
/// entire point of the migration.
#[derive(Deserialize)]
struct LegacyRoomBody {
    #[serde(flatten)]
    room: Room,
    #[serde(default)]
    log: Vec<StoredMessage>,
}

#[derive(Deserialize)]
struct LegacyDevice {
    id: DeviceId,
    record: DeviceRecord,
}

#[derive(Deserialize)]
struct LegacyAccount {
    id: UserId,
    record: AccountRecord,
}

#[derive(Deserialize)]
struct LegacyInvite {
    token: String,
    record: InviteRecord,
}

#[derive(Deserialize)]
struct LegacyKeyPackages {
    device: DeviceId,
    packages: VecDeque<String>,
}

impl DbStorage {
    /// Import `state.json` on first start, if one exists and the database is empty.
    ///
    /// The old file is left in place. An operator who has to roll back should find their
    /// data where the previous release put it, and an import that deleted its own source
    /// makes that impossible.
    fn import_legacy_snapshot(&self) -> Result<(), StorageError> {
        let legacy_path = self.dir.join("state.json");
        let contents = match fs::read_to_string(&legacy_path) {
            Ok(c) => c,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        // Only import into a database nobody has written yet. Running twice would
        // resurrect records an operator deleted after the first import.
        {
            let tx = self.db.begin_read().map_err(RedbError::from)?;
            let already = match tx.open_table(META) {
                Ok(t) => t.get("imported_legacy_snapshot").map_err(RedbError::from)?.is_some(),
                Err(redb::TableError::TableDoesNotExist(_)) => false,
                Err(e) => return Err(RedbError::from(e).into()),
            };
            if already {
                return Ok(());
            }
        }

        let legacy: LegacyState = serde_json::from_str(&contents)?;

        let mut writes = Vec::new();
        for entry in legacy.rooms {
            writes.push(Write::Room(entry.id, entry.room.room));
            for message in entry.room.log {
                writes.push(Write::Message(entry.id, message));
            }
        }
        for d in legacy.devices {
            writes.push(Write::Device(d.id, d.record));
        }
        for a in legacy.accounts {
            writes.push(Write::Account(a.id, a.record));
        }
        for i in legacy.invites {
            writes.push(Write::Invite(i.token, i.record));
        }
        for k in legacy.key_packages {
            writes.push(Write::KeyPackages(k.device, k.packages));
        }
        writes.push(Write::Policy(legacy.registration_policy));

        // One transaction: a crash part-way through an import must not leave an instance
        // holding half its accounts and none of its rooms.
        let tx = self.db.begin_write().map_err(RedbError::from)?;
        apply(&tx, &writes)?;
        {
            let mut meta = tx.open_table(META).map_err(RedbError::from)?;
            meta.insert("imported_legacy_snapshot", serde_json::to_vec(&true)?.as_slice())
                .map_err(RedbError::from)?;
        }
        tx.commit().map_err(RedbError::from)?;

        tracing::info!(
            path = %legacy_path.display(),
            "imported legacy state.json; the original was left in place"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_proto::{Envelope, EnvelopePayload, RoomSeal, RoomShape, Tier};

    fn dm_shape() -> RoomShape {
        RoomShape { is_direct: true, is_publicly_discoverable: false, member_ceiling: 2 }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cairn-test-{}-{}", name, uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn message(seq: u64) -> StoredMessage {
        StoredMessage {
            envelope: Envelope::new(
                Tier::Private,
                RoomId::new(),
                UserId::new(),
                DeviceId::new(),
                0,
                EnvelopePayload::MlsApplication { ciphertext: vec![1, 2, 3] },
            )
            .unwrap(),
            server_seq: seq,
            franking_tag: None,
        }
    }

    #[test]
    fn franking_key_survives_a_restart() {
        // The property this module exists for. A different key after restart means every
        // previously issued franking tag stops verifying.
        let dir = temp_dir("key");
        let first = DbStorage::new(&dir).unwrap().load_or_create_franking_key().unwrap();
        let second = DbStorage::new(&dir).unwrap().load_or_create_franking_key().unwrap();
        assert_eq!(first.to_bytes(), second.to_bytes());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_corrupt_key_file_is_an_error_not_a_silent_new_key() {
        // Silently minting a replacement would discard the ability to verify history,
        // and would do it without telling the operator.
        let dir = temp_dir("corrupt");
        let storage = DbStorage::new(&dir).unwrap();
        storage.load_or_create_franking_key().unwrap();
        fs::write(dir.join("franking.key"), "not json at all").unwrap();

        assert!(matches!(
            storage.load_or_create_franking_key(),
            Err(StorageError::Corrupt(_)) | Err(StorageError::BadKey)
        ));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_wrong_length_key_is_rejected() {
        let dir = temp_dir("shortkey");
        let storage = DbStorage::new(&dir).unwrap();
        fs::write(dir.join("franking.key"), r#"{"franking_key":"abcd"}"#).unwrap();
        assert!(matches!(storage.load_or_create_franking_key(), Err(StorageError::BadKey)));
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn the_key_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perms");
        DbStorage::new(&dir).unwrap().load_or_create_franking_key().unwrap();
        let mode = fs::metadata(dir.join("franking.key")).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "the franking key must not be readable by other users");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_key_on_a_populated_instance_is_an_error_not_a_new_key() {
        // ADR-007's second probe. Restoring a data volume without `franking.key` is a
        // realistic operator mistake, and the old behaviour — mint a fresh one — produced
        // an instance that looked healthy while every historical report had quietly become
        // unverifiable.
        let dir = temp_dir("lostkey");
        {
            let storage = DbStorage::new(&dir).unwrap();
            storage.load_or_create_franking_key().unwrap();
            storage
                .commit(&[Write::Account(UserId::new(), AccountRecord { devices: vec![] })])
                .unwrap();
        }

        fs::remove_file(dir.join("franking.key")).unwrap();

        let reopened = DbStorage::new(&dir).unwrap();
        assert!(
            matches!(reopened.load_or_create_franking_key(), Err(StorageError::FrankingKeyMissing)),
            "a lost key beside real data must stop the instance, not be replaced"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_brand_new_instance_still_mints_its_first_key() {
        // The counterfactual to the test above: if "missing key" were always an error, a
        // first run could never start.
        let dir = temp_dir("firstrun");
        assert!(DbStorage::new(&dir).unwrap().load_or_create_franking_key().is_ok());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_state_loads_as_empty_rather_than_failing() {
        let dir = temp_dir("empty");
        let dir_state = DbStorage::new(&dir).unwrap().load_directory().unwrap();
        assert!(dir_state.rooms.is_empty());
        assert!(dir_state.accounts.is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_database_from_a_newer_build_is_refused() {
        // Opening it anyway would mean reading records under rules that have since changed.
        let dir = temp_dir("future");
        {
            let storage = DbStorage::new(&dir).unwrap();
            let tx = storage.db.begin_write().unwrap();
            {
                let mut meta = tx.open_table(META).unwrap();
                let bytes = serde_json::to_vec(&(SCHEMA_VERSION + 1)).unwrap();
                meta.insert("schema_version", bytes.as_slice()).unwrap();
            }
            tx.commit().unwrap();
        }
        assert!(matches!(DbStorage::new(&dir), Err(StorageError::SchemaTooNew { .. })));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn records_survive_a_restart() {
        let dir = temp_dir("roundtrip");
        let room_id = RoomId::new();
        let user = UserId::new();
        let device = DeviceId::new();
        let room = Room::for_test(RoomSeal::new(dm_shape()).unwrap());

        {
            let storage = DbStorage::new(&dir).unwrap();
            storage
                .commit(&[
                    Write::Room(room_id, room),
                    Write::Account(user, AccountRecord { devices: vec![device] }),
                    Write::Device(device, DeviceRecord { user, public_key: "ab".into() }),
                    Write::Invite(
                        "tok".into(),
                        InviteRecord { used_by: None, expires_at_ms: None },
                    ),
                    Write::KeyPackages(device, VecDeque::from(vec!["cd".to_string()])),
                    Write::Policy(RegistrationPolicy::Open),
                    Write::Message(room_id, message(1)),
                ])
                .unwrap();
        }

        let storage = DbStorage::new(&dir).unwrap();
        let loaded = storage.load_directory().unwrap();
        assert_eq!(loaded.rooms.len(), 1);
        assert_eq!(loaded.rooms[0].0, room_id, "a room id must round-trip unchanged");
        assert_eq!(loaded.accounts.len(), 1);
        assert_eq!(loaded.accounts[0].0, user, "an account id must round-trip unchanged");
        assert_eq!(loaded.accounts[0].1.devices, vec![device]);
        assert_eq!(loaded.devices.len(), 1);
        assert_eq!(loaded.invites.len(), 1);
        assert_eq!(loaded.key_packages.len(), 1);
        assert_eq!(loaded.registration_policy, RegistrationPolicy::Open);
        assert_eq!(storage.messages_since(room_id, 0).unwrap().len(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_cursor_read_returns_only_later_messages_of_that_room() {
        // The read path membership depends on. A range that leaked another room's messages
        // would hand a member of one room the metadata of another.
        let dir = temp_dir("cursor");
        let storage = DbStorage::new(&dir).unwrap();
        let a = RoomId::new();
        let b = RoomId::new();
        for seq in 1..=5 {
            storage.commit(&[Write::Message(a, message(seq))]).unwrap();
            storage.commit(&[Write::Message(b, message(seq))]).unwrap();
        }

        let after_two = storage.messages_since(a, 2).unwrap();
        assert_eq!(
            after_two.iter().map(|m| m.server_seq).collect::<Vec<_>>(),
            vec![3, 4, 5],
            "a cursor read must be exclusive and ordered"
        );
        assert_eq!(storage.messages_since(a, 0).unwrap().len(), 5);
        assert_eq!(storage.messages_since(RoomId::new(), 0).unwrap().len(), 0);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_legacy_snapshot_is_imported_whole() {
        // ADR-007's third probe. Existing instances hold real state and the self-hosting
        // guide told operators to back up `state.json`; dropping it on upgrade would be
        // data loss delivered as a release note.
        let dir = temp_dir("migrate");
        let room_id = RoomId::new();
        let user = UserId::new();
        let device = DeviceId::new();

        let legacy = serde_json::json!({
            "rooms": [{
                "id": room_id,
                "room": {
                    "seal": RoomSeal::new(dm_shape()).unwrap(),
                    "next_seq": 2,
                    "last_franked": null,
                    "members": [{ "user": user, "role": "owner" }],
                    "log": [message(1), message(2)],
                }
            }],
            "devices": [{ "id": device, "record": { "user": user, "public_key": "ab" } }],
            "accounts": [{ "id": user, "record": { "devices": [device] } }],
            "invites": [{ "token": "tok", "record": { "used_by": null, "expires_at_ms": null } }],
            "key_packages": [{ "device": device, "packages": ["cd"] }],
            "registration_policy": "open",
        });
        fs::write(dir.join("state.json"), serde_json::to_vec(&legacy).unwrap()).unwrap();

        let storage = DbStorage::new(&dir).unwrap();
        let loaded = storage.load_directory().unwrap();

        assert_eq!(loaded.rooms.len(), 1, "the room must survive");
        assert_eq!(loaded.rooms[0].0, room_id, "with the same id");
        assert_eq!(loaded.accounts[0].0, user, "and the account with the same id");
        assert_eq!(loaded.devices[0].0, device);
        assert_eq!(loaded.invites[0].0, "tok");
        assert_eq!(loaded.key_packages[0].1.len(), 1);
        assert_eq!(loaded.registration_policy, RegistrationPolicy::Open);

        let messages = storage.messages_since(room_id, 0).unwrap();
        assert_eq!(
            messages.iter().map(|m| m.server_seq).collect::<Vec<_>>(),
            vec![1, 2],
            "the log must come out of the room record intact"
        );

        assert!(dir.join("state.json").exists(), "the original must be left for a rollback");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_legacy_snapshot_is_not_imported_twice() {
        // A second import would resurrect records an operator deleted after the first.
        let dir = temp_dir("migrate-twice");
        let room_id = RoomId::new();
        let legacy = serde_json::json!({
            "rooms": [{
                "id": room_id,
                "room": {
                    "seal": RoomSeal::new(dm_shape()).unwrap(),
                    "next_seq": 1,
                    "last_franked": null,
                    "members": [],
                    "log": [message(1)],
                }
            }]
        });
        fs::write(dir.join("state.json"), serde_json::to_vec(&legacy).unwrap()).unwrap();

        DbStorage::new(&dir).unwrap();
        // Simulate the operator deleting the imported room, then restarting.
        {
            let storage = DbStorage::new(&dir).unwrap();
            let tx = storage.db.begin_write().unwrap();
            {
                let mut t = tx.open_table(ROOMS).unwrap();
                t.remove(room_id.to_string().as_str()).unwrap();
            }
            tx.commit().unwrap();
        }

        let storage = DbStorage::new(&dir).unwrap();
        assert!(
            storage.load_directory().unwrap().rooms.is_empty(),
            "a re-import would undo the operator's deletion"
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// A room id both the parent and the aborted child agree on without sharing memory.
    fn crash_probe_room() -> RoomId {
        RoomId::from_uuid(uuid::Uuid::nil())
    }

    #[test]
    fn a_committed_write_survives_a_killed_process() {
        // ADR-007's first probe, and it needs a real process death: `mem::forget` was tried
        // first and proves nothing, because redb's exclusive file lock is process-wide, so
        // the "crashed" store was still holding it and the reopen failed for the wrong
        // reason. This re-executes the test binary and has the child `abort()` — no
        // unwinding, no destructors, no clean shutdown of any kind.
        const ENV: &str = "CAIRN_CRASH_PROBE_DIR";

        if let Ok(dir) = std::env::var(ENV) {
            let storage = DbStorage::new(&dir).unwrap();
            storage.commit(&[Write::Message(crash_probe_room(), message(1))]).unwrap();
            storage.commit(&[Write::Message(crash_probe_room(), message(2))]).unwrap();
            std::process::abort();
        }

        let dir = temp_dir("crash");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "storage::tests::a_committed_write_survives_a_killed_process"])
            .env(ENV, &dir)
            .status()
            .unwrap();
        assert!(!status.success(), "the child was supposed to abort, not exit cleanly");

        let reopened = DbStorage::new(&dir).unwrap();
        assert_eq!(
            reopened
                .messages_since(crash_probe_room(), 0)
                .unwrap()
                .iter()
                .map(|m| m.server_seq)
                .collect::<Vec<_>>(),
            vec![1, 2],
            "committed messages must survive a process that was killed without warning"
        );
        fs::remove_dir_all(&dir).ok();
    }
}
