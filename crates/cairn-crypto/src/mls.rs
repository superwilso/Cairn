//! MLS group sessions.
//!
//! A thin wrapper over `mls-rs` (RFC 9420) that gives the rest of Cairn a small,
//! Cairn-shaped surface. See `docs/adr/002-mls-for-groups.md`.
//!
//! ## Design notes
//!
//! - **A DM is a two-member group.** There is no separate pairwise protocol, so there is
//!   one code path and one set of bugs rather than two.
//! - **This API is synchronous.** `mls-rs` generates both sync and async surfaces via
//!   `maybe_async`; Cairn uses the default (sync) build. That keeps the FFI for platform
//!   bindings simple — no runtime has to be pumped across the boundary. See
//!   `docs/09-platform-strategy.md`.
//! - **The server sequences commits.** MLS requires strictly ordered, append-only group
//!   changes. In a single-instance deployment the server provides that ordering for free;
//!   doing it across federating servers is the hard problem deferred by
//!   `docs/adr/003-islands-first.md`.
//! - **State can be persistent or ephemeral.** [`Session::open`] keeps group state, key
//!   package secrets, and the device key in a directory so a client resumes after a
//!   restart; [`Session::new`] keeps them in memory for tests and one-shot tools. See
//!   [`crate::store`].
//! - **Persistence is not automatic in `mls-rs`,** so [`GroupHandle`] writes after every
//!   state-changing call rather than offering a `save()` a caller can forget. The reason
//!   this is not merely tidiness is in [`crate::store`]'s module docs: a group that
//!   resumes at a stale generation sends messages the receiver silently drops.

use std::path::Path;

use mls_rs::client_builder::{
    BaseConfig, IntoConfigOutput, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
    WithKeyPackageRepo,
};
use mls_rs::error::MlsError as RsMlsError;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::identity::SigningIdentity;
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, Group, MlsMessage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

use crate::store::{ClientStore, GroupStore, KeyPackageStore, StoreError};

/// The ciphersuite Cairn pins.
///
/// X25519 + AES-128-GCM + SHA-256 + Ed25519 — MLS mandatory-to-implement, so it is the
/// most widely interoperable choice. The upgrade path must be defined before the protocol
/// freezes; see `docs/adr/002-mls-for-groups.md`.
pub const CIPHERSUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

/// The builder configuration Cairn uses, before `build()` resolves it.
///
/// The wrapper order mirrors the order of the builder calls in [`Session::build`]; they
/// have to match or the types do not line up.
type BuilderConfig = WithKeyPackageRepo<
    KeyPackageStore,
    WithGroupStateStorage<
        GroupStore,
        WithCryptoProvider<
            RustCryptoProvider,
            WithIdentityProvider<BasicIdentityProvider, BaseConfig>,
        >,
    >,
>;

/// The concrete MLS configuration for all Cairn sessions.
///
/// Named explicitly rather than hidden behind `impl MlsConfig` because it appears in
/// struct fields, where `impl Trait` is not permitted. Persistent and ephemeral sessions
/// deliberately share one type — the storage choice is a value, not a type parameter, so
/// it never leaks into `cairn-client-core` or the FFI surface.
pub type CairnConfig = IntoConfigOutput<BuilderConfig>;

#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    #[error("mls error: {0}")]
    Mls(#[from] RsMlsError),
    #[error("crypto provider error: {0}")]
    Crypto(String),
    #[error("no MLS group is attached to this conversation")]
    NoGroup,
    #[error("commit produced no welcome message; cannot add the member")]
    NoWelcome,
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Verify a signature made by [`Session::sign`].
///
/// Returns `false` on any failure — a malformed key, a malformed signature, or a genuine
/// mismatch. Callers must not distinguish these, since doing so would tell an attacker
/// which part of their forgery was wrong.
pub fn verify_signature(public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    let crypto = RustCryptoProvider::default();
    let Some(cs) = crypto.cipher_suite_provider(CIPHERSUITE) else {
        return false;
    };
    cs.verify(&public_key.to_vec().into(), signature, data).is_ok()
}

/// Parse a wire-format MLS message.
pub fn parse_message(bytes: &[u8]) -> Result<MlsMessage, MlsError> {
    Ok(MlsMessage::from_bytes(bytes)?)
}

/// Generate a fresh signature keypair for the pinned ciphersuite.
fn generate_signature_key(
) -> Result<(mls_rs::crypto::SignatureSecretKey, mls_rs::crypto::SignaturePublicKey), MlsError> {
    let crypto = RustCryptoProvider::default();
    let cipher_suite = crypto
        .cipher_suite_provider(CIPHERSUITE)
        .expect("rustcrypto provider supports the pinned ciphersuite");
    cipher_suite
        .signature_key_generate()
        .map_err(|e: mls_rs_crypto_rustcrypto::RustCryptoError| MlsError::Crypto(e.to_string()))
}

/// A Cairn participant: an identity plus the MLS client built from it.
pub struct Session {
    client: Client<CairnConfig>,
    identity: Vec<u8>,
    public_key: Vec<u8>,
    /// Retained so the device can sign envelopes, not just MLS messages.
    ///
    /// MLS authenticates messages *within* a group. It says nothing about a request
    /// arriving at the server, so envelope authentication needs the same key used
    /// directly. See `cairn_proto::Envelope::signing_bytes`.
    secret_key: mls_rs::crypto::SignatureSecretKey,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Session(<mls client>)")
    }
}

impl Session {
    /// Create a session for a participant.
    ///
    /// `identity` is the credential bytes other members see. In Cairn this is the
    /// device-scoped identity — per `docs/01-threat-model.md` §6 each device holds its own
    /// leaf, so revoking one device does not disturb the others.
    ///
    /// The identity is a `BasicCredential`, which carries no proof of who holds it: the
    /// server asserts the binding. Defending against a malicious server substituting keys
    /// needs out-of-band verification and key transparency, which are **not implemented
    /// yet** — see `docs/01-threat-model.md` §4. Until they are, the E2EE guarantee holds
    /// against an honest-but-curious server, not a malicious one.
    pub fn new(identity: &[u8]) -> Result<Self, MlsError> {
        let (secret, public) = generate_signature_key()?;
        Ok(Self::build(
            identity,
            secret,
            public,
            GroupStore::in_memory(),
            KeyPackageStore::in_memory(),
        ))
    }

    /// Open — or create — a persistent session rooted at `dir`.
    ///
    /// On first run this mints the device key and writes it. On every later run it reloads
    /// the same key, so the device keeps the identity the server authenticates it by and
    /// the safety number its contacts verified. A session opened this way can call
    /// [`Session::load_group`] to resume a conversation that outlived the process.
    ///
    /// One directory holds exactly one device. Opening a directory under a different
    /// identity is refused rather than quietly adopting the stored key — see
    /// [`ClientStore::load_or_create_device_key`].
    pub fn open(dir: impl AsRef<Path>, identity: &[u8]) -> Result<Self, MlsError> {
        let store = ClientStore::open(dir.as_ref())?;
        let key = store.load_or_create_device_key(identity, || {
            let (secret, public) =
                generate_signature_key().map_err(|e| StoreError::KeyGeneration(e.to_string()))?;
            Ok((public.as_ref().to_vec(), secret.as_ref().to_vec()))
        })?;

        Ok(Self::build(
            identity,
            key.secret().to_vec().into(),
            key.public.clone().into(),
            store.group_store()?,
            store.key_package_store()?,
        ))
    }

    fn build(
        identity: &[u8],
        secret: mls_rs::crypto::SignatureSecretKey,
        public: mls_rs::crypto::SignaturePublicKey,
        group_store: GroupStore,
        key_packages: KeyPackageStore,
    ) -> Self {
        let public_key = public.as_ref().to_vec();
        let secret_key = secret.clone();
        let credential = BasicCredential::new(identity.to_vec()).into_credential();
        let signing_identity = SigningIdentity::new(credential, public);

        let client = Client::builder()
            .identity_provider(BasicIdentityProvider)
            .crypto_provider(RustCryptoProvider::default())
            .group_state_storage(group_store)
            .key_package_repo(key_packages)
            .signing_identity(signing_identity, secret, CIPHERSUITE)
            .build();

        Self { client, identity: identity.to_vec(), public_key, secret_key }
    }

    /// Sign arbitrary bytes with this device's identity key.
    ///
    /// Used for envelope authentication. The server verifies against the public key
    /// registered for the device, which is what turns `sender` from a claim into an
    /// authenticated fact.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, MlsError> {
        let crypto = RustCryptoProvider::default();
        let cs = crypto
            .cipher_suite_provider(CIPHERSUITE)
            .expect("rustcrypto provider supports the pinned ciphersuite");
        cs.sign(&self.secret_key, data).map_err(|e| MlsError::Crypto(e.to_string()))
    }

    /// This participant's identity (credential) bytes.
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    /// This participant's long-term signature public key.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The fingerprint others compare against out of band.
    ///
    /// See [`crate::verification`] — this is the value that makes a malicious server's key
    /// substitution visible.
    pub fn fingerprint(&self) -> crate::verification::Fingerprint {
        crate::verification::Fingerprint::compute(&self.public_key, &self.identity)
    }

    /// Start a new group. The creator is its only member until it commits an add.
    pub fn create_group(&self) -> Result<GroupHandle, MlsError> {
        let group =
            self.client.create_group(ExtensionList::default(), ExtensionList::default(), None)?;
        let mut handle = GroupHandle { group };
        handle.persist()?;
        Ok(handle)
    }

    /// Resume a group this session already belongs to.
    ///
    /// The counterpart to [`Session::open`]: a persistent session plus the group id is
    /// enough to pick a conversation back up after a restart. On an ephemeral session this
    /// fails, because there is nothing to load from.
    pub fn load_group(&self, group_id: &[u8]) -> Result<GroupHandle, MlsError> {
        Ok(GroupHandle { group: self.client.load_group(group_id)? })
    }

    /// Produce a key package so another member can add this session to a group.
    pub fn key_package(&self) -> Result<MlsMessage, MlsError> {
        Ok(self.client.generate_key_package_message(
            ExtensionList::default(),
            ExtensionList::default(),
            None,
        )?)
    }

    /// Join a group from a welcome message produced by an existing member's commit.
    pub fn join(&self, welcome: &MlsMessage) -> Result<GroupHandle, MlsError> {
        let (group, _info) = self.client.join_group(None, welcome, None)?;
        let mut handle = GroupHandle { group };
        handle.persist()?;
        Ok(handle)
    }
}

/// A joined MLS group.
pub struct GroupHandle {
    group: Group<CairnConfig>,
}

impl std::fmt::Debug for GroupHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupHandle").field("epoch", &self.group.current_epoch()).finish()
    }
}

/// The messages a commit produces, which the caller must relay via the server.
#[derive(Debug)]
pub struct CommitOutput {
    /// Broadcast to existing members so they advance to the new epoch.
    pub commit: MlsMessage,
    /// Sent to the newly added member so they can join.
    pub welcome: Option<MlsMessage>,
}

impl GroupHandle {
    /// Flush group state to whatever storage the session was built with.
    ///
    /// Private on purpose. `mls-rs` leaves persistence to the caller, and a public `save()`
    /// is a call site that eventually gets forgotten — the failure is silent until a
    /// restart, and for an encrypt it is message-key reuse rather than merely lost state
    /// (see [`crate::store`]). Every method below that mutates the group calls this before
    /// returning, so there is nothing for a caller to remember.
    fn persist(&mut self) -> Result<(), MlsError> {
        self.group.write_to_storage()?;
        Ok(())
    }

    /// This group's MLS group id — what [`Session::load_group`] takes to resume it.
    pub fn group_id(&self) -> &[u8] {
        self.group.group_id()
    }

    /// Add a member and advance the epoch.
    ///
    /// The returned messages must be relayed: the commit to existing members, the welcome
    /// to the newcomer. A member added without existing members seeing the commit is a
    /// wiretap, which is why clients must surface membership changes
    /// (`docs/02-encryption-tiers.md` §4.6).
    pub fn add_member(&mut self, key_package: MlsMessage) -> Result<CommitOutput, MlsError> {
        let output = self.group.commit_builder().add_member(key_package)?.build()?;
        self.group.apply_pending_commit()?;
        self.persist()?;
        let welcome = output.welcome_messages.into_iter().next();
        Ok(CommitOutput { commit: output.commit_message, welcome })
    }

    /// Remove a member and advance the epoch.
    ///
    /// After the removal commit, MLS's post-compromise security means the removed member
    /// cannot read subsequent messages even if they kept old key material.
    pub fn remove_member(&mut self, index: u32) -> Result<CommitOutput, MlsError> {
        let output = self.group.commit_builder().remove_member(index)?.build()?;
        self.group.apply_pending_commit()?;
        self.persist()?;
        Ok(CommitOutput { commit: output.commit_message, welcome: None })
    }

    /// Encrypt an application message for the group.
    ///
    /// Persists before returning. MLS derives each message key from a per-sender
    /// generation counter, so a client that encrypted and then resumed from state saved
    /// *before* the encrypt would send its next message at a generation the receiver has
    /// already consumed — the receiver rejects it and the sender never learns. See
    /// [`crate::store`] for what that does and does not amount to.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<MlsMessage, MlsError> {
        let message = self.group.encrypt_application_message(plaintext, Vec::new())?;
        self.persist()?;
        Ok(message)
    }

    /// Process an incoming message, returning plaintext if it was an application message.
    ///
    /// Handshake messages return `Ok(None)` after being applied — the group state advances
    /// as a side effect.
    pub fn process(&mut self, message: MlsMessage) -> Result<Option<Vec<u8>>, MlsError> {
        use mls_rs::group::ReceivedMessage;
        let received = self.group.process_incoming_message(message)?;
        self.persist()?;
        match received {
            ReceivedMessage::ApplicationMessage(app) => Ok(Some(app.data().to_vec())),
            _ => Ok(None),
        }
    }

    /// Current epoch. Advances on every commit.
    pub fn epoch(&self) -> u64 {
        self.group.current_epoch()
    }

    /// Number of members currently in the group.
    pub fn member_count(&self) -> usize {
        self.group.roster().members_iter().count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("cairn-mls-tests")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// M1's exit condition, minus the network: both ends close and both resume.
    ///
    /// Every handle and session is dropped before the second half, so the only thing
    /// carrying the conversation forward is what reached disk.
    #[test]
    fn a_conversation_survives_both_ends_restarting() {
        let alice_dir = scratch("resume-alice");
        let bob_dir = scratch("resume-bob");

        let group_id = {
            let alice = Session::open(&alice_dir, b"alice@instance").unwrap();
            let bob = Session::open(&bob_dir, b"bob@instance").unwrap();

            let mut ag = alice.create_group().unwrap();
            let group_id = ag.group_id().to_vec();
            let out = ag.add_member(bob.key_package().unwrap()).unwrap();
            let mut bg = bob.join(&out.welcome.expect("welcome for new member")).unwrap();

            let ct = ag.encrypt(b"before restart").unwrap();
            assert_eq!(bg.process(ct).unwrap().as_deref(), Some(&b"before restart"[..]));
            group_id
        };

        // Restart: nothing from the first block is still alive.
        let alice = Session::open(&alice_dir, b"alice@instance").unwrap();
        let bob = Session::open(&bob_dir, b"bob@instance").unwrap();
        let mut ag = alice.load_group(&group_id).expect("alice must resume from disk");
        let mut bg = bob.load_group(&group_id).expect("bob must resume from disk");
        assert_eq!(ag.epoch(), bg.epoch(), "both ends must resume at the same epoch");

        let ct = ag.encrypt(b"after restart").unwrap();
        assert_eq!(bg.process(ct).unwrap().as_deref(), Some(&b"after restart"[..]));

        // And in the other direction, so this is not one-way luck.
        let ct = bg.encrypt(b"bob replies").unwrap();
        assert_eq!(ag.process(ct).unwrap().as_deref(), Some(&b"bob replies"[..]));
    }

    #[test]
    fn a_resumed_group_can_still_change_its_membership() {
        // Resuming enough to send is not the same as resuming enough to commit: a commit
        // needs the ratchet tree and the signer, not just the message keys.
        let alice_dir = scratch("resume-commit-alice");
        let bob_dir = scratch("resume-commit-bob");
        let carol_dir = scratch("resume-commit-carol");

        let group_id = {
            let alice = Session::open(&alice_dir, b"alice").unwrap();
            let bob = Session::open(&bob_dir, b"bob").unwrap();
            let mut ag = alice.create_group().unwrap();
            let group_id = ag.group_id().to_vec();
            let out = ag.add_member(bob.key_package().unwrap()).unwrap();
            bob.join(&out.welcome.unwrap()).unwrap();
            group_id
        };

        let alice = Session::open(&alice_dir, b"alice").unwrap();
        let bob = Session::open(&bob_dir, b"bob").unwrap();
        let carol = Session::open(&carol_dir, b"carol").unwrap();

        let mut ag = alice.load_group(&group_id).unwrap();
        let mut bg = bob.load_group(&group_id).unwrap();

        let out = ag.add_member(carol.key_package().unwrap()).unwrap();
        let mut cg = carol.join(&out.welcome.unwrap()).unwrap();
        bg.process(out.commit).unwrap();

        let ct = ag.encrypt(b"hi carol").unwrap();
        assert_eq!(cg.process(ct.clone()).unwrap().as_deref(), Some(&b"hi carol"[..]));
        assert_eq!(bg.process(ct).unwrap().as_deref(), Some(&b"hi carol"[..]));
    }

    #[test]
    fn a_device_keeps_its_identity_across_a_restart() {
        // A device that regenerates its key is a device the server will not authenticate,
        // and every contact reads the change as the signal a malicious server's key
        // substitution produces (`docs/01-threat-model.md` §4).
        let dir = scratch("stable-identity");
        let first = Session::open(&dir, b"alice@instance").unwrap();
        let public = first.public_key().to_vec();
        let fingerprint = first.fingerprint();
        drop(first);

        let second = Session::open(&dir, b"alice@instance").unwrap();
        assert_eq!(second.public_key(), public.as_slice());
        assert_eq!(second.fingerprint(), fingerprint, "the safety number must not move");

        // And the key still signs: reloading the bytes must produce a usable secret, not
        // merely an equal-looking one.
        let sig = second.sign(b"envelope bytes").unwrap();
        assert!(verify_signature(&public, b"envelope bytes", &sig));
    }

    #[test]
    fn a_published_key_package_still_works_after_a_restart() {
        // A key package is published to the server before anyone adds you. If its secrets
        // did not survive the restart, the welcome addressed to it could never be opened
        // and the invitation would fail with no visible cause.
        let dir = scratch("key-package-restart");
        let alice = Session::new(b"alice").unwrap();

        let published = {
            let bob = Session::open(&dir, b"bob").unwrap();
            bob.key_package().unwrap()
        };

        let mut ag = alice.create_group().unwrap();
        let out = ag.add_member(published).unwrap();

        let bob = Session::open(&dir, b"bob").unwrap();
        let mut bg = bob.join(&out.welcome.unwrap()).expect("a pre-restart key package must open");
        let ct = ag.encrypt(b"welcome back").unwrap();
        assert_eq!(bg.process(ct).unwrap().as_deref(), Some(&b"welcome back"[..]));
    }

    #[test]
    fn an_ephemeral_session_cannot_resume() {
        // The distinction has to be real, or a caller could believe an in-memory session
        // was durable. Nothing was written, so nothing loads.
        let alice = Session::new(b"alice").unwrap();
        let group_id = alice.create_group().unwrap().group_id().to_vec();
        let reopened = Session::new(b"alice").unwrap();
        assert!(reopened.load_group(&group_id).is_err());
    }

    #[test]
    fn a_second_identity_cannot_open_another_devices_store() {
        // Two accounts sharing a directory would have the second adopt the first's key,
        // and every message it sent would be attributed to the first account.
        let dir = scratch("shared-store");
        Session::open(&dir, b"alice").unwrap();
        assert!(Session::open(&dir, b"mallory").is_err());
    }

    #[test]
    fn state_saved_before_an_encrypt_leaves_the_next_message_undeliverable() {
        // Why `GroupHandle` persists after *every* mutation instead of offering a `save()`.
        //
        // Two handles loaded from one saved state stand in for a client that encrypted and
        // then died before writing. The receiver takes the first message and rejects the
        // second: it has already consumed the key for that generation. Nothing about this
        // is visible to the sender, which is what makes it dangerous.
        let alice_dir = scratch("stale-encrypt-alice");
        let bob_dir = scratch("stale-encrypt-bob");

        let alice = Session::open(&alice_dir, b"alice").unwrap();
        let bob = Session::open(&bob_dir, b"bob").unwrap();

        let mut ag = alice.create_group().unwrap();
        let group_id = ag.group_id().to_vec();
        let out = ag.add_member(bob.key_package().unwrap()).unwrap();
        let mut bg = bob.join(&out.welcome.unwrap()).unwrap();

        let mut stale = alice.load_group(&group_id).unwrap();
        let first = ag.encrypt(b"message one").unwrap();
        let second = stale.encrypt(b"message two").unwrap();

        assert_eq!(bg.process(first).unwrap().as_deref(), Some(&b"message one"[..]));
        assert!(
            bg.process(second).is_err(),
            "a message sent at an already-spent generation must not be deliverable"
        );
    }

    /// The vertical slice from the plan: a two-member MLS group exchanging a message.
    #[test]
    fn two_member_dm_round_trip() {
        let alice = Session::new(b"alice@instance").unwrap();
        let bob = Session::new(b"bob@instance").unwrap();

        let mut alice_group = alice.create_group().unwrap();
        assert_eq!(alice_group.member_count(), 1);

        let out = alice_group.add_member(bob.key_package().unwrap()).unwrap();
        let mut bob_group = bob.join(&out.welcome.expect("welcome for new member")).unwrap();

        assert_eq!(alice_group.member_count(), 2);
        assert_eq!(bob_group.member_count(), 2);
        assert_eq!(alice_group.epoch(), bob_group.epoch());

        let ct = alice_group.encrypt(b"hello bob").unwrap();
        assert_eq!(bob_group.process(ct).unwrap().as_deref(), Some(&b"hello bob"[..]));

        let ct = bob_group.encrypt(b"hello alice").unwrap();
        assert_eq!(alice_group.process(ct).unwrap().as_deref(), Some(&b"hello alice"[..]));
    }

    #[test]
    fn three_member_group_all_receive() {
        let alice = Session::new(b"alice").unwrap();
        let bob = Session::new(b"bob").unwrap();
        let carol = Session::new(b"carol").unwrap();

        let mut ag = alice.create_group().unwrap();

        let out = ag.add_member(bob.key_package().unwrap()).unwrap();
        let mut bg = bob.join(&out.welcome.unwrap()).unwrap();

        // Adding Carol produces a commit Bob must also apply to stay in sync.
        let out = ag.add_member(carol.key_package().unwrap()).unwrap();
        let mut cg = carol.join(&out.welcome.unwrap()).unwrap();
        bg.process(out.commit).unwrap();

        assert_eq!(ag.member_count(), 3);
        assert_eq!(bg.epoch(), ag.epoch(), "bob must track alice's epoch");
        assert_eq!(cg.epoch(), ag.epoch(), "carol must join at the current epoch");

        let ct = ag.encrypt(b"hi all").unwrap();
        assert_eq!(bg.process(ct.clone()).unwrap().as_deref(), Some(&b"hi all"[..]));
        assert_eq!(cg.process(ct).unwrap().as_deref(), Some(&b"hi all"[..]));
    }

    #[test]
    fn removed_member_cannot_read_later_messages() {
        // Post-compromise security: the group heals after a removal. This is the property
        // that makes MLS worth its complexity over static sender keys.
        let alice = Session::new(b"alice").unwrap();
        let bob = Session::new(b"bob").unwrap();
        let carol = Session::new(b"carol").unwrap();

        let mut ag = alice.create_group().unwrap();
        let out = ag.add_member(bob.key_package().unwrap()).unwrap();
        let mut bg = bob.join(&out.welcome.unwrap()).unwrap();
        let out = ag.add_member(carol.key_package().unwrap()).unwrap();
        let mut cg = carol.join(&out.welcome.unwrap()).unwrap();
        bg.process(out.commit).unwrap();

        // Remove Carol (leaf index 2).
        let out = ag.remove_member(2).unwrap();
        bg.process(out.commit).unwrap();

        let ct = ag.encrypt(b"after carol left").unwrap();
        assert!(cg.process(ct.clone()).is_err(), "a removed member must not be able to decrypt");
        assert_eq!(
            bg.process(ct).unwrap().as_deref(),
            Some(&b"after carol left"[..]),
            "remaining members must still receive"
        );
    }

    #[test]
    fn safety_numbers_detect_a_substituted_key() {
        // The threat model's A4: a malicious server hands Alice a key it controls while
        // claiming it is Bob's. MLS cannot detect this — only comparing safety numbers
        // out of band can. This exercises it with real generated MLS identity keys rather
        // than synthetic bytes.
        use crate::verification::SafetyNumber;

        let alice = Session::new(b"alice@instance").unwrap();
        let bob = Session::new(b"bob@instance").unwrap();

        // A malicious server generates its own key and presents it as Bob's.
        let impostor = Session::new(b"bob@instance").unwrap();

        let honest = SafetyNumber::between(&alice.fingerprint(), &bob.fingerprint());
        let attacked = SafetyNumber::between(&alice.fingerprint(), &impostor.fingerprint());

        assert_ne!(
            honest, attacked,
            "an impostor using the same claimed identity must still produce a different \
             safety number, or out-of-band verification is worthless"
        );

        // Both parties independently derive the same value.
        let from_bobs_side = SafetyNumber::between(&bob.fingerprint(), &alice.fingerprint());
        assert_eq!(honest, from_bobs_side);
    }

    #[test]
    fn a_sessions_fingerprint_is_stable() {
        let alice = Session::new(b"alice@instance").unwrap();
        assert_eq!(alice.fingerprint(), alice.fingerprint());
        assert!(!alice.public_key().is_empty());
        assert_eq!(alice.identity(), b"alice@instance");
    }

    #[test]
    fn a_signature_verifies_against_its_own_key_and_no_other() {
        let alice = Session::new(b"alice").unwrap();
        let mallory = Session::new(b"mallory").unwrap();
        let data = b"authenticated envelope bytes";

        let sig = alice.sign(data).unwrap();
        assert!(verify_signature(alice.public_key(), data, &sig));
        assert!(
            !verify_signature(mallory.public_key(), data, &sig),
            "a signature must not verify under someone else's key"
        );
    }

    #[test]
    fn a_signature_does_not_carry_over_to_different_data() {
        let alice = Session::new(b"alice").unwrap();
        let sig = alice.sign(b"original").unwrap();
        assert!(!verify_signature(alice.public_key(), b"tampered", &sig));
    }

    #[test]
    fn malformed_input_fails_closed() {
        // Every failure mode must return false rather than panicking or, worse,
        // accidentally succeeding.
        let alice = Session::new(b"alice").unwrap();
        let sig = alice.sign(b"data").unwrap();
        assert!(!verify_signature(b"", b"data", &sig));
        assert!(!verify_signature(b"not a key", b"data", &sig));
        assert!(!verify_signature(alice.public_key(), b"data", b""));
        assert!(!verify_signature(alice.public_key(), b"data", b"garbage"));
    }

    #[test]
    fn epoch_advances_on_membership_change() {
        let alice = Session::new(b"alice").unwrap();
        let bob = Session::new(b"bob").unwrap();
        let mut ag = alice.create_group().unwrap();
        let before = ag.epoch();
        ag.add_member(bob.key_package().unwrap()).unwrap();
        assert!(ag.epoch() > before, "adding a member must advance the epoch");
    }

    #[test]
    fn wire_round_trip_through_bytes() {
        // The transport carries bytes, not MlsMessage values, so the serialize/parse pair
        // is on the critical path.
        let alice = Session::new(b"alice").unwrap();
        let bob = Session::new(b"bob").unwrap();
        let mut ag = alice.create_group().unwrap();
        let out = ag.add_member(bob.key_package().unwrap()).unwrap();
        let mut bg = bob.join(&out.welcome.unwrap()).unwrap();

        let ct = ag.encrypt(b"over the wire").unwrap();
        let bytes = ct.to_bytes().unwrap();
        let reparsed = parse_message(&bytes).unwrap();
        assert_eq!(bg.process(reparsed).unwrap().as_deref(), Some(&b"over the wire"[..]));
    }
}
