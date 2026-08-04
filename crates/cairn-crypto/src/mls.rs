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
//! - **Storage is in-memory.** Persisting group state across restarts is required before
//!   this is usable in a real client — see `docs/03-protocol-evaluation.md`.

use mls_rs::client_builder::{
    BaseConfig, IntoConfigOutput, WithCryptoProvider, WithIdentityProvider,
};
use mls_rs::error::MlsError as RsMlsError;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::identity::SigningIdentity;
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, Group, MlsMessage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

/// The ciphersuite Cairn pins.
///
/// X25519 + AES-128-GCM + SHA-256 + Ed25519 — MLS mandatory-to-implement, so it is the
/// most widely interoperable choice. The upgrade path must be defined before the protocol
/// freezes; see `docs/adr/002-mls-for-groups.md`.
pub const CIPHERSUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

/// The builder configuration Cairn uses, before `build()` resolves it.
type BuilderConfig =
    WithCryptoProvider<RustCryptoProvider, WithIdentityProvider<BasicIdentityProvider, BaseConfig>>;

/// The concrete MLS configuration for all Cairn sessions.
///
/// Named explicitly rather than hidden behind `impl MlsConfig` because it appears in
/// struct fields, where `impl Trait` is not permitted.
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
}

/// Parse a wire-format MLS message.
pub fn parse_message(bytes: &[u8]) -> Result<MlsMessage, MlsError> {
    Ok(MlsMessage::from_bytes(bytes)?)
}

/// A Cairn participant: an identity plus the MLS client built from it.
pub struct Session {
    client: Client<CairnConfig>,
    identity: Vec<u8>,
    public_key: Vec<u8>,
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
        let crypto = RustCryptoProvider::default();
        let cipher_suite = crypto
            .cipher_suite_provider(CIPHERSUITE)
            .expect("rustcrypto provider supports the pinned ciphersuite");

        let (secret, public) = cipher_suite.signature_key_generate().map_err(
            |e: mls_rs_crypto_rustcrypto::RustCryptoError| MlsError::Crypto(e.to_string()),
        )?;

        let public_key = public.as_ref().to_vec();
        let credential = BasicCredential::new(identity.to_vec()).into_credential();
        let signing_identity = SigningIdentity::new(credential, public);

        let client = Client::builder()
            .identity_provider(BasicIdentityProvider)
            .crypto_provider(crypto)
            .signing_identity(signing_identity, secret, CIPHERSUITE)
            .build();

        Ok(Self { client, identity: identity.to_vec(), public_key })
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
        Ok(GroupHandle { group })
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
        Ok(GroupHandle { group })
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
    /// Add a member and advance the epoch.
    ///
    /// The returned messages must be relayed: the commit to existing members, the welcome
    /// to the newcomer. A member added without existing members seeing the commit is a
    /// wiretap, which is why clients must surface membership changes
    /// (`docs/02-encryption-tiers.md` §4.6).
    pub fn add_member(&mut self, key_package: MlsMessage) -> Result<CommitOutput, MlsError> {
        let output = self.group.commit_builder().add_member(key_package)?.build()?;
        self.group.apply_pending_commit()?;
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
        Ok(CommitOutput { commit: output.commit_message, welcome: None })
    }

    /// Encrypt an application message for the group.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<MlsMessage, MlsError> {
        Ok(self.group.encrypt_application_message(plaintext, Vec::new())?)
    }

    /// Process an incoming message, returning plaintext if it was an application message.
    ///
    /// Handshake messages return `Ok(None)` after being applied — the group state advances
    /// as a side effect.
    pub fn process(&mut self, message: MlsMessage) -> Result<Option<Vec<u8>>, MlsError> {
        use mls_rs::group::ReceivedMessage;
        match self.group.process_incoming_message(message)? {
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
