//! Who this device has verified, and whether their key has changed since.
//!
//! Verification is worthless if it does not persist. A safety number compared in person
//! today must still be remembered next week, or the user is asked to re-verify constantly,
//! learns the prompt means nothing, and stops reading it — at which point a real key change
//! passes unnoticed. So this is a store, not a session-lifetime cache.
//!
//! ## What a contact is keyed by
//!
//! The **credential identity** presented in the MLS group, not a user id or a device id.
//! That is deliberate: the identity is the label a user sees next to a message, so it is
//! the thing they believe they verified. Keying by an id the server assigns would let the
//! server point an existing verification at a different key by reassigning the id.
//!
//! Identities are not unique — a `BasicCredential` carries no proof, and two devices can
//! present the same bytes (see `cairn_crypto::mls::Session::new`). That is exactly why a
//! *key change* under a known identity is the event worth surfacing, and why
//! [`ContactStore::observe`] never silently re-trusts.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use cairn_crypto::mls::GroupMember;
use cairn_crypto::verification::{ContactVerification, Fingerprint, VerificationState};

#[derive(Debug, thiserror::Error)]
pub enum ContactError {
    #[error("contact store i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("contact store is corrupt or from an incompatible version: {0}")]
    Corrupt(#[from] serde_json::Error),
}

/// What this device remembers about one contact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactRecord {
    /// Hex of the credential identity, so the map keys survive JSON.
    pub identity: String,
    pub verification: ContactVerification,
}

impl ContactRecord {
    /// The identity as bytes, for display next to a message.
    pub fn identity_bytes(&self) -> Vec<u8> {
        hex::decode(&self.identity).unwrap_or_default()
    }

    /// Best-effort human label. Cairn identities are UTF-8 today; a non-UTF-8 identity
    /// renders as hex rather than as replacement characters, since a mangled label is
    /// indistinguishable from a deliberately confusing one.
    pub fn label(&self) -> String {
        let bytes = self.identity_bytes();
        String::from_utf8(bytes).unwrap_or_else(|e| hex::encode(e.into_bytes()))
    }

    pub fn state(&self) -> VerificationState {
        self.verification.state
    }
}

/// Verification state for every contact this device has seen, persisted as one JSON file.
#[derive(Debug)]
pub struct ContactStore {
    path: PathBuf,
    contacts: BTreeMap<String, ContactRecord>,
}

impl ContactStore {
    /// Open the store at `dir`, or start an empty one.
    ///
    /// A corrupt file is an error rather than a fresh start, matching
    /// [`crate::ConversationIndex`]. Quietly starting over would mark every verified
    /// contact unverified, which reads to the user as "everyone reinstalled" and trains
    /// them to dismiss the warning that matters.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, ContactError> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir)?;
        let path = dir.join("contacts.json");

        let contacts = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };

        Ok(Self { path, contacts })
    }

    /// Record a sighting of a member as the group's roster reports them.
    ///
    /// Takes a [`GroupMember`] rather than a key and an identity so that the only thing a
    /// caller can feed this is group state. Handing it a server-supplied key would record
    /// a verification of something the conversation does not use — the failure the safety
    /// number itself had before `GroupHandle::members` existed.
    ///
    /// Returns the record as it now stands, so a caller can warn immediately.
    pub fn observe(&mut self, member: &GroupMember) -> Result<&ContactRecord, ContactError> {
        let key = hex::encode(&member.identity);
        let fingerprint = member.fingerprint();

        match self.contacts.get_mut(&key) {
            Some(existing) => existing.verification.observe(fingerprint),
            None => {
                self.contacts.insert(
                    key.clone(),
                    ContactRecord {
                        identity: key.clone(),
                        verification: ContactVerification::new(fingerprint),
                    },
                );
            }
        }

        self.save()?;
        Ok(self.contacts.get(&key).expect("just inserted or updated"))
    }

    /// Record that the user compared safety numbers out of band and they matched.
    ///
    /// Only meaningful after [`ContactStore::observe`] has seen the member, because the
    /// fingerprint being marked verified must be one that came from a group roster. An
    /// unknown contact is refused rather than created, so a mis-typed identity cannot mint
    /// a verified contact out of nothing.
    pub fn mark_verified(&mut self, identity: &[u8]) -> Result<bool, ContactError> {
        let key = hex::encode(identity);
        let Some(record) = self.contacts.get_mut(&key) else {
            return Ok(false);
        };
        record.verification.mark_verified();
        self.save()?;
        Ok(true)
    }

    pub fn get(&self, identity: &[u8]) -> Option<&ContactRecord> {
        self.contacts.get(&hex::encode(identity))
    }

    /// The state to render beside a contact. Unknown contacts are `Unverified`, which is
    /// the truthful answer and the safe default.
    pub fn state_of(&self, identity: &[u8]) -> VerificationState {
        self.get(identity).map_or(VerificationState::Unverified, ContactRecord::state)
    }

    /// The fingerprint last seen for a contact, if any.
    pub fn fingerprint_of(&self, identity: &[u8]) -> Option<Fingerprint> {
        self.get(identity).map(|r| r.verification.fingerprint)
    }

    pub fn contacts(&self) -> impl Iterator<Item = &ContactRecord> {
        self.contacts.values()
    }

    /// Contacts whose key changed after being verified. A client should refuse to look
    /// calm while this is non-empty.
    pub fn needing_attention(&self) -> impl Iterator<Item = &ContactRecord> {
        self.contacts.values().filter(|r| r.verification.needs_attention())
    }

    /// Temp file plus rename, so a crash leaves the old store rather than a truncated one.
    fn save(&self) -> Result<(), ContactError> {
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(&self.contacts)?)?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_crypto::mls::Session;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("cairn-contacts")
            .join(format!("{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// A member as a real group would report them.
    fn member(session: &Session, index: u32) -> GroupMember {
        GroupMember {
            index,
            identity: session.identity().to_vec(),
            signature_key: session.public_key().to_vec(),
        }
    }

    #[test]
    fn verification_survives_a_restart() {
        // The whole reason this is a store. A verification that evaporates on restart
        // teaches the user that the prompt is noise.
        let dir = scratch("persist");
        let bob = Session::new(b"bob@instance").unwrap();

        {
            let mut store = ContactStore::open(&dir).unwrap();
            store.observe(&member(&bob, 1)).unwrap();
            assert_eq!(store.state_of(b"bob@instance"), VerificationState::Unverified);
            assert!(store.mark_verified(b"bob@instance").unwrap());
        }

        let store = ContactStore::open(&dir).unwrap();
        assert_eq!(store.state_of(b"bob@instance"), VerificationState::Verified);
    }

    #[test]
    fn a_key_change_after_verification_survives_a_restart_too() {
        // The warning is worth more than the verification: it must not be the thing that
        // gets lost when the process dies.
        let dir = scratch("changed");
        let bob = Session::new(b"bob@instance").unwrap();
        // A different device presenting the same credential bytes — a reinstall, or an
        // active attack. Indistinguishable here, which is why the user must be told.
        let impostor = Session::new(b"bob@instance").unwrap();

        {
            let mut store = ContactStore::open(&dir).unwrap();
            store.observe(&member(&bob, 1)).unwrap();
            store.mark_verified(b"bob@instance").unwrap();
            let record = store.observe(&member(&impostor, 1)).unwrap();
            assert_eq!(record.state(), VerificationState::ChangedSinceVerified);
        }

        let store = ContactStore::open(&dir).unwrap();
        assert_eq!(store.state_of(b"bob@instance"), VerificationState::ChangedSinceVerified);
        assert_eq!(store.needing_attention().count(), 1);
    }

    #[test]
    fn re_observing_a_substituted_key_does_not_clear_the_warning() {
        let dir = scratch("sticky");
        let bob = Session::new(b"bob@instance").unwrap();
        let impostor = Session::new(b"bob@instance").unwrap();

        let mut store = ContactStore::open(&dir).unwrap();
        store.observe(&member(&bob, 1)).unwrap();
        store.mark_verified(b"bob@instance").unwrap();
        store.observe(&member(&impostor, 1)).unwrap();

        // Every later sync sees the substituted key. If that cleared the flag, the
        // evidence would survive exactly one poll.
        store.observe(&member(&impostor, 1)).unwrap();
        store.observe(&member(&impostor, 1)).unwrap();
        assert_eq!(store.state_of(b"bob@instance"), VerificationState::ChangedSinceVerified);
    }

    #[test]
    fn an_unseen_contact_cannot_be_marked_verified() {
        // Otherwise a typo would mint a verified contact whose fingerprint never came
        // from a group at all.
        let mut store = ContactStore::open(scratch("unseen")).unwrap();
        assert!(!store.mark_verified(b"nobody@instance").unwrap());
        assert!(store.get(b"nobody@instance").is_none());
        assert_eq!(store.state_of(b"nobody@instance"), VerificationState::Unverified);
    }

    #[test]
    fn a_corrupt_store_is_an_error_not_a_fresh_start() {
        let dir = scratch("corrupt");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("contacts.json"), b"{not json").unwrap();
        assert!(matches!(ContactStore::open(&dir), Err(ContactError::Corrupt(_))));
    }

    #[test]
    fn an_unverified_contact_rotating_keys_stays_quiet() {
        // Only a change *after* verification is evidence. Warning about every rotation
        // for contacts nobody verified would bury the signal.
        let dir = scratch("rotate");
        let bob = Session::new(b"bob@instance").unwrap();
        let bob2 = Session::new(b"bob@instance").unwrap();

        let mut store = ContactStore::open(&dir).unwrap();
        store.observe(&member(&bob, 1)).unwrap();
        store.observe(&member(&bob2, 1)).unwrap();
        assert_eq!(store.state_of(b"bob@instance"), VerificationState::Unverified);
        assert_eq!(store.needing_attention().count(), 0);
    }

    #[test]
    fn two_identities_are_tracked_separately() {
        let dir = scratch("two");
        let alice = Session::new(b"alice@instance").unwrap();
        let bob = Session::new(b"bob@instance").unwrap();

        let mut store = ContactStore::open(&dir).unwrap();
        store.observe(&member(&alice, 0)).unwrap();
        store.observe(&member(&bob, 1)).unwrap();
        store.mark_verified(b"alice@instance").unwrap();

        assert_eq!(store.state_of(b"alice@instance"), VerificationState::Verified);
        assert_eq!(store.state_of(b"bob@instance"), VerificationState::Unverified);
        assert_eq!(store.contacts().count(), 2);
    }
}
