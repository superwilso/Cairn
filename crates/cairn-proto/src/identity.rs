//! What an MLS credential says about who holds it.
//!
//! ## The bug this exists for
//!
//! The credential used to be `format!("{name}@{server}")` — a display label the client chose
//! for itself, with nothing checking it. Probing that:
//!
//! ```text
//! mallory joined as "bob@instance" — accepted
//!   leaf 0 shows as "alice@instance"
//!   leaf 1 shows as "bob@instance"
//! RESULT: the REAL bob is now refused: duplicate identity found at index 1
//! ```
//!
//! Mallory joins a room first, presenting bob's label. Every member's client displays her as
//! bob — and because MLS refuses duplicate identities, **the real bob can then never join
//! that room**. Impersonation with a denial of service stacked on top.
//!
//! MLS's duplicate check is the only thing that stopped mallory sitting *beside* bob, and it
//! is order-dependent: it protects whoever arrives first, which is not a security property.
//!
//! ## What replaces it
//!
//! The credential carries the **account and device ids the server already authenticates**,
//! rather than a name anyone can type. Those ids are not secret — they are on every message —
//! so this reveals nothing new. What it buys is that a credential becomes *checkable*: a
//! client claiming key packages for `usr_bob` can verify the package it got back actually
//! names `usr_bob`, and refuse otherwise.
//!
//! **Carrying the id is not itself the protection — the check is.** A credential nobody
//! verifies is as forgeable as a display name. See
//! `cairn_client_core::Client::claim_key_packages`.
//!
//! ## What this still does not do
//!
//! It does not defend against a **malicious server**. The server maps account ids to key
//! packages, so one that lies can hand out a package it minted and name it anything. That is
//! `docs/01-threat-model.md` §4, and it is what safety numbers and key transparency are for.
//! This closes the gap where *another user* — not the server — picks a label at will.
//!
//! Display names still exist; they are simply no longer the thing a room is keyed on. A name
//! is for reading, an id is for deciding.

use std::fmt;

use crate::{DeviceId, UserId};

/// Domain tag, so credential bytes can never be confused with any other encoding that
/// happens to be 32 bytes of ids.
const DOMAIN: &[u8] = b"cairn device identity v1\x00";

/// Total length: tag + two 16-byte uuids.
const ENCODED_LEN: usize = DOMAIN.len() + 16 + 16;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    #[error("credential is not a Cairn device identity")]
    NotCairn,
    #[error("credential is {found} bytes, expected {ENCODED_LEN}")]
    WrongLength { found: usize },
}

/// The account and device an MLS leaf belongs to.
///
/// Both, not just the account: `docs/01-threat-model.md` §6 gives every device its own leaf
/// so that revoking one does not disturb the others, and a credential naming only the
/// account could not tell two of a person's devices apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceIdentity {
    user: UserId,
    device: DeviceId,
}

impl DeviceIdentity {
    pub const fn new(user: UserId, device: DeviceId) -> Self {
        Self { user, device }
    }

    pub const fn user(&self) -> UserId {
        self.user
    }

    pub const fn device(&self) -> DeviceId {
        self.device
    }

    /// The bytes that go into the MLS credential.
    ///
    /// Fixed-width fields after a domain tag rather than a delimiter: the project's rule is
    /// that two different field splits must never produce the same bytes, and with 16-byte
    /// uuids there is no split to get wrong. A separator-based encoding would have to answer
    /// what happens when a field contains the separator, and the answer is always a bug.
    pub fn to_credential(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENCODED_LEN);
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(self.user.as_uuid().as_bytes());
        out.extend_from_slice(self.device.as_uuid().as_bytes());
        out
    }

    /// Read a credential back, rejecting anything that is not one.
    ///
    /// A legacy `name@server` credential lands in [`IdentityError::NotCairn`] rather than
    /// being coerced into something — a client that guessed here would be inventing an
    /// account id for a leaf that never claimed one.
    pub fn parse(bytes: &[u8]) -> Result<Self, IdentityError> {
        if !bytes.starts_with(DOMAIN) {
            return Err(IdentityError::NotCairn);
        }
        if bytes.len() != ENCODED_LEN {
            return Err(IdentityError::WrongLength { found: bytes.len() });
        }
        let rest = &bytes[DOMAIN.len()..];
        let user: [u8; 16] = rest[..16].try_into().expect("checked length above");
        let device: [u8; 16] = rest[16..].try_into().expect("checked length above");
        Ok(Self {
            user: UserId::from_uuid(uuid::Uuid::from_bytes(user)),
            device: DeviceId::from_uuid(uuid::Uuid::from_bytes(device)),
        })
    }

    /// Does this credential belong to `user`?
    ///
    /// The question a client asks after claiming key packages for a specific account. Named
    /// as a question rather than exposing the comparison, because the answer is the whole
    /// point of the type and a caller writing `==` against the wrong field is the mistake.
    pub fn belongs_to(&self, user: UserId) -> bool {
        self.user == user
    }
}

impl fmt::Display for DeviceIdentity {
    /// Ids, not a name. Anything user-facing should show a display name *beside* this, never
    /// instead of it — the point of the type is that the name is not what identifies anyone.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.user, self.device)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_round_trips() {
        let id = DeviceIdentity::new(UserId::new(), DeviceId::new());
        assert_eq!(DeviceIdentity::parse(&id.to_credential()).unwrap(), id);
    }

    #[test]
    fn a_display_name_is_not_a_credential() {
        // The old format. Accepting it would mean inventing an account id for a leaf that
        // never claimed one — worse than refusing, because the invented answer looks real.
        assert_eq!(
            DeviceIdentity::parse(b"bob@instance"),
            Err(IdentityError::NotCairn),
            "a name-shaped credential must not parse as an identity"
        );
    }

    #[test]
    fn a_credential_cannot_be_claimed_for_another_account() {
        // The property the whole type exists for. Mallory's credential names mallory's
        // account, so a client that claimed key packages for bob can see it is not bob's.
        let bob = UserId::new();
        let mallory = DeviceIdentity::new(UserId::new(), DeviceId::new());
        assert!(!mallory.belongs_to(bob), "mallory's credential must not pass as bob's");
        assert!(mallory.belongs_to(mallory.user()), "and her own must pass as hers");
    }

    #[test]
    fn two_devices_of_one_account_are_distinguishable() {
        // Per-device leaves are what make revoking one device leave the others alone.
        let user = UserId::new();
        let a = DeviceIdentity::new(user, DeviceId::new());
        let b = DeviceIdentity::new(user, DeviceId::new());
        assert_ne!(a, b);
        assert_ne!(a.to_credential(), b.to_credential());
        assert!(a.belongs_to(user) && b.belongs_to(user), "both still belong to the account");
    }

    #[test]
    fn the_domain_tag_is_covered_not_merely_prefixed() {
        // Truncation and extension both have to fail, or a credential could be padded into
        // agreeing with a different one.
        let id = DeviceIdentity::new(UserId::new(), DeviceId::new());
        let good = id.to_credential();

        let mut long = good.clone();
        long.push(0);
        assert!(matches!(DeviceIdentity::parse(&long), Err(IdentityError::WrongLength { .. })));

        assert!(matches!(
            DeviceIdentity::parse(&good[..good.len() - 1]),
            Err(IdentityError::WrongLength { .. })
        ));

        let mut wrong_tag = good.clone();
        wrong_tag[0] ^= 0xff;
        assert_eq!(DeviceIdentity::parse(&wrong_tag), Err(IdentityError::NotCairn));
    }

    #[test]
    fn swapping_the_two_ids_produces_a_different_credential() {
        // Fixed-width fields in a fixed order. If user and device were interchangeable, a
        // client could present an identity whose halves had been transposed.
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        let forward = DeviceIdentity::new(UserId::from_uuid(a), DeviceId::from_uuid(b));
        let backward = DeviceIdentity::new(UserId::from_uuid(b), DeviceId::from_uuid(a));
        assert_ne!(forward.to_credential(), backward.to_credential());
    }
}
