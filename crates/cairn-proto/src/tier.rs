//! Encryption tiers.
//!
//! See `docs/02-encryption-tiers.md` and `docs/adr/001-tiered-encryption.md`.
//!
//! The central rule from ADR-001 is that a room's tier is **immutable after creation**.
//! That rule is enforced structurally here rather than by policy: [`Tier`] is only
//! reachable through [`RoomSeal`], which owns it, exposes no setter, and is constructed
//! once from the room's creation parameters. There is deliberately no
//! `fn set_tier(&mut self)` anywhere in this crate, and there must never be one.

use serde::{Deserialize, Serialize};

/// Maximum members in an ad-hoc group chat before it must become a community.
///
/// PROVISIONAL. Must be replaced by a measured value from the protocol spike —
/// see `docs/03-protocol-evaluation.md` criterion 2.
pub const T1_MAX_MEMBERS: u32 = 256;

/// Maximum members in a private (T2) community before it must be public (T3).
///
/// PROVISIONAL. See `T1_MAX_MEMBERS`.
pub const T2_MAX_MEMBERS: u32 = 2_000;

/// The protection level applied to a room, fixed at creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// T1 — DMs and ad-hoc group chats. End-to-end encrypted via MLS.
    Private,
    /// T2 — invite-only communities. End-to-end encrypted via MLS.
    PrivateCommunity,
    /// T3 — public/large communities. Transport encryption only; server-readable.
    PublicCommunity,
}

impl Tier {
    /// Whether message content is end-to-end encrypted in this tier.
    ///
    /// This is the single predicate the rest of the codebase should branch on when
    /// deciding whether the server may see plaintext. Do not compare tiers directly.
    pub const fn is_e2ee(self) -> bool {
        match self {
            Tier::Private | Tier::PrivateCommunity => true,
            Tier::PublicCommunity => false,
        }
    }

    /// Whether the server may index content for search and run server-side moderation.
    ///
    /// Exactly the inverse of [`Tier::is_e2ee`] today, but kept as a distinct predicate:
    /// these are different questions and may diverge (e.g. server-side indexing of
    /// client-supplied encrypted search tokens).
    pub const fn server_may_read(self) -> bool {
        !self.is_e2ee()
    }

    /// Stable short label for UI and logs.
    pub const fn label(self) -> &'static str {
        match self {
            Tier::Private => "T1",
            Tier::PrivateCommunity => "T2",
            Tier::PublicCommunity => "T3",
        }
    }
}

/// The properties of a room at creation time, from which its tier is derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomShape {
    /// A DM or ad-hoc group chat, as opposed to a community.
    pub is_direct: bool,
    /// The community is discoverable: public invite, directory listing, or published entry.
    pub is_publicly_discoverable: bool,
    /// The member ceiling the creator requested.
    pub member_ceiling: u32,
}

/// Reasons a room cannot be created as specified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ShapeError {
    #[error("direct rooms are limited to {T1_MAX_MEMBERS} members; create a community instead")]
    DirectRoomTooLarge,
}

/// Derive the tier from a room's shape.
///
/// This is the deterministic, published rule from `docs/02-encryption-tiers.md` §2.
/// It is a pure function so that a client can show the resulting tier *before* the room
/// is created, which the UI requirements in that document mandate.
pub const fn derive_tier(shape: RoomShape) -> Result<Tier, ShapeError> {
    if shape.is_direct {
        if shape.member_ceiling > T1_MAX_MEMBERS {
            return Err(ShapeError::DirectRoomTooLarge);
        }
        return Ok(Tier::Private);
    }
    if shape.is_publicly_discoverable || shape.member_ceiling > T2_MAX_MEMBERS {
        return Ok(Tier::PublicCommunity);
    }
    Ok(Tier::PrivateCommunity)
}

/// A room's immutable creation record.
///
/// Holds the tier and the shape it was derived from. There is no way to mutate either
/// after construction — that is the enforcement mechanism for ADR-001's immutability
/// rule. To change a room's tier you must create a different room, which by construction
/// has a different [`crate::ids::RoomId`] and is therefore visibly a different room.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomSeal {
    tier: Tier,
    is_direct: bool,
    member_ceiling: u32,
}

impl RoomSeal {
    /// Seal a room's tier at creation.
    pub fn new(shape: RoomShape) -> Result<Self, ShapeError> {
        let tier = derive_tier(shape)?;
        Ok(Self { tier, is_direct: shape.is_direct, member_ceiling: shape.member_ceiling })
    }

    pub const fn tier(&self) -> Tier {
        self.tier
    }

    pub const fn is_direct(&self) -> bool {
        self.is_direct
    }

    pub const fn member_ceiling(&self) -> u32 {
        self.member_ceiling
    }

    /// Whether a publicly-shareable invite may be minted for this room.
    ///
    /// Publishing an invite for an encrypted community would make it publicly
    /// discoverable, which under [`derive_tier`] would mean it should have been T3 —
    /// but the tier cannot change (ADR-001). So the invite is refused instead.
    /// See `docs/02-encryption-tiers.md` §6 open question 3.
    pub const fn may_mint_public_invite(&self) -> bool {
        !self.tier.is_e2ee()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn community(ceiling: u32, public: bool) -> RoomShape {
        RoomShape { is_direct: false, is_publicly_discoverable: public, member_ceiling: ceiling }
    }

    #[test]
    fn dms_are_t1() {
        let shape =
            RoomShape { is_direct: true, is_publicly_discoverable: false, member_ceiling: 2 };
        assert_eq!(derive_tier(shape).unwrap(), Tier::Private);
    }

    #[test]
    fn oversized_direct_room_is_rejected_not_downgraded() {
        // Important: too many members must be an error, never a silent downgrade to a
        // server-readable tier. A user who asked for a DM must never get a T3 room.
        let shape = RoomShape {
            is_direct: true,
            is_publicly_discoverable: false,
            member_ceiling: T1_MAX_MEMBERS + 1,
        };
        assert_eq!(derive_tier(shape), Err(ShapeError::DirectRoomTooLarge));
    }

    #[test]
    fn small_private_community_is_t2() {
        assert_eq!(derive_tier(community(50, false)).unwrap(), Tier::PrivateCommunity);
    }

    #[test]
    fn discoverable_community_is_t3_regardless_of_size() {
        assert_eq!(derive_tier(community(5, true)).unwrap(), Tier::PublicCommunity);
    }

    #[test]
    fn oversized_community_is_t3() {
        assert_eq!(
            derive_tier(community(T2_MAX_MEMBERS + 1, false)).unwrap(),
            Tier::PublicCommunity
        );
    }

    #[test]
    fn e2ee_predicate_matches_tiers() {
        assert!(Tier::Private.is_e2ee());
        assert!(Tier::PrivateCommunity.is_e2ee());
        assert!(!Tier::PublicCommunity.is_e2ee());
        assert!(Tier::PublicCommunity.server_may_read());
    }

    #[test]
    fn encrypted_rooms_refuse_public_invites() {
        // The alternative would be a silent downgrade, which ADR-001 forbids.
        let t2 = RoomSeal::new(community(50, false)).unwrap();
        assert!(!t2.may_mint_public_invite());
        let t3 = RoomSeal::new(community(50, true)).unwrap();
        assert!(t3.may_mint_public_invite());
    }

    #[test]
    fn seal_survives_roundtrip_without_exposing_a_setter() {
        // A seal must deserialize to the same tier it was created with. If a future
        // refactor adds a way to mutate the tier, this test is where it should be
        // noticed — but the real defence is that no setter exists at all.
        let seal = RoomSeal::new(community(50, false)).unwrap();
        let json = serde_json::to_string(&seal).unwrap();
        let back: RoomSeal = serde_json::from_str(&json).unwrap();
        assert_eq!(seal.tier(), back.tier());
        assert_eq!(seal, back);
    }
}
