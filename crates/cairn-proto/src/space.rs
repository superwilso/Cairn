//! Space permissions: the vocabulary, not the rules.
//!
//! A space is a container of channels, and every channel is an ordinary room with its own
//! sealed tier (`docs/adr/011-spaces-channels-roles.md`). What an account may do in a space is
//! a set of these bits, computed **by the instance** from the roles it holds and the channel's
//! overrides. That computation lives in `cairn-server`'s `state.rs` and nowhere else: this
//! module only names the bits so a client and the server agree on what a number means.
//!
//! **None of this is cryptographic.** Roles and permissions are metadata the instance holds
//! in the clear and enforces on its own say-so. A malicious instance can grant or withhold
//! any of them. What it cannot do in an end-to-end encrypted channel is read the messages —
//! and that comes from MLS, not from anything here.

use serde::{Deserialize, Serialize};

/// A set of permission bits.
///
/// A plain `u32` on the wire. Unknown bits are refused on the way in
/// ([`Permissions::from_bits`]) rather than carried: a bit this build does not understand is
/// a bit it cannot enforce, and storing it would let a later build grant something nobody
/// ever chose to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Permissions(u32);

impl Permissions {
    /// See a channel and read its history. Without it a channel is not listed at all.
    pub const READ: Self = Self(1 << 0);
    /// Post into a channel. Meaningless without [`Permissions::READ`], and never granted
    /// without it: a member who can write but not read would be posting blind into a room
    /// whose franking chain they cannot see.
    pub const SEND: Self = Self(1 << 1);
    /// Mint invites to the space.
    pub const INVITE: Self = Self(1 << 2);
    /// Remove a member ranked below you from the space, which bars them from rejoining by
    /// invite until someone with this permission lifts the bar.
    pub const KICK: Self = Self(1 << 3);
    /// Create, rename and delete channels, set their overrides and their timers.
    pub const MANAGE_CHANNELS: Self = Self(1 << 4);
    /// Create, edit, delete, assign and unassign roles ranked below your own.
    pub const MANAGE_ROLES: Self = Self(1 << 5);

    pub const NONE: Self = Self(0);
    pub const ALL: Self = Self(0b11_1111);

    /// The only bits a per-channel override may touch.
    ///
    /// Overrides decide who can see and speak in a channel. Letting one grant `KICK` or
    /// `MANAGE_ROLES` would make those space-wide powers depend on which channel a request
    /// happened to name, which is a rule nobody could reason about.
    pub const CHANNEL_SCOPED: Self = Self(Self::READ.0 | Self::SEND.0);

    /// What `@everyone` holds in a new space.
    pub const DEFAULT_EVERYONE: Self = Self(Self::READ.0 | Self::SEND.0);

    /// Every named bit, with its wire name. The order is the display order.
    pub const NAMED: [(Self, &'static str); 6] = [
        (Self::READ, "read"),
        (Self::SEND, "send"),
        (Self::INVITE, "invite"),
        (Self::KICK, "kick"),
        (Self::MANAGE_CHANNELS, "manage_channels"),
        (Self::MANAGE_ROLES, "manage_roles"),
    ];

    /// Parse bits from the wire, refusing any this build does not name.
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::ALL.0 != 0 {
            None
        } else {
            Some(Self(bits))
        }
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The wire names of the bits set, in display order.
    pub fn names(self) -> Vec<&'static str> {
        Self::NAMED.iter().filter(|(p, _)| self.contains(*p)).map(|(_, n)| *n).collect()
    }

    /// Parse a list of wire names, refusing an unknown one.
    pub fn from_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Option<Self> {
        let mut out = Self::NONE;
        for name in names {
            let (bit, _) = Self::NAMED.iter().find(|(_, n)| *n == name)?;
            out = out.union(*bit);
        }
        Some(out)
    }
}

/// The action string a device signs for a space request, with its targets bound in.
///
/// A signed request names one resource (`crate::ResourceRef`) — here the space. Most space
/// actions also have a second target in the path: *which* member to kick, *which* role to
/// assign. Signing only the space would let a captured "assign role R to Bob" be replayed,
/// inside the window, as "assign role R to Mallory" by rewriting the path. So the targets are
/// part of the action. `verb` never contains `:`, and a uuid's hyphenated form is fixed-width,
/// so two different target lists cannot produce the same string.
pub fn space_action(verb: &str, targets: &[&uuid::Uuid]) -> String {
    debug_assert!(!verb.contains(':'), "a verb must not contain the separator");
    let mut out = String::from("space.");
    out.push_str(verb);
    for t in targets {
        out.push(':');
        out.push_str(&t.hyphenated().to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signed_space_action_names_its_targets() {
        let (a, b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        assert_ne!(space_action("kick", &[&a]), space_action("kick", &[&b]));
        assert_ne!(space_action("assign_role", &[&a, &b]), space_action("assign_role", &[&b, &a]));
    }

    #[test]
    fn unknown_bits_are_refused_rather_than_stored() {
        assert_eq!(Permissions::from_bits(1 << 31), None);
        assert_eq!(Permissions::from_bits(Permissions::ALL.bits()), Some(Permissions::ALL));
    }

    #[test]
    fn names_round_trip() {
        let p = Permissions::READ.union(Permissions::KICK);
        assert_eq!(p.names(), vec!["read", "kick"]);
        assert_eq!(Permissions::from_names(p.names()), Some(p));
        assert_eq!(Permissions::from_names(["administrator"]), None);
    }

    #[test]
    fn all_is_exactly_the_named_bits() {
        let named = Permissions::NAMED.iter().fold(Permissions::NONE, |a, (p, _)| a.union(*p));
        assert_eq!(named, Permissions::ALL);
    }
}
