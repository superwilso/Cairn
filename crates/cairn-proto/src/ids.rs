//! Opaque identifiers.
//!
//! All IDs are UUIDs rather than sequential integers. Sequential IDs leak volume and
//! ordering to anyone who can see them, which matters here because
//! `docs/01-threat-model.md` already concedes broad metadata exposure — there is no
//! reason to make it worse for free.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

macro_rules! opaque_id {
    ($name:ident, $prefix:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Mint a new random identifier.
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            pub const fn from_uuid(id: Uuid) -> Self {
                Self(id)
            }

            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            /// Short prefixed form for logs and UI.
            pub fn display_prefix() -> &'static str {
                $prefix
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}_{}", $prefix, self.0.simple())
            }
        }
    };
}

opaque_id!(UserId, "usr", "An account on an instance.");
opaque_id!(
    DeviceId,
    "dev",
    "A single device belonging to a user. Each device holds its own MLS leaf and its own \
     identity key — see `docs/01-threat-model.md` §6."
);
opaque_id!(RoomId, "rom", "A conversation: DM, group chat, or community channel.");
opaque_id!(MessageId, "msg", "A single message.");
opaque_id!(InstanceId, "ins", "A Cairn server instance.");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique() {
        assert_ne!(UserId::new(), UserId::new());
    }

    #[test]
    fn display_is_prefixed() {
        let id = RoomId::new();
        assert!(id.to_string().starts_with("rom_"));
    }

    #[test]
    fn serde_is_transparent() {
        // Transparent so the wire format is a bare UUID string, not a wrapper object.
        let id = UserId::new();
        let json = serde_json::to_string(&id).unwrap();
        assert!(json.starts_with('"'));
        assert_eq!(serde_json::from_str::<UserId>(&json).unwrap(), id);
    }

    #[test]
    fn distinct_id_types_do_not_mix() {
        // Compile-time property: this test exists to document that UserId and RoomId are
        // distinct types. `let _: UserId = RoomId::new();` would not compile.
        let user = UserId::new();
        let room = RoomId::new();
        assert_ne!(user.as_uuid(), room.as_uuid());
    }
}
