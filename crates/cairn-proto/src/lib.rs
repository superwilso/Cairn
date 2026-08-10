//! # cairn-proto
//!
//! Wire types, identifiers, and the encryption tier model for Cairn.
//!
//! This crate is deliberately dependency-light and contains no cryptography and no I/O.
//! It is the vocabulary shared by clients, the server, and any third-party
//! implementation. It is licensed permissively (Apache-2.0) for exactly that reason —
//! see `docs/adr/004-licensing.md`.
//!
//! ## Status
//!
//! Pre-alpha. The wire format is **not** stable and will change without notice until the
//! protocol specification is frozen.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod envelope;
pub mod identity;
pub mod ids;
pub mod tier;
pub mod username;

pub use envelope::{
    device_authorization_bytes, request_signing_bytes, Envelope, EnvelopePayload, ResourceRef,
};
pub use identity::{DeviceIdentity, IdentityError};
pub use ids::{BlobId, DeviceId, InstanceId, MessageId, RoomId, UserId};
pub use tier::{derive_tier, RoomSeal, RoomShape, ShapeError, Tier};
pub use username::{Username, UsernameError, MAX_USERNAME_LEN, MIN_USERNAME_LEN};

/// The wire protocol version this build speaks.
///
/// Bumped on any breaking change to [`envelope::Envelope`]. While the leading component
/// is 0, breaking changes may occur on any bump.
pub const PROTOCOL_VERSION: u16 = 0;
