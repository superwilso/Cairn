//! Cairn instance server, as a library.
//!
//! The binary is a thin wrapper over this. It exists as a library so the HTTP surface can
//! be tested **over a real socket** rather than only through in-process calls to
//! [`state`]. That distinction is not academic here: two shipped vulnerability classes —
//! rooms with no membership concept, and devices registerable against any account — both
//! looked correct in unit tests written against the same wrong mental model that produced
//! the code. What found them was making the actual request.
//!
//! ## Status
//!
//! Pre-alpha scaffold. No TLS termination — it must sit behind a reverse proxy. **Not
//! deployable.**

#![forbid(unsafe_code)]

pub mod address;
pub mod backup;
pub mod gif_relay;
pub mod http;
pub mod spaces_http;
// The SFU is a default-on feature so an operator can build an instance without it. Without
// the feature the same interface refuses to start, so nothing else in the crate is conditional.
#[cfg(feature = "sfu")]
pub mod sfu;
#[cfg(not(feature = "sfu"))]
#[path = "sfu_disabled.rs"]
pub mod sfu;
pub mod state;
pub mod storage;
