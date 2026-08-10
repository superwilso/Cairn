//! # cairn-crypto
//!
//! Cryptography for Cairn: MLS group sessions ([`mls`]) and message franking
//! ([`franking`]).
//!
//! ## Rules for this crate
//!
//! 1. **No hand-rolled group cryptography.** MLS comes from `mls-rs`, a conformance-tested
//!    RFC 9420 implementation. See `docs/adr/002-mls-for-groups.md`.
//! 2. **Secrets do not appear in `Debug` output.** Openings and keys print as
//!    `<redacted>`, and are zeroized on drop.
//! 3. **Comparisons on secret-dependent values are constant time**, via `subtle`.
//!
//! ## Status
//!
//! Pre-alpha and **not audited**. Per `docs/03-protocol-evaluation.md`, external
//! cryptographic review is required before any of this protects a real user.

#![forbid(unsafe_code)]

pub mod attachment;
pub mod franking;
pub mod mls;
pub mod store;
pub mod verification;

pub use franking::{
    commit, verify_commitment, Commitment, Context as FrankingContext, Opening, ReportError,
    ReportedMessage, ServerFrankingKey, Tag, TranscriptReport,
};
pub use mls::{CommitOutput, GroupHandle, MlsError, Session};
pub use store::{ClientStore, DeviceKey, StoreError};
pub use verification::{ContactVerification, Fingerprint, SafetyNumber, VerificationState};
