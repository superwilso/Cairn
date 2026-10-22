//! Interoperability tests for Cairn's MLS layer. The tests are in `tests/`; this crate has
//! no code of its own.
//!
//! Cairn's MLS is `mls-rs`, so every Cairn test until now checked `mls-rs` against itself.
//! That cannot catch a choice two implementations make differently, and an outsider
//! implementing `docs/15-protocol.md` will almost certainly not use `mls-rs`. These tests
//! put [OpenMLS](https://github.com/openmls/openmls), an independent RFC 9420
//! implementation, on the other side of the same group.

#![forbid(unsafe_code)]
