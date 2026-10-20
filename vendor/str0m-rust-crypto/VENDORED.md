# Why this copy exists

`str0m-rust-crypto` 0.6.0 is the "pure Rust" crypto backend for `str0m`, the SFU's WebRTC
stack. Every published version switches on `dimpl`'s `rcgen` feature to generate the SFU's
self-signed DTLS certificate, and that feature also switches on `dimpl`'s `aws-lc-rs` feature.
**When both are compiled in, `dimpl::Config::build` picks AWS-LC over RustCrypto** (see its
provider order), so with the published crate the SFU's DTLS handshakes ran on AWS-LC, a C
library, while everything around it said pure Rust. Found while chasing an MSRV failure.

This copy is the published 0.6.0 source with one change: `generate_certificate` in
`src/dtls.rs` builds the certificate with `p256` and `x509-cert`, both already in the tree,
instead of `dimpl::certificate`. With `rcgen` gone, `aws-lc-rs` and `rcgen` leave the build
and dimpl's only provider is RustCrypto. The certificate is the shape upstream makes: ECDSA
P-256 with SHA-256, a random 128-bit serial (Firefox rejects a repeated issuer and serial),
a year's validity, a PKCS#8 key. It is wired in by `[patch.crates-io]` in the workspace
`Cargo.toml`.

What it does **not** fix: `str0m`, `str0m-proto` and `dimpl` each depend on `time`, which
needs rustc 1.88 from 0.3.47 (the release fixing RUSTSEC-2026-0009). So the SFU stays above
the project's 1.85 floor whatever this crate does; `cairn-server`'s `sfu` feature exists for
that, and the MSRV job checks the server without it.

The unit test in `src/dtls.rs` does not run in the workspace's `cargo test` (this directory
is excluded from the workspace). Every real handshake does: `crates/cairn-server/tests/voice_sfu.rs`
and `clients/desktop/tests/voicechannel.browser.test.js` connect through this certificate.

**Drop this directory** when a `str0m-rust-crypto` release stops enabling `rcgen`.

Licence: MIT OR Apache-2.0, as upstream (https://github.com/algesten/str0m), Martin Algesten.
