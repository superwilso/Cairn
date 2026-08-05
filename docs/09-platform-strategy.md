# Platform Strategy

**Status:** Draft
**Decision record:** [ADR-006](adr/006-platform-architecture.md)

## Target matrix

**Clients — all native.** Windows, macOS, Linux, iOS, Android.
**Servers.** Linux (primary), Windows, macOS. Old phones as low-power servers: a plausible
later target, explicitly not a v1 goal, and not a constraint on any current decision.

## Architecture in one line

One shared Rust core; a thin native UI per platform; no protocol logic above the FFI line.
See [ADR-006](adr/006-platform-architecture.md) for the full diagram and rationale.

## What exists today

| Crate | Role | Status |
|---|---|---|
| `cairn-proto` | Wire types, IDs, tier model | Scaffold, tested |
| `cairn-crypto` | MLS sessions, franking | Scaffold, tested |
| `cairn-client-core` | Conversation logic, tier enforcement | Scaffold, tested |
| `cairn-server` | Instance server | Scaffold, tested |
| `cairn-cli` | Headless demo client | Working |

No UI exists yet, deliberately — the protocol comes first, and the core is fully testable
without one.

## Client sequencing

1. **Headless CLI** — done. Proves the protocol without UI work.
2. **Windows desktop** — first GUI target. WinUI 3 over the Rust core via C ABI.
3. **Linux desktop** — GTK4 + libadwaita. Likely where early adopters are.
4. **Android** — Jetpack Compose, UniFFI Kotlin bindings.
5. **macOS + iOS** — SwiftUI, UniFFI Swift bindings, most view code shared.

## Server hosting

The server is pure Rust with no platform-specific dependencies, so all three host platforms
build from one source tree.

| Platform | Support | Notes |
|---|---|---|
| Linux x86_64 | Primary | Tested, documented, the reference deployment |
| Linux aarch64 | Primary | Small VPS and single-board machines |
| Windows | Best-effort | CI-built; less operational tooling |
| macOS | Best-effort | CI-built; mainly for developers |

Self-hosting is a first-class requirement, so the deployment story has to be genuinely
easy: a single static binary, a config file, and a Docker image. If self-hosting is hard,
"self-hostable" is a marketing claim rather than a property.

## Build and verification status

Honest reporting of what has actually been verified, and where:

| Target | Status |
|---|---|
| Linux x86_64 — build + tests | ✅ **Verified locally and in CI.** 48 tests pass; the demo runs; the server responds over HTTP |
| Windows x86_64 — build + tests | ✅ **Verified in CI.** Full test suite and the vertical slice pass on `windows-latest` |
| macOS — build + tests | ✅ **Verified in CI.** Full test suite and the vertical slice pass on `macos-latest` |
| iOS / Android — build | ⚠️ Not attempted; no bindings exist yet |

The cross-platform claim is therefore checked rather than assumed: the same source tree
builds and passes its tests on all three desktop platforms today, before any UI exists.

**Minimum supported Rust version: 1.85.** This is a hard floor rather than a preference —
the crypto dependency tree pulls in crates requiring `edition2024`, which stabilized in
exactly that release. CI enforces it.

CI (`.github/workflows/ci.yml`) builds and tests on Linux, Windows, and macOS so the
cross-platform claim is continuously checked rather than assumed.

## Constraints that will shape the FFI

- **`mls-rs` is synchronous by default.** No async runtime crosses the FFI boundary, which
  materially simplifies the Swift and Kotlin bindings. This was confirmed against the
  crate, not assumed — an earlier reading of the source suggested async-only, and the
  compiler corrected it.
- **Key storage is platform-specific** and does not abstract cleanly: Windows DPAPI, macOS
  and iOS Keychain, Android Keystore, and on Linux a genuinely fragmented picture. The core
  needs a storage trait with a native implementation per platform.
- **Push notifications** must carry no content and no sender identity — only an opaque
  wake signal (`01-threat-model.md` §8). APNs and FCM are untrusted third parties.
- **Background execution** differs sharply per platform and constrains how MLS commit
  backlogs are processed after a device has been offline.

## Open questions

1. **Web client?** It would widen reach substantially, but its guarantees are weaker
   because the server ships the code that holds the keys. If it happens, the UI must say
   so plainly. Deferred to v3.
2. **Reproducible builds.** Signal has them; they are a meaningful trust signal for a
   security product, and they are much cheaper to design in early than to retrofit.
3. **Old phones as servers.** Attractive for the self-hosting story. Needs a decision on
   whether ARM Android-as-host is a supported configuration or a curiosity.
