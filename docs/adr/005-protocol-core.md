# ADR-005: Custom MLS-native core in Rust

**Status:** Accepted (architecture); performance constants still to be measured
**Date:** 2026-08-04

## Context

[`03-protocol-evaluation.md`](../03-protocol-evaluation.md) framed this as a two-week
timeboxed spike between three options: a custom MLS-native core, building on Matrix, or
forking Stoat. The spike was to be decided on six weighted criteria.

A new requirement arrived before the spike ran and settled most of it: **native
applications on Windows, macOS, Linux, iOS, and Android, with servers hostable on Windows,
Linux, and macOS.** That constraint is decisive on its own.

- **Matrix** — clients in the ecosystem are overwhelmingly Element-derived (web/Electron)
  or thin SDK wrappers. Its MLS story is MSC4244, still experimental, needing a per-room
  hub server. Adopting Matrix means adopting Megolm now and an unfinished MLS migration
  later, and fighting the ecosystem to get genuinely native clients.
- **Stoat** — its client is TypeScript, and its backend was not designed for E2EE.
  Retrofitting MLS into it while also replacing the client with five native apps means
  keeping very little of what the fork bought.
- **Custom, MLS-native in Rust** — one core library cross-compiles to all five client
  targets and all three server platforms. `mls-rs` and OpenMLS are both Rust, so the MLS
  dependency is native to the stack rather than bridged.

The "native everywhere" requirement therefore eliminates the two options whose value was
their existing non-native clients.

## Decision

**Build a custom, MLS-native core in Rust.**

1. **A shared Rust core** (`cairn-proto`, `cairn-crypto`, `cairn-client-core`) holds all
   protocol, cryptography, and client logic. It compiles to every client target.
2. **`mls-rs` provides MLS**, per [ADR-002](002-mls-for-groups.md). Selected over OpenMLS
   for its stated 100% RFC 9420 conformance. Revisit if its audit status does not improve.
3. **The server is Rust** (`cairn-server`), pure and dependency-portable, so the same
   source runs on Linux, Windows, and macOS. Linux is the primary supported target.
4. **Native UI per platform**, binding to the shared core via FFI. See
   [ADR-006](006-platform-architecture.md).
5. **Steal Matrix's moderation design, not its protocol.** Subscribable policy lists are
   the best moderation primitive in the field and are protocol-independent.

## What the spike still owes

Deciding the architecture is not the same as knowing the numbers. These remain open and
must be measured before the tier constants and product limits are fixed:

- [ ] Join/leave latency for a 1,000-member MLS group
- [ ] Mobile battery and sync cost under sustained commit churn
- [ ] Read-path latency on a 50,000-member public channel
- [ ] `T1_MAX_MEMBERS` and `T2_MAX_MEMBERS`, currently **provisional placeholders** in
      `crates/cairn-proto/src/tier.rs` (256 / 2,000) and explicitly marked as such

Until these land, no public claim should be made about maximum encrypted group size.

## Findings already in hand

From building the scaffold:

- **`mls-rs` is sync by default.** It generates both surfaces via `maybe_async`; the
  default feature set is synchronous. This is good news for FFI — no async runtime has to
  be pumped across the language boundary, which materially simplifies the iOS and Android
  bindings.
- **`mls-rs` compiles in ~27s from cold** on a modest Linux container, and the full
  workspace test suite runs in under a second. Iteration speed is not a concern.
- **The two-member-group-as-DM approach works** and is exercised in
  `crates/cairn-crypto/src/mls.rs`. Post-compromise security after member removal is
  verified by test, not merely assumed.

## Consequences

### Positive

- One implementation of the protocol and the cryptography, shared by every platform. Five
  native clients cannot drift into five different sets of security bugs.
- No legacy crypto and no migration inherited on day one.
- The server is cross-platform for free.
- Rust's memory safety matters disproportionately for a network service parsing hostile
  input. `#![forbid(unsafe_code)]` is set on every crate.

### Negative

- **We write everything.** Sync, storage, transport, presence, media, voice — none of it
  comes free. This is the largest cost in the project and it is accepted knowingly.
- No existing user base or bridge ecosystem to inherit.
- FFI to five platforms is real, ongoing work, and the binding layer is a place where
  memory-safety guarantees can be lost if done carelessly.
- Rust talent is scarcer than TypeScript talent, which affects contributor growth for an
  open-source project.

## References

- [`03-protocol-evaluation.md`](../03-protocol-evaluation.md) — criteria and what remains
- [ADR-002](002-mls-for-groups.md) — MLS
- [ADR-006](006-platform-architecture.md) — how the core reaches each platform
