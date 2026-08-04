# Protocol Evaluation

**Status:** Architecture decided; measurements outstanding
**Decision record:** [ADR-005](adr/005-protocol-core.md)

## What this was

A timeboxed evaluation between three options for the protocol core — custom MLS-native,
build on Matrix, or fork Stoat — decided against criteria fixed **before** measuring, so
that the numbers decided the outcome rather than being recruited to justify it.

## What actually happened

The architecture was settled early by a requirement rather than a benchmark: **native
clients on Windows, macOS, Linux, iOS, and Android**. Both non-custom options derived most
of their value from existing non-native clients (Element-derived for Matrix, TypeScript for
Stoat), so that requirement removed their main advantage. See
[ADR-005](adr/005-protocol-core.md).

This is worth being explicit about: the decision was made on architectural grounds, not on
performance measurements. Those are still owed.

## Criteria, and status

| # | Criterion | Weight | Status |
|---|---|---|---|
| 1 | Cost to reach E2EE DMs + a 1,000-member MLS group | High | ⚠️ DMs done; 1,000-member untested |
| 2 | Mobile sync and battery under MLS commit churn | High | ❌ Not measured — no mobile client |
| 3 | Public-server read path at 50k members | High | ❌ Not measured |
| 4 | Can the safety stack be implemented natively | High | ✅ Franking implemented and tested |
| 5 | Ecosystem and migration path | Medium | ✅ Assessed — custom core has none; accepted |
| 6 | Governance independence | Medium | ✅ Full |

## Findings so far

**From building the scaffold (`crates/`):**

- **A DM as a two-member MLS group works**, and the one-code-path approach holds up.
  Verified by `two_member_dm_round_trip`.
- **Post-compromise security after removal is real**, not merely claimed — a removed member
  cannot decrypt subsequent messages (`removed_member_cannot_read_later_messages`).
- **`mls-rs` is synchronous by default.** It generates both surfaces via `maybe_async`. An
  initial reading of the source suggested async-only; the compiler corrected it. This
  matters well beyond style: no async runtime needs to cross the FFI boundary, which
  materially simplifies the Swift and Kotlin bindings ([ADR-006](adr/006-platform-architecture.md)).
- **Build and iteration speed are not a concern.** `mls-rs` compiles cold in ~27s; the full
  workspace test suite runs in well under a second.
- **Transcript franking is practical** — a plain HMAC hash chain gives verifiable causality
  with no exotic cryptography. Detecting an omitted middle message costs nothing extra.
- **The franking opening now travels inside the encrypted body**, so a recipient can
  actually file a report. The recipient also re-derives the commitment and rejects the
  message if it does not open to the text they were shown — without that check a sender
  could have the server tag one commitment while displaying different text, leaving the
  recipient unable to prove what they received.
- **Safety numbers work against real MLS identity keys**, not just synthetic input. An
  impostor claiming the same identity string still produces a different number.
- **Envelope authentication had to come before franking could mean anything.** A franking
  tag binds a commitment to a *claimed* sender; while anyone could claim to be anyone, the
  tag proved nothing and unframeability did not hold. Signing the envelope and fixing the
  device→account binding at registration is what makes the attribution real.

## Still owed

These block fixing the tier constants and any public claim about group sizes:

- [ ] **1,000-member MLS group**: join, leave, and commit latency; memory per client
- [ ] **Mobile battery and sync** under sustained commit churn — needs a mobile client
- [ ] **50,000-member public channel** read path
- [ ] **MLS group state persistence** on the *client* (server state now persists; client
      group state is still in-memory, so a client cannot resume a session after restart)
- [ ] **`T1_MAX_MEMBERS` / `T2_MAX_MEMBERS`** — currently provisional placeholders
      (256 / 2,000) in `crates/cairn-proto/src/tier.rs`, clearly marked as such

A benchmark harness should live in `crates/cairn-crypto/benches/`.

## Known gaps in the scaffold

Deliberate omissions, listed so nobody mistakes the scaffold for a product:

| Gap | Consequence |
|---|---|
| No key transparency; safety numbers not surfaced in a UI | The primitive exists and is tested, but nothing displays it and no contact store persists verification state, so in practice E2EE still holds against an honest-but-curious server rather than a malicious one (`01-threat-model.md` §4) |
| Snapshot storage rewrites all state per message | O(messages) per write; fine for a scaffold, not for load |
| No write-ahead log | A crash between saves loses everything since the last one (writes are atomic, so never a partial file) |
| No account system | Messages are authenticated per device, but anyone can *register* any unused user id — no passwords, sessions, invites, or rate limits |
| No group franking (AGMF) | T2 franking is not yet sound for groups |
| JSON + hex wire format | A development convenience; a binary format replaces it |
| No TLS termination | Must sit behind a reverse proxy |

## Verification standard

Before any of this protects a real user:

1. **External cryptographic review** of the protocol spec, by someone who is not on the
   project. This is the cheapest security spend available and it is not optional.
2. **Two-device end-to-end test**: confirm via packet capture and server logs that the
   server stored only ciphertext.
3. **Franking end-to-end**: generate a report, verify it validates, and verify a tampered
   transcript fails.
4. **Independent MLS interop** against another RFC 9420 implementation.

Item 3 is currently satisfied in-process by `cargo run -p cairn-cli`; items 1, 2, and 4 are
outstanding.
