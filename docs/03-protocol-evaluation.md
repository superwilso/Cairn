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
| 1 | Cost to reach E2EE DMs + a 1,000-member MLS group | High | ✅ **Measured** — see below |
| 2 | Mobile sync and battery under MLS commit churn | High | ❌ Not measured — no mobile client |
| 3 | Public-server read path at 50k members | High | ❌ Not measured |
| 4 | Can the safety stack be implemented natively | High | ✅ Franking implemented and tested |
| 5 | Ecosystem and migration path | Medium | ✅ Assessed — custom core has none; accepted |
| 6 | Governance independence | Medium | ✅ Full |

## Findings so far

**From building a UI on top of the primitives (M2):**

- **A safety number is only as good as where its keys came from.** `mls-rs` exposes the
  group roster, but nothing in Cairn read it, so the only key a client could reach was the
  one the server published. Both ends of a MITM'd conversation then display the *same*
  number. The lesson generalises past safety numbers: **any value a UI presents as evidence
  must be sourced from state the adversary cannot write**, and for anything about a group
  that means the ratchet tree, never the account directory.
- **`ReceivedMessage::Commit` is not enough to detect a membership change**, and the
  roster diff is not enough either. `mls-rs` does not advance a group whose local client
  was just removed, so a self-removal shows an unchanged roster; it has to be read from
  `CommitEffect::Removed`. Two different mechanisms are needed for what looks like one
  event, and only running a removal over HTTP revealed it.
- **A read cursor is protocol state, not UI convenience.** MLS discards each message key
  after use, so a client that restarts and re-reads a room from sequence 0 cannot decrypt
  its own history — it emits `invalid generation` and `incorrect epoch` for traffic it
  already consumed. The cursor must be persisted with the same care as the group index.
- **A welcome can travel through the room it invites you to.** No separate channel or
  endpoint is needed: the joiner is made a room member server-side first, then finds the
  welcome among traffic it cannot read (`is_welcome` distinguishes it). This keeps the
  server's single sequencing point covering handshakes and messages together, which is the
  ordering MLS requires (ADR-002).
- **Running it found bugs the tests could not.** Two clients against a live server surfaced
  a message truncated at its first space and a replay storm on restart. Every test had sent
  single-word messages and used fresh state, so both passed.

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
- **`mls-rs` does not persist group state for you.** `write_to_storage` is explicit, and
  omitting it fails silently rather than loudly. Probing the omission on the encrypt path:
  two handles loaded from one saved state each encrypt once, the receiver takes the first
  message and rejects the second with `KeyMissing` — the second is undeliverable and the
  sender never learns. It is *not* an AEAD nonce collision, because RFC 9420 §7.3.1's
  4-byte reuse guard randomizes the nonce, and the first draft of this module's docs
  claimed otherwise before the claim was checked. `GroupHandle` therefore persists after
  every mutation rather than exposing a `save()`.
- **A conversation cannot be allowed to invent its own room id.** `create_encrypted`
  minted one locally, which worked only because the vertical slice faked the server
  in-process. Against a real server every message was addressed to a room that did not
  exist and came back `404 no such room`. The constructors now require the id the server
  assigned. This is precisely the class of defect `CLAUDE.md` says to expect from
  in-process testing, and it took one HTTP request to find.
- **A signed request has to name what it acts on, not just what it does.** Request
  authorization could originally bind only a `RoomId`, so the key package endpoints would
  have had to sign "no resource" — authorizing the action alone. One legitimately obtained
  signature would then drain any account inside the 60s replay window. `ResourceRef` now
  carries a kind label and an id, both signed.

  The first HTTP test written for this **passed against the broken design**, because the
  test client and the server disagreed about what to sign and the request failed for the
  wrong reason. It was replaced with one checked against the counterfactual: reverting the
  handler makes it fail. A test that cannot fail is the project's documented failure mode,
  not a new one.
- **MLS key packages are single-use, so there is no last-resort package.** `mls-rs` deletes
  a package's secrets once it is used to join, so serving one twice would leave the second
  welcome permanently unopenable. An exhausted account is therefore an error the caller
  sees (409), not a silent half-add.
- **The room→group mapping is client-only state.** MLS picks group ids and the server picks
  room ids; nothing but the client holds the correspondence. Losing that index leaves the
  group state on disk and unreachable, which is indistinguishable from losing it.
- **Envelope authentication had to come before franking could mean anything.** A franking
  tag binds a commitment to a *claimed* sender; while anyone could claim to be anyone, the
  tag proved nothing and unframeability did not hold. Signing the envelope and fixing the
  device→account binding at registration is what makes the attribution real.

## Criterion 1: measured

`cargo run -p cairn-crypto --example group_scaling --release`, on the development
container. Absolute numbers are machine-specific; the growth rates are the point.

| n | add member | commit | welcome | encrypt | decrypt |
|---|---|---|---|---|---|
| 2 | 1.21 ms | 472 B | 908 B | 125 µs | 79 µs |
| 10 | 1.01 ms | 472 B | 2.4 KB | 109 µs | 71 µs |
| 100 | 1.58 ms | 472 B | 18.7 KB | 89 µs | 60 µs |
| 250 | 4.11 ms | 472 B | 46.2 KB | 87 µs | 60 µs |
| 500 | 5.28 ms | 472 B | 91.9 KB | 89 µs | 59 µs |
| 1000 | 10.02 ms | 472 B | 183.4 KB | 93 µs | 62 µs |

**ADR-002's O(log n) claim holds for ongoing operations.** Growing the group 500× raised
add-member cost 8.3×, against 9.0× predicted by log₂. Commit size is *constant* at 472
bytes at every size measured, and message encrypt/decrypt are flat — the cost of sending
does not depend on how many people are listening. Sender-key fanout would have grown
quadratically here.

**But joining is O(n), and that is the real ceiling.** The welcome message grows linearly
at ~180 bytes per member because it carries the ratchet tree. This was not called out in
ADR-002, which discussed group operations as uniformly logarithmic. It is the constraint
that actually sets the tier limits: a joiner at 2,000 members downloads ~360 KB, at 10,000
~1.8 MB, at 50,000 ~9 MB. Mobile joins, not mobile messaging, are what cap encrypted
community size.

The tier constants in `crates/cairn-proto/src/tier.rs` are therefore justified by
measurement rather than provisional. T2_MAX at 2,000 is extrapolated one doubling past the
largest measured group; re-measure before raising it.

## Still owed

- [ ] **Leave/removal cost** at scale (only add was measured)
- [ ] **Memory per client** at large group sizes
- [ ] **Mobile battery and sync** under sustained commit churn — needs a mobile client
- [ ] **50,000-member public channel** read path
- [x] **MLS group state persistence** on the *client* — done; see the finding below
The benchmark harness lives at `crates/cairn-crypto/examples/group_scaling.rs`.

## Known gaps in the scaffold

Deliberate omissions, listed so nobody mistakes the scaffold for a product:

| Gap | Consequence |
|---|---|
| No key transparency; safety numbers not surfaced in a UI | The primitive exists and is tested, but nothing displays it and no contact store persists verification state, so in practice E2EE still holds against an honest-but-curious server rather than a malicious one (`01-threat-model.md` §4) |
| Snapshot storage rewrites all state per message | O(messages) per write; fine for a scaffold, not for load |
| No write-ahead log | A crash between saves loses everything since the last one (writes are atomic, so never a partial file) |
| Client state stored unencrypted | Group state and key package secrets sit on disk in the clear, 0600 on Unix and default ACLs on Windows. Consistent with `01-threat-model.md` §3.4, but weaker than the platform keystores a shipping client needs |
| No sessions or rate limits | Accounts are claimed, invite-gated, and device linking is authorized — but there is no session concept, no rate limiting, and no account recovery. Concretely: an authenticated account can drain another account's key packages and make it unaddable until it republishes |
| Franking unreviewed | Groups are handled, but no external cryptographic review yet |
| JSON + hex wire format | A development convenience; a binary format replaces it |
| Replay window, not nonces | Signed requests carry a timestamp checked against a 60s window; replay inside that window is possible |
| No bans or instance-wide moderation | Rooms have owner/moderator/member roles and removal, but a removed account can be re-added, and there is no instance-level ban or the subscribable policy lists `04-safety-architecture.md` §2 calls the highest-leverage item |
| No TLS termination | Must sit behind a reverse proxy. `HttpTransport` verifies certificates via rustls, but pointing it at a bare `http://` origin is a plaintext connection and defeats A1/A2 in `01-threat-model.md` §2 |
| Vertical slice is one process | Two clients over a real socket, but not yet two machines — the last part of M1's exit condition |

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
