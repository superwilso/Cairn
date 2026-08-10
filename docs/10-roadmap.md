# Roadmap

**Status:** Active. This is the document a session picks work from.

The route to a finished app, in the order the owner chose:

> usable → test with friends → open source → audits and community feedback → finished app

Each milestone has an **exit condition** that is checkable, not a feeling. Work does not
move to the next milestone while the current one's exit condition is unmet.

---

## M1 — Dogfoodable core, no UI

**Goal:** two people on two machines can hold an end-to-end encrypted conversation across a
real network, and both can close their clients and resume.

Today the vertical slice runs *in-process*. `cairn-cli` fakes the server. Client state now
persists, so what is left is the network.

- [x] **Client-side MLS state persistence.** Group state, key package secrets, the device
      key, and the room→group index survive a restart; `Conversation::resume_encrypted`
      rebuilds a conversation from disk alone. Covered by
      `a_conversation_resumes_from_disk_and_keeps_talking`.
- [x] **A real network client.** `cairn_client_core::Client` over a `Transport` seam,
      with a rustls-backed `HttpTransport`. It builds and signs every request, so a
      platform UI cannot construct a wrongly-scoped one (ADR-006). `cairn-cli` still
      prints the in-process slice; rewiring its presentation onto `Client` is cosmetic and
      outstanding.
- [x] **Key package distribution.** `POST /v1/devices/{device}/key-packages` publishes,
      `POST /v1/users/{user}/key-packages` claims one per device and consumes them. Both
      require a signed request naming the target. Verified over a real socket in
      `crates/cairn-server/tests/key_packages_http.rs`. **No rate limiting yet**, so an
      authenticated account can still drain another's supply — M3.
- [x] **Message delivery.** `Client::fetch_since` polls; WebSocket can wait.
- [x] **Franking round-trip over the wire**, not just in-process.

**Exit:** two processes on two machines exchange E2EE messages, both restart, both resume,
and a recipient files a report the server verifies.

**Status: met in one process over a real socket**, by
`crates/cairn-server/tests/vertical_slice_http.rs` — two clients with separate sessions and
separate on-disk stores, talking HTTP, both restarting mid-conversation, ending in a report
the server verifies and a tampered one it rejects. **Not yet demonstrated on two physical
machines**, which is the part of the exit condition still owed and belongs with M3's
self-hosting guide.

## M2 — Basic client

**Goal:** something a person who is not the author can use without reading the source.

The owner has deferred UI, so this is deliberately minimal — a TUI or a plain desktop
window, not the native Windows client of ADR-006.

- [x] **Minimal client UI.** `cargo run -p cairn-cli -- chat`, line-based, no new
      dependencies. Creates rooms, adds members, sends and receives, verifies contacts.
- [x] **Tier badge always visible** — on every prompt, derived *locally* from the room's
      shape. `Client::create_room` refuses a room the instance classifies differently in
      either direction, rather than displaying a label it cannot vouch for. The badge also
      says `plaintext-transport` over `http://`, since a lock icon there would be a claim
      the threat model does not support.
- [x] **Safety numbers displayed and comparable** (`/safety`, `/verify`), computed from
      the MLS roster. Probing found the previous construction certified nothing: both ends
      of a MITM'd conversation displayed the *same* number. See `01-threat-model.md` §4.
- [x] **Membership changes visible in the timeline.** Additions, removals, and this
      device's own removal are distinct events; before this a commit adding a member was
      indistinguishable from any other handshake.
- [x] Contact store persisting verification state, including a sticky
      `ChangedSinceVerified` warning that re-observation cannot clear.

**Exit: partly met.** The mechanics work end to end against a real server — verified by
running two clients, not only by tests, which is how the message-truncation and
cursor-replay bugs surfaced. **What is still owed is the invite flow**: a joiner currently
needs a room id pasted to them out of band and must be added by user id, so "joins by
invite, without being told what to type" is not yet true. That belongs with M3's invite
work, which the same exit condition depends on.

## M3 — Friends test

**Goal:** the owner runs an instance and a handful of people use it for real.

- [x] **Self-hosting guide**, honest about what is not ready — `docs/11-self-hosting.md`,
      with a "What is not ready" section split into what bites a small deployment and what
      is structural.
- [x] **Docker image and compose file.** Multi-stage build pinned to the MSRV floor,
      unprivileged user, `--locked`. The image could not be built in the authoring
      environment (no Docker daemon), but the Dockerfile's exact file set was verified to
      build with `--locked` from a clean copy.
- [x] **TLS guidance.** Caddy in the compose file terminates TLS and obtains certificates;
      `cairn` has **no published port**, so the plaintext server is unreachable from
      outside the Docker network. §3 of the guide explains why this is not optional: MLS
      covers message bodies, and A1/A2 belong to the transport.
- [x] **Registration invites work end to end.** `cairn-cli chat --invite <token>`. The
      client claims once and records it, because the server checks the invite *before* it
      notices the account already exists — without that, a returning user is locked out of
      their own account.
- [ ] **Room invite links** — a joiner is still handed a room id and a user id by hand.
      **M2's exit condition depends on this**, not just M3's.
- [ ] Backup and restore, including **the franking key**: losing it invalidates every
      report the instance ever issued
- [ ] Rate limiting on registration and sending
- [ ] Crash/restart resilience under real use

**Exit:** five people use it for two weeks. Bugs come from use, not from tests.

## M4 — Open source launch

**Goal:** the repository is public and someone else could plausibly contribute.

- [ ] **Licence files committed** — AGPL-3.0 and Apache-2.0, verbatim *(owner)*
- [ ] **Name clearance** — USPTO/EUIPO, domains *(owner; may rename, see `NAMING.md`)*
- [ ] Protocol specification good enough for an outsider to implement against
- [ ] Public threat model review invited
- [ ] Build and contribution instructions that work on a clean machine
- [ ] Reproducible builds investigated

**Exit:** the repository is public, and a stranger can build and run it from the README.

## M5 — Audit and community

**Goal:** people who are not us have attacked it.

- [ ] **External cryptographic review** of franking and the protocol. `SECURITY.md` calls
      this non-optional and it is the cheapest security spend available
- [ ] Independent MLS interop against another RFC 9420 implementation
- [ ] Key transparency, so a malicious server is bounded without manual comparison
- [ ] **Subscribable policy lists** — `04-safety-architecture.md` §2 calls this the
      highest-leverage safety item, and it is still unbuilt
- [ ] Group franking reviewed under the current server-anchored design
- [ ] Security disclosure process exercised at least once
- [ ] Findings fixed and published

**Exit:** an external reviewer's findings are closed, and the claims in `SECURITY.md`
survive someone else's scrutiny.

## M6 — Finished app

Only after M5. Native clients per ADR-006, mobile, communities at scale, authenticated
embeds, voice. The feature scorecard in `08-feature-parity.md` is the target.

- [ ] **Attachments.** Encrypted blob storage, chunked and resumable upload/download, a
      per-attachment key carried inside the encrypted message. **A prerequisite, not a
      nice-to-have**: sending a photo or video needs it, and so does any embed that
      re-hosts media. Nothing in the envelope today can carry a file — `EnvelopePayload`
      has no attachment variant — and the server's snapshot storage rewrites all state per
      message, so this lands on a known scaling gap. Deserves its own ADR.
- [ ] **Video sending.** Table stakes against every product in `08-feature-parity.md`.
      Blocked on attachments; unrelated to embeds despite sharing the word.
- [ ] **Authenticated embeds**, per `05-embeds.md`. **Text cards already ship** —
      sender-side unfurl, card inside the encrypted body, server never sees the URL. What
      remains here is the authenticated rung of the fallback chain (per-platform sessions),
      the proxy rung with its privacy notice, per-platform opt-in, a DNS-resolving address
      check, multi-media cards (Instagram carousels), and video — whose inline playback
      requires re-hosting because Cairn cannot use an iframe player.

---

## Working order for an autonomous session

1. Take the topmost unchecked item in the earliest incomplete milestone.
2. **Probe before building.** Three vulnerability classes in this project were found by
   writing a test that attacked the code, and none by reading it. If the item touches
   something that already exists, try to break it first.
3. One coherent change per PR, with the reasoning in the commit message.
4. Update the docs the change makes stale **in the same commit**. A doc that overstates
   what is built is the specific failure this project cannot afford.
5. Tick the box here when the exit condition is met, not when the code compiles.

## Standing constraints

From `00-vision.md`, and they outrank roadmap velocity:

1. Never weaken an encryption tier after launch
2. Never ship client-side scanning as an enforcement mechanism
3. **Never claim a protection the threat model does not support**
4. No ads, no monetization derived from message content
5. The flagship instance gets no protocol privileges a self-hosted one cannot have
