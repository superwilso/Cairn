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
- [ ] **A real network client.** `cairn-cli` talks to `cairn-server` over HTTP: claim an
      account, create a room, add a member, send, receive, report.
- [x] **Key package distribution.** `POST /v1/devices/{device}/key-packages` publishes,
      `POST /v1/users/{user}/key-packages` claims one per device and consumes them. Both
      require a signed request naming the target. Verified over a real socket in
      `crates/cairn-server/tests/key_packages_http.rs`. **No rate limiting yet**, so an
      authenticated account can still drain another's supply — M3.
- [ ] **Message delivery.** Polling is enough for M1. WebSocket can wait.
- [ ] **Franking round-trip over the wire**, not just in-process.

**Exit:** two processes on two machines exchange E2EE messages, both restart, both resume,
and a recipient files a report the server verifies.

## M2 — Basic client

**Goal:** something a person who is not the author can use without reading the source.

The owner has deferred UI, so this is deliberately minimal — a TUI or a plain desktop
window, not the native Windows client of ADR-006.

- [ ] Minimal client UI (TUI is acceptable and cheapest)
- [ ] **Tier badge always visible** — `docs/02-encryption-tiers.md` §4 is normative, and a
      client that hides it is worse than one with no encryption, because users calibrate to
      the badge
- [ ] **Safety numbers displayed and comparable.** Until a UI shows them, key verification
      protects nobody and a malicious server stays unbounded (`01-threat-model.md` §4)
- [ ] Membership changes visible in the timeline — a silently added member is a wiretap
- [ ] Contact store persisting verification state

**Exit:** a friend installs it, joins by invite, sends a message, and compares a safety
number, without being told what to type.

## M3 — Friends test

**Goal:** the owner runs an instance and a handful of people use it for real.

- [ ] Self-hosting guide, honest about what is not ready
- [ ] Docker image and compose file
- [ ] TLS guidance — the server has no transport security of its own
- [ ] Invite flow that a non-technical person can follow
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
