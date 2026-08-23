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
      `crates/cairn-server/tests/key_packages_http.rs`. The drain this originally warned
      about is now **bounded** — see M3.
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

**Exit: met, and now without a manual step.** Invite links exist (`/invite`, `/join`), and
`/admit` closes the loop: a member opening a room is told who joined by invite and cannot
read yet, and one command lets them all in. No uuid is pasted anywhere in the flow.

Deliberately one command rather than automatic — the waiting list comes from the instance, so
admitting on its word alone would let a malicious one name an account and have a moderator's
client hand it the group keys silently. What was removed is the uuid, not the decision. Verified with two real clients:
alice mints an invite, bob redeems it, alice adds him to the encrypted group, and bob reads
the message that follows.

Superseded assessment, kept because the reasoning still applies to what is *not* done: the
mechanics worked end to end against a real server — verified by
running two clients, not only by tests, which is how the message-truncation and
cursor-replay bugs surfaced. **What is still owed is the invite flow**: a joiner currently
needs a room id pasted to them out of band and must be added by user id, so "joins by
invite, without being told what to type" is not yet true. That belongs with M3's invite
work, which the same exit condition depends on.

### Direction: WhatsApp for the surface, not for the architecture

The owner's call, and the boundary matters more than the list.

**Take from WhatsApp:** onboarding and identity, everyday messaging features, multi-device
and backup.

**Do not take:** its encryption model. **ADR-001 stands.** WhatsApp end-to-end encrypts
groups far larger than Cairn's T2 ceiling, which is a real demonstration that the other
choice works — and it was considered and declined. T3 remains transport-only and
server-readable, because that is what buys server-side moderation and search on the
surfaces where abuse actually scales. Everything below is additive to that model, and any
proposal that quietly erodes it is out of scope, not a refinement.

Also declined, for the record: **phone-number identity**. It is the strongest discovery
mechanism available and the most criticised thing about WhatsApp, because the address-book
upload hands the server the social graph. `01-threat-model.md` §3 already concedes broad
metadata exposure, so this would not break a stated guarantee — it would make the conceded
thing much worse, in the one product area where Cairn claims to be different.

#### What this means concretely

- **Usernames plus invite links** replace passing raw ids by hand. `@alice` claimed like an
  account; a link carrying a room capability for joining. This leaks nothing the server does
  not already know — it holds the accounts — and it removes the friction that has ended
  every session so far at "paste this uuid to your friend". Depends on the room-invite
  token design recorded under M3.
- **Everyday messaging**: disappearing messages, voice notes, media, message history. All
  but the first are behind attachments, which are behind [ADR-007](adr/007-server-storage.md).
  Disappearing messages are independent and cheap, and fit the threat model without strain.
- **Multi-device and backup.** Device-scoped MLS leaves already exist
  (`01-threat-model.md` §6), so the foundation is there and largely unused; `/v1/devices`
  exists but no linking flow does. Copy WhatsApp's *shape* for backup, not its defaults —
  cloud backup is historically where its E2EE guarantee weakened, and any backup here has to
  answer to `07-regulatory-posture.md` and the keystore decision above.

**Not adopted:** read receipts and typing indicators. Both leak more than users expect —
presence and timing are exactly what `01-threat-model.md` §3 lists as already-conceded
metadata, and these would broadcast it continuously rather than per message.

#### Sequencing

[ADR-007](adr/007-server-storage.md) came first and is **done**, so the dependency that
blocked most of this list is gone: media, voice notes and history sit behind attachments,
and attachments sat behind the storage rewrite. **Attachments are now half-built**: the server side landed — ciphertext blobs stored against
a room, membership checked on upload and on fetch — and the encryption alongside it
(`cairn_crypto::attachment`). The key now travels inside the
encrypted body (`Conversation::send_with_attachment`), with a test asserting it never
appears in the envelope the server sees. What remains is transport: `Transport::send` takes
a `&str` body, so uploading bytes needs that seam widened — and a file picker in a client
that has no UI yet.
Usernames and disappearing messages remain the two items that can proceed in parallel,
since neither needs attachments.

### Direction: Discord's real-time features

Voice calls, group calls and screen sharing are what keep communities on Discord, and
`08-feature-parity.md` marked them v2 without saying what they cost. Now designed in
[`12-realtime-media.md`](12-realtime-media.md), against Discord's own **DAVE** protocol as
the reference. Four things a session should not have to rediscover:

- **This is the largest component the project has considered** — larger than the server. A
  call needs its own MLS group (participants are not room members), the server has to
  sequence commits under join/leave races, and media needs SFrame (RFC 9605) plus an SFU.
- **It lands after the native clients**, not before. A terminal cannot capture a microphone.
  Sequencing: ADR-007 → attachments → native clients → this.
- **No downgrade, unlike DAVE.** Discord falls back to a plaintext passthrough mode for
  clients that cannot do E2EE media. Non-negotiable #1 forbids that here, so an E2EE-tier
  call **refuses** such a client rather than degrading. The cost — "your friend must update"
  instead of a warning banner — is accepted.
- **Calls are unreportable.** Transcript franking has no live-media equivalent, which is now
  stated in `04-safety-architecture.md` rather than discovered later.

One open question is escalated rather than answered, because the tier model is not a
session's to change: **do calls inherit the room's tier?** `02-encryption-tiers.md` §6.4
leaned always-E2EE; §12.1 of the new document argues for inherit, so that a room's badge and
its call's badge cannot disagree.

### Decided while the owner was reachable, for a session that is not

Four calls made deliberately in advance, so an unattended session does not guess.

- **Usernames resolve by exact match only.** `@alice` looks up if you already know the
  handle; there is **no search, listing, or browse**. Knowing a name confirms that account
  exists, which is the price of the feature — but nobody can walk the instance for a roster.
  Partial search was declined: on a private instance the membership list *is* the social
  graph, and `01-threat-model.md` §3 concedes metadata to the server, not to every account
  that registers.
- **Disappearing messages: per-room, any member may set it, and the clock starts on send.**
  Applies to future messages only. Start-on-read was declined because it requires the client
  to report having read a message, which is a read receipt wearing a different name — and
  read receipts were already excluded for broadcasting presence. "Any member" rather than
  moderators-only because a DM has no moderator and both parties are equals.
- **Local message history is stored now, unencrypted, and said so plainly.** `0600`, beside
  the client state that already sits there in the clear. This is strictly no worse than
  today — the group keys are already on disk — and without it the client cannot hold a real
  conversation, since MLS discards each message key after use and a restart loses everything.
  It is superseded by the platform keystores when the native clients land, and the docs must
  keep saying which of the two is in force.
- **Invite links: the creator chooses the terms.** All three shapes are offered at creation
  — single-use with a 24h expiry (the default), single-use with no expiry, and multi-use with
  a cap and a window — because the right answer differs between "a link for one friend" and
  "onboarding a group this evening".

  **One shape stays forbidden: unlimited uses.** An unbounded link is a public invite in
  everything but name, and `RoomSeal::may_mint_public_invite` exists because
  discoverability is an input to `derive_tier` — a genuinely public invite to a T1 or T2
  room would mean it should have been T3, and the tier cannot change (ADR-001). A capped,
  expiring link does not make a room discoverable. An uncapped one does.

### Decided, unimplemented

Four calls made by the owner, so a session does not re-litigate them:

- **Server storage → `redb`** ([ADR-007](adr/007-server-storage.md)). **Done.** Storing a
  message costs 640 bytes at message 1 and 646 at message 200, against 200× that under the
  old snapshot design. Attachments are no longer blocked on storage, which unblocks images
  in link previews and Instagram media. Migration from `state.json` is automatic and was
  verified by upgrading a real instance created with the previous build.
- **Attachment liability → sender responsible**, instance offers a removal path
  (`05-embeds.md` §4).
- **Client state at rest → platform keystores**, with the native clients. Blocks linked
  social accounts until it lands (`11-self-hosting.md`).
- **Room invites → single-use capability tokens**, which are not the public invite
  `may_mint_public_invite` forbids. Design and probes recorded under M3 below.

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
- [x] **Room invite links.** `/invite [uses] [hrs]` mints one, `/join <token>` redeems it.
      The creator chooses the terms; unlimited uses stays forbidden in code, not merely in
      docs. **M2's exit condition depended on this** and is now met.

      One bug the flow exposed, worth keeping: `add_room_member` checked the member ceiling
      *before* checking whether the target was already a member, so a DM at its ceiling of
      two was "full" for the joiner who had just redeemed an invite into it. Invites were
      useless for exactly the case they exist for, every unit test passed, and it surfaced
      only from running two clients through the whole flow.

      **Design, as built:**

      - A **single-use, server-generated, non-enumerable token** minted by a member with
        role ≥ Moderator, redeemed once, which adds the bearer as a `Member`.
      - **This is not the invite `RoomSeal::may_mint_public_invite` forbids**, and the
        distinction is the whole design. That guard blocks a *publicly discoverable*
        invite for an E2EE room, because discoverability is an input to `derive_tier` — a
        published invite would mean the room should have been T3, and the tier cannot
        change (ADR-001). A capability handed to one named person and spent on redemption
        does not make the room discoverable, so it does not weaken the tier. Say so in the
        code, or someone will later "fix" the inconsistency by loosening the guard.
      - Store the token **hashed** (SHA-256) and compare in constant time via `subtle`,
        matching the project's convention. The server can read its own state, so this is
        damage-limitation on a state leak, not a secrecy claim.
      - Redemption must still check the member ceiling, or a DM invite becomes a way past
        the two-person bound that `membership_respects_the_room_ceiling` defends.
      - Retain spent tokens rather than deleting them, as `InviteRecord` already does, so
        a replay is distinguishable from an unknown token.
      - **Probe before trusting it**: redeem twice, redeem after removal, redeem against a
        full room, redeem a token minted for a different room, and mint as a non-moderator.
        Membership is where this project's three shipped vulnerabilities lived.
- [x] **Backup and restore, including the franking key.** `cairn-server backup|verify|
      restore`, a logical snapshot taken inside one read transaction rather than a file copy.

      Probing the *documented* procedure is what shaped this. Copying a live `cairn.redb`
      produces a file that **opens cleanly on an idle instance and cannot be opened at all on
      a busy one** — so `cp` works exactly when an operator tests their backup and fails
      exactly when they need it, with the failure surfacing at restore time. The command
      opens the database instead, so redb's lock makes it refuse against a running instance.

      The same probing found a hole in the protection already in place: `FrankingKeyMissing`
      caught an *absent* key, and a **mismatched** one started perfectly cleanly while every
      report filed before the restore silently stopped verifying. The database now records a
      hash of the key it belongs to, so a separated pair is refused
      (`StorageError::FrankingKeyMismatch`). Verified live: a report filed before a backup
      still verifies against the restored instance.
- [x] **Rate limiting on key package claims.** Probing confirmed the drain rather than
      assuming it: one authenticated account emptied a victim's whole published supply in a
      loop, after which nobody could add that victim to a room. Now capped per actor —
      `MAX_CLAIMS_PER_TARGET` and `MAX_CLAIMS_TOTAL` per hour — with the actor threaded into
      `state.rs`, because the handler had authenticated it and then dropped it, leaving the
      rule expressible only where it could not be tested. 429 verified over a socket.
      **Bounds the rate, not the total**: several accounts still drain between them, and the
      counter is in memory so a restart clears it.
- [x] **MLS credentials name the account, not a display name.** Probing the old
      `name@server` credential found a working impersonation: mallory joins a room first
      presenting bob's label, every client displays her as bob, and MLS's duplicate-identity
      rule then locks the real bob out of that room permanently.

      The credential now carries the account and device ids. **Carrying them is not the
      protection — the checks are**, because an MLS credential is self-asserted and anyone
      can mint one naming anyone. Both ends compare it against an authenticated identity:
      the instance refuses a key package whose credential does not name the device
      publishing it, and a claiming client refuses one that does not name the account it
      asked for. The server-side half is what stops the guarantee resting on every client
      remembering to check.

      Unblocks auto-adding invite joiners, since a client can finally map the MLS roster
      onto the server's member list. **Breaking**: a client too old to name its account
      cannot publish key packages or be added to a room.
- [ ] Rate limiting on registration and sending. Both need the caller's address, which
      `state.rs` never sees — so unlike the claim limit, this one genuinely cannot live
      entirely where the other rules do, and that boundary needs designing rather than
      assuming.
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

## Direction change, 2026-08 (owner)

The priority moved from privacy depth to **product**: automatic embedding, integrations, and
good voice and video in a lightweight client. Three decisions, recorded so they are not
re-litigated:

- **[ADR-008](adr/008-client-architecture.md): one web client, wrapped in Tauri.** Supersedes
  the five-native-UI plan, which was the single largest cost in the project and the main
  thing standing between here and calls. WebRTC supplies capture, echo cancellation, jitter
  buffering and codec negotiation. The FFI line survives — protocol logic stays in Rust.
- **[ADR-009](adr/009-instance-side-unfurl.md): the instance unfurls links.** One adapter
  set, a shared cache, and thumbnails, at the cost of the instance seeing URLs its users
  send. **Recipients still fetch nothing** — that was always the important half.
- **Calls may downgrade** (`12-realtime-media.md` §5), carrying their own badge and
  announcing the fallback, rather than refusing to connect.

Both concessions are recorded in `01-threat-model.md` §3a. The tier model, franking, and the
honesty rule are unchanged.

**What this reorders.** Calls move from M6 to roughly M4; the native-client work that used to
gate them is gone. Attachments and the storage rewrite are already done, so instance-side
unfurl with thumbnails is close. Key transparency and metadata protection move further out —
they were always M5+, and this makes that explicit rather than implied.

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
