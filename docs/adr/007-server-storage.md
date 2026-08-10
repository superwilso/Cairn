# ADR-007: redb for server storage

**Status:** Accepted (owner decision), **implemented**. Probe results in the final section.

## Context

`cairn-server` persists a single JSON snapshot and **rewrites all of it on every message**.
That is O(messages) per write and therefore quadratic over a conversation's life. It also
has no write-ahead log, so a crash between saves loses everything since the last one —
though never a partial file, since `write_atomic` renames into place.

This was a deliberate scaffold choice and it is now the binding constraint on several
things at once:

- **Attachments** (`10-roadmap.md`, M6) put file bytes in envelopes. On snapshot storage
  that turns a slow quadratic into a fast one.
- **Link previews carry no images** for exactly this reason (`05-embeds.md`).
- **Instagram media re-hosting** — the feature that prompted this — is blocked behind
  attachments, which are blocked behind this.
- Even a friends test degrades: cost grows with every message sent
  (`11-self-hosting.md`, "What is not ready").

The `Storage` trait already exists as the seam, so `state::Instance` does not have to
change shape.

## Decision

**Use `redb`.**

Pure Rust, embedded, ACID, no separate daemon, no C in the build. It replaces code the
alternative would have us hand-roll — durability, compaction, crash recovery — in a place
where getting it subtly wrong loses the franking key or the room table.

### Rejected: SQLite via `rusqlite`

More battle-tested than anything else available, and far easier to inspect or repair by
hand, which is a real operational advantage for self-hosters. Rejected because it pulls C
into the build of a project whose every crate is `#![forbid(unsafe_code)]`. That forbiddance
is about our code, not our dependencies, so this is a matter of posture rather than a
guarantee — but the posture is the point, and reproducible builds (M4) get harder with a
C toolchain in the graph.

### Rejected: hand-rolled append-only log

Zero new dependencies and fully auditable, which fits the existing "deliberately boring"
note in `storage.rs`. Rejected because durability, compaction, and crash recovery are
precisely the things that look finished and are not, and this is the component holding the
franking key — whose loss silently invalidates **every report the instance ever issued**.
A subtle bug here does not announce itself.

### Pinned to redb 2.x, not 4.x

Found while adding the dependency, not in review: **redb 4.1 requires rustc 1.89**, and the
MSRV floor is 1.85. `cargo add` quietly resolves to 2.6.3 rather than failing, so without
checking, this would have surfaced later as an MSRV job failure in CI on someone else's
change.

Staying on 2.x is the right call for now — the floor exists because the crypto tree needs
`edition2024`, and raising it to chase a storage dependency inverts that priority. It does
mean a future decision: redb 2.x will not get new features indefinitely, so either the MSRV
rises or the pin becomes a liability. Revisit when something needs 4.x, not before.

## Consequences

- One substantial dependency added to a supply chain kept deliberately small. It goes
  through `cargo audit` in CI like everything else.
- **A migration path is required**, not optional: existing instances hold real state, and
  `11-self-hosting.md` currently tells operators to back up `franking.key` and `state.json`.
  A one-shot import from the JSON snapshot, run on first start, with the old file left in
  place.
- The franking key should stay a **separate file**, not a row. It is the one piece of state
  whose loss is unrecoverable, and keeping it outside the database keeps the backup
  instruction simple and the blast radius of a corrupt database smaller.
- `storage.rs` and `state.rs` are both CODEOWNERS paths. This lands as a reviewed PR.

## Probes, and what they showed

Storage is not a security boundary, but it holds the material several boundaries depend on.
All four ran; the results are below.

**Kill the process mid-write.** `a_committed_write_survives_a_killed_process` re-executes
the test binary and has the child `abort()` — no unwinding, no destructors, no clean
shutdown. The first attempt used `std::mem::forget` instead and *proved nothing*: redb's
exclusive file lock is process-wide, so the "crashed" store still held it and the reopen
failed with `DatabaseAlreadyOpen` rather than testing durability at all. A passing version
of that test would have been pure false confidence.

Also verified over HTTP, per the project's rule about not trusting unit tests alone: two
messages sent, `kill -9` on the server, restart, and the recipient's **first ever** poll
returned both — decrypted, which additionally proves the envelopes round-tripped byte-exact.

**The franking key.** Round-trips across restart (`franking_key_survives_a_restart`), and a
new rule this ADR asked for now exists: a *missing* key beside a populated database is a
hard error rather than a silent regeneration. Restoring a data volume without
`franking.key` is a realistic operator mistake, and the old behaviour produced an instance
that looked healthy while every historical report had quietly stopped verifying. Guarded
both ways — `a_brand_new_instance_still_mints_its_first_key` is the counterfactual, since a
rule of "missing key is always fatal" would mean no instance could ever start.

**Import a `state.json`.** Covered by unit tests for exact id round-tripping, and then done
for real: an instance was created with the *previous build*, populated over HTTP, shut down,
and the new binary started on the same directory. It imported four messages out of the
inline room log, and the recipient read messages written by the old server. The old file is
left in place so a rollback still finds its data.

**Cost per message.** The one a passing functional test would not tell us, so it is asserted
rather than eyeballed: `a_message_costs_the_same_to_store_however_long_the_backlog` wraps the
store and records bytes written per commit. Message 1 costs **640 bytes**, message 200 costs
**646** — the drift is the message number in the body. Under the old design message 200 cost
200 times message 1.

A wall-clock assertion was deliberately avoided: it would be noise on a shared CI runner.
Measured separately, a redb commit is about **750µs**. Worth recording, because the 500-message
version of this test took 14 seconds and the obvious conclusion — that storage is slow — was
wrong. In release it takes 0.32s; the cost was debug-mode Ed25519, not the database.

Note also that the *old* code never called `fsync` at all, so its speed was partly an
illusion: a crash could lose acknowledged writes. This is slower per commit and actually
durable.
