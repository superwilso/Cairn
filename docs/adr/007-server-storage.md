# ADR-007: redb for server storage

**Status:** Accepted (owner decision), unimplemented.

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

## Probes before this is trusted

Storage is not a security boundary, but it holds the material several boundaries depend on.
Per the project's method, write these and print what happens:

- Kill the process mid-write; confirm the last committed state survives and no partial
  record is readable.
- Confirm the franking key round-trips across a restart, and that a **missing** key is an
  error rather than a silent regeneration — a regenerated key looks like a working
  instance and invalidates every prior report.
- Import a `state.json` from the current format and confirm every account, room, membership
  and message survives with identical ids.
- Confirm cost per message is flat as the message count grows. That is the entire point of
  this change, and it is the one thing a passing functional test would not tell us.
