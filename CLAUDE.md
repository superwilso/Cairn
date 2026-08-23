# Working on Cairn

Read this before doing anything. A session starting cold has no memory of how this project
got here, and some of what it needs to know was learned the hard way.

## What this is

An open-source, self-hostable messaging platform: Discord's community features with
Signal-grade encryption on the surfaces that are actually private. Pre-alpha, not audited,
not deployable.

**Start with `docs/01-threat-model.md`.** Every other document is downstream of it, and its
*non-goals* matter more than its goals. **Take work from `docs/10-roadmap.md`**, topmost
unchecked item in the earliest incomplete milestone.

## The lesson this project actually learned

Three vulnerability classes shipped to `main` in code that was **merged, CI-green,
cross-platform verified, and covered by tests that looked adequate**:

1. **Account impersonation** — a device could be registered against any user id, so anyone
   who saw an id (they are on every message) could speak as that account.
2. **Room access** — no membership concept at all. Any account could read and write any
   room by id, including private E2EE ones.
3. **No removal path** — a room could never eject anyone, and any member could admit
   anyone.

**None were found by reading the code.** Each came from writing a test that tried the
attack and printing what happened. Reviews of my own security code, in this project, have a
3-for-3 failure rate.

So: **probe before you trust anything, including your own previous work.** Before extending
a security-relevant path, write a throwaway test that attacks it and print the result. If
the attack fails, delete the probe. If it succeeds, you have found something and the probe
becomes a regression test named after the property.

## Non-negotiables

These outrank velocity, tidiness, and the roadmap:

1. **A room's tier is immutable.** There is no setter for it anywhere, and there must never
   be one. **Narrowed (owner, pre-launch):** this constrains the *room*. A **call** inside an
   E2EE room may fall back to transport-only if a participant cannot do E2EE media — it must
   then carry its own badge saying so, and announce the fallback to everyone in the call.
   See [`docs/12-realtime-media.md`](docs/12-realtime-media.md) §5. Messages are unaffected.
2. **Never ship client-side scanning as an enforcement mechanism.** As a user-controlled
   filter, yes. As a mandate, never.
3. **Never claim a protection the threat model does not support.** This is the one that
   matters most. A doc or comment asserting a property that does not hold is worse than
   silence — `DeviceRecord`'s comment once claimed impersonation was impossible while it
   was trivially possible.
4. No ads, no monetization derived from message content.
5. The flagship instance gets no protocol privileges a self-hosted one cannot have.

## Layout

```
crates/cairn-proto/        wire types, IDs, tier model, canonical signing bytes
crates/cairn-crypto/       MLS sessions, franking, safety numbers
crates/cairn-client-core/  conversation logic — never gains a UI dependency
crates/cairn-server/       instance server: state.rs holds the rules, http.rs translates
crates/cairn-cli/          headless demo
```

**All protocol, crypto, storage, and tier logic lives below the FFI line** — in `proto`,
`crypto`, or `client-core`. A UI must never construct an envelope, decide a tier, or touch a
key. This rule outlived the plan that motivated it: [ADR-008](docs/adr/008-client-architecture.md)
replaced five native clients with one web client wrapped in Tauri, and the line still holds —
a browser UI is exactly where protocol logic must not drift to.

Rules live in `state.rs`; `http.rs` only maps them onto status codes. Put a rule in the
handler and it is untested and bypassable.

## Verification

**Run `scripts/ci-local.sh` before pushing.** It is a faithful copy of
`.github/workflows/ci.yml` and catches what ad-hoc local runs missed: CI sets
`RUSTFLAGS=-D warnings` globally, tests with `--all-targets`, runs the vertical slice, and
checks the MSRV floor and `cargo audit`. Running `cargo test` alone is a weaker check than
CI, which is how a green local tree can still fail.

This matters more than tidiness. GitHub bills a private repo's macOS minutes at **10x** and
Windows at 2x, so a full matrix run costs ~49 billed minutes against a 2000/month allowance —
about 40 runs. It has already run out once. A failure caught locally costs nothing.

```bash
scripts/ci-local.sh                                 # everything CI runs, locally
scripts/ci-local.sh quick                           # fmt + clippy + tests, tight loop

cargo test --workspace                              # must pass
cargo fmt --all
cargo clippy --workspace --all-targets              # CI runs -D warnings
cargo run -p cairn-cli                              # vertical slice
cargo run -p cairn-desktop                          # desktop client (needs libwebkit2gtk-4.1-dev)
cargo run -p cairn-crypto --example group_scaling --release
```

CI additionally builds and tests on Windows and macOS, checks MSRV (**1.85** — a hard floor,
the crypto tree needs `edition2024`), and runs `cargo audit`.

**Verify over HTTP, not only in unit tests.** Both room bugs looked fine in unit tests
written against the same wrong mental model. Start the server and make the actual request.

## Conventions

- **Name tests after the property they defend.** `an_attacker_cannot_send_as_someone_else`
  beats `test_auth_2`, and in six months it is the only thing that says why the rule exists.
- **Comments explain why, not what.** Most existing comments record a decision or a hazard.
- **Length-prefix everything that gets signed.** Two different field splits must never
  produce the same bytes.
- **Secrets never appear in `Debug`** — print `<redacted>`, derive `Zeroize`.
- **Constant-time comparison** for anything secret-dependent, via `subtle`.
- **Update stale docs in the same commit** as the change that staled them.
- Every crate is `#![forbid(unsafe_code)]`.

## Git

Work on `claude/messaging-app-planning-hgwlue`. If its PR is already merged, restart the
branch from `main` — never stack new work on merged history.

Commit messages explain *why*; the diff already says what. Where a change fixes something
found by probing, say what the probe showed.

## Merge policy

- **Docs, tests, benchmarks, refactors, dependency bumps** — auto-merge once CI is green.
- **Anything touching `cairn-crypto`, authentication, membership, or the threat model** —
  open the PR and leave it for the owner. `.github/CODEOWNERS` marks those paths. Given the
  3-for-3 record above, self-merging security changes would remove the only check that has
  ever caught anything.

## Owner's items — do not attempt these

- **Name clearance** (USPTO/EUIPO, domains). The owner may rename later; do not block on it.
- **Licence files.** Must be verbatim from an authoritative source. Do not reproduce a
  legal document from memory.
- **External cryptographic review.** Scheduled for M5.
