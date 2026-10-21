# Contributing to Cairn

Cairn is pre-alpha. Right now, **design feedback is worth more than code** — especially on
[the threat model](docs/01-threat-model.md), which everything else depends on.

## Most useful contributions

1. **Attack the threat model.** Find an adversary we have not listed, or a claim we cannot
   support. Being wrong about our own guarantees is the worst failure mode available to a
   security product.
2. **Review the franking design** (`crates/cairn-crypto/src/franking.rs`). It is the
   centrepiece and it is unaudited.
3. **Review the tier model.** If you can construct a way to make a room's tier change after
   creation, or make the UI claim a protection that is not there, that is a serious bug.
4. **Cross-platform build fixes.** CI builds and tests on Linux, Windows and macOS, but
   only Linux is used day to day; a rough edge on the others is worth a report.
5. Then code.

## Ground rules

### Never claim a protection we do not have

The single most important rule. If a change makes a security claim, it must be supported by
[`docs/01-threat-model.md`](docs/01-threat-model.md) — or that document changes in the same
PR, with reasoning.

### Security-critical code lives below the FFI line

Protocol, cryptography, storage, and tier enforcement belong in `cairn-proto`,
`cairn-crypto`, or `cairn-client-core`. A platform UI must never construct an envelope,
decide a tier, or touch a key. `cairn-client-core` must never gain a UI dependency
([ADR-006](docs/adr/006-platform-architecture.md)).

### Do not hand-roll cryptography

MLS comes from `mls-rs`. If you think Cairn needs a new cryptographic primitive, open an
issue first — that is a design discussion, not a pull request.

### Decisions get ADRs

Anything architectural gets a record in [`docs/adr/`](docs/adr/), including the
consequences and the alternatives rejected. Documenting why we did *not* do something is
usually more valuable later than documenting what we did.

### Every crate is `#![forbid(unsafe_code)]`

If you need `unsafe`, that is a design discussion. FFI bindings will eventually be the
exception, and they will get proportionate review.

## Practicalities

### Building

| | Needed for |
|---|---|
| Rust **1.88+** ([rustup](https://rustup.rs)) | everything — 1.88 is a hard floor, checked in CI |
| A C compiler | everything — `ring` compiles C. `build-essential` (Debian/Ubuntu), Xcode Command Line Tools (macOS), MSVC Build Tools (Windows) |
| Webview development packages, **Linux only** | `cairn-desktop` |
| Node 18+ | the desktop client's JavaScript tests |
| Python 3 | `scripts/ci-local.sh`'s bundle-icon check |

On Debian or Ubuntu, the webview packages are the ones CI installs:

```bash
sudo apt-get install -y libwebkit2gtk-4.1-dev libxdo-dev \
  libayatana-appindicator3-dev librsvg2-dev
```

Other distributions: the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)
list the equivalents. Without them, everything except the desktop app still builds and
tests — add `--exclude cairn-desktop` to workspace commands. Windows ships WebView2 and
macOS ships WebKit, so neither needs anything.

### Before you push

```bash
scripts/ci-local.sh          # what CI runs: fmt, clippy, tests, the slice, JS tests, MSRV, audit
scripts/ci-local.sh quick    # fmt + clippy + tests, for a tight loop
```

The script is a copy of `.github/workflows/ci.yml`, including the `RUSTFLAGS=-D warnings`
CI sets globally — so a plain `cargo test` passing is a weaker signal than it looks. The
MSRV step needs `rustup toolchain install 1.88.0`, the audit step `cargo install
cargo-audit --locked`, and the JavaScript steps node; without them the script skips the step
and says so in yellow, which is not the same as passing.
By hand, the core of it is:

```bash
cargo fmt --all
RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets
RUSTFLAGS="-D warnings" cargo test --workspace --all-targets
cargo run -p cairn-cli       # the vertical slice
```

**Run it as an ordinary user, not root.** CI does, and root hides permission bugs: one
chmod that only root could make passed locally and failed thirteen tests on the runner.

### The desktop client's JavaScript

`cargo test` cannot see the web UI in `clients/desktop/ui/`, where the call mesh lives. The
stubbed tests need only node; the browser tests drive two real Chromium pages through
Playwright, and skip themselves if it is missing:

```bash
node --test clients/desktop/tests/mesh.test.js
node --test clients/desktop/tests/mediaframe.test.js

npm install --no-save playwright && npx playwright install --with-deps chromium
node --test clients/desktop/tests/call.browser.test.js     # and the other *.browser.test.js
```

### Tests

Test the security property, not the implementation detail. Name tests after the property
they defend — `omitting_a_middle_message_breaks_the_chain` is more useful in six months
than `test_report_verify_2`. A test that documents *why* a rule exists is worth writing
even when the rule looks obvious.

### Commits and PRs

Explain **why**, not what — the diff already says what. Keep PRs focused; a PR that changes
a security property should not also reformat a module.

### Developer Certificate of Origin

Contributions are accepted under the [DCO](https://developercertificate.org/). Sign off
your commits:

```bash
git commit -s -m "your message"
```

We use a DCO rather than a CLA deliberately: a CLA assigning rights to a single entity
reads as a rug-pull risk to exactly the community this project depends on.

## Licensing

Contributions are licensed per component ([ADR-004](docs/adr/004-licensing.md)): AGPL-3.0
for server and applications, Apache-2.0 for protocol libraries and clients, CC-BY-SA-4.0
for documentation. By contributing you agree to license under the terms for that component.

## Reporting security issues

**Do not open a public issue.** See [SECURITY.md](SECURITY.md).

## Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Building a platform with serious safety
tooling while running a community that tolerates abuse would be an obvious contradiction.
