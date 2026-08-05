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
4. **Cross-platform build fixes.** Only Linux has been verified locally.
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

```bash
cargo test --workspace     # must pass
cargo fmt --all            # must be clean
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p cairn-cli     # the vertical slice
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
