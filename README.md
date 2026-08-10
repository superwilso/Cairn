# Cairn

**Open-source, self-hostable messaging with Discord's features and Signal's cryptography.**

> ⚠️ **Pre-alpha. Not usable, not audited, not secure yet.** This repository currently holds
> a design foundation and a working protocol core. Do not use it to protect anyone. See
> [SECURITY.md](SECURITY.md).

A cairn is a stack of stones placed by many hands to mark a trail for those who follow.

---

## The idea

Every existing option makes you give something up. Discord has the best community product
and reads everything you write. Signal has the best cryptography and is not trying to be a
community platform. Matrix is genuinely decentralized but not competitive as a Discord
replacement. Telegram's default chats are not end-to-end encrypted at all.

Cairn's bet is that these have not been combined because everyone treats encryption as
all-or-nothing. A 50,000-member public server with an open invite link is **already
public** — encrypting it buys no real confidentiality while destroying search, moderation,
and mobile sync.

So Cairn tiers it:

| Tier | Surface | Protection |
|---|---|---|
| **T1** | DMs, group chats | End-to-end encrypted (MLS) |
| **T2** | Private communities | End-to-end encrypted (MLS) |
| **T3** | Large / public communities | Transport encryption; server-side search and moderation |

The tier is visible at all times and **immutable after the room is created**. That one
decision ([ADR-001](docs/adr/001-tiered-encryption.md)) dissolves most of the
privacy-versus-safety tension: the surfaces where abuse scales are exactly the ones that
can be moderated conventionally.

## What's actually built

A working protocol core, with the security-critical paths under test:

- **MLS group sessions** (RFC 9420, via `mls-rs`) — a DM is a two-member group, so there is
  one code path rather than two. Post-compromise security after member removal is verified
  by test, not assumed.
- **Transcript franking** — a recipient can prove "this account sent me exactly this
  message" without the server ever seeing plaintext. Reports cover a **hash-chained run of
  messages**, so a moderator can verify ordering and causality — and a reporter cannot
  quietly drop the message that supplies the context.
- **Safety numbers** — 60-digit out-of-band key verification, so a malicious server
  substituting keys becomes visible to the user. Verified against real MLS identity keys.
  Not yet surfaced in any UI, so the protection is not yet effective in practice.
- **Authenticated envelopes** — every message is signed by its sending device over
  length-prefixed canonical bytes, and a device's account binding is fixed at registration.
  This is what makes franking's attribution real rather than a claim the server takes on
  faith.
- **Tier enforcement** — structurally enforced. There is no setter for a room's tier, and
  the server re-validates every message against its room's tier because
  [modified clients exist](docs/01-threat-model.md).
- **An instance server** — pure Rust, so the same source runs on Linux, Windows, and macOS.

```
crates/
  cairn-proto/        wire types, IDs, tier model          (Apache-2.0)
  cairn-crypto/       MLS sessions, franking               (Apache-2.0)
  cairn-client-core/  conversation logic, tier enforcement (Apache-2.0)
  cairn-server/       instance server                      (AGPL-3.0)
  cairn-cli/          headless demo client                 (AGPL-3.0)
```

There is a minimal line-based client, not a graphical one. The protocol comes first, and
the core is fully testable without a UI.

## Try it

```bash
cargo test --workspace     # 176 tests
cargo run -p cairn-cli     # the vertical slice, in-process, end to end
```

The demo establishes an MLS group, sends franked encrypted messages, has the "server"
sequence and tag them without seeing plaintext, builds a transcript report, verifies it,
and then demonstrates that editing a message, dropping context, or reattributing a message
to another account are all detected.

### Two people, over a real server

```bash
CAIRN_REGISTRATION_POLICY=open cargo run -p cairn-server    # 127.0.0.1:8080

# Bob, in one terminal — publish key packages, then note his user id
cargo run -p cairn-cli -- chat --name bob
  /keys 5
  /whoami

# Alice, in another — create a room and add him
cargo run -p cairn-cli -- chat --name alice
  /new
  /add usr_...
  hello

# Bob opens the room id Alice was shown, compares safety numbers, and verifies
  /open rom_...
  /safety
  /verify 0
```

The prompt carries the tier badge at all times, and says `plaintext-transport` over
`http://` — MLS protects the message body there and nothing protects anything else.
Members added to a room are announced in the timeline with their verification state, and
`/safety` shows numbers derived from the MLS group's own roster, which is the only source
that makes the comparison mean anything (`docs/01-threat-model.md` §4).

**Not yet an invite flow:** the room id and user id still have to be passed between people
by hand. See M3 in [the roadmap](docs/10-roadmap.md).

## Documentation

Start with the [threat model](docs/01-threat-model.md) — everything else is downstream of
it, and its **non-goals** matter more than its goals.

| Doc | What it covers |
|---|---|
| [00 — Vision](docs/00-vision.md) | Thesis, differentiation, non-negotiables |
| [01 — Threat model](docs/01-threat-model.md) | Adversaries, and what Cairn does **not** defend against |
| [02 — Encryption tiers](docs/02-encryption-tiers.md) | Tier rules, immutability, UI requirements |
| [03 — Protocol evaluation](docs/03-protocol-evaluation.md) | What was decided, what is still owed |
| [04 — Safety architecture](docs/04-safety-architecture.md) | Franking, policy lists, on-device ML, hash matching |
| [05 — Embeds](docs/05-embeds.md) | Authenticated on-device unfurl |
| [06 — Federation seam](docs/06-federation-seam.md) | Islands now, federation later |
| [07 — Regulatory posture](docs/07-regulatory-posture.md) | DSA, OSA, age assurance, export control |
| [08 — Feature parity](docs/08-feature-parity.md) | Scorecard vs Discord, Signal, WhatsApp, Instagram, Telegram |
| [09 — Platform strategy](docs/09-platform-strategy.md) | Native on five platforms; servers on three |
| [Naming](docs/NAMING.md) | Why "Cairn", and the clearance still required |
| [ADRs](docs/adr/) | The decisions, with their consequences |

## Platforms

Native everywhere — one shared Rust core, a thin native UI per platform, and **no protocol
logic above the FFI line** ([ADR-006](docs/adr/006-platform-architecture.md)).

**Clients:** Windows (first), Linux, Android, macOS, iOS.
**Servers:** Linux (primary), Windows, macOS.

## What Cairn is not

- **Not yet safe against a *malicious* server.** Safety numbers exist but no client shows
  them, and key transparency is unimplemented. ([SECURITY.md](SECURITY.md))
- **Not metadata-private.** The server sees who talks to whom and when. Signal beats us
  here, and will until it is designed for. ([Threat model §3.1](docs/01-threat-model.md))
- **Not federated at launch.** Self-hosted islands, with a designed seam.
  ([ADR-003](docs/adr/003-islands-first.md))
- **Not safe against a targeted state-level attacker.**
- **Not a Discord API clone.** Spacebar occupies that niche.
- **Not a blockchain project.** In any form.

## Non-negotiables

1. Never weaken an encryption tier after launch. No silent downgrades, ever.
2. Never ship client-side scanning as an enforcement mechanism.
3. Never claim a protection the threat model does not support.
4. No ads, no monetization derived from message content.
5. The flagship instance gets no protocol privileges a self-hosted one cannot have.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Design feedback on the threat model and the
protocol is more valuable right now than code.

## Licence

Split by component, deliberately — see [ADR-004](docs/adr/004-licensing.md).
Server and applications: **AGPL-3.0-or-later**. Protocol libraries and clients:
**Apache-2.0**. Documentation: **CC-BY-SA-4.0**.

> **Licence files are not yet committed.** They must be copied verbatim from an
> authoritative source; the environment used to draft this could not reach `gnu.org` or
> `apache.org`. See [ADR-004](docs/adr/004-licensing.md) action items.
