# Security Policy

## Current status: pre-alpha. Do not use this to protect anyone.

Cairn is a scaffold with a threat model and a working protocol core. It has **not** been
audited, it has known gaps, and several security-critical pieces are unimplemented. If you
need a secure messenger today, use Signal.

Specifically, and non-exhaustively:

- **No key transparency, and safety numbers are not yet surfaced in any UI.**
  Safety-number verification is implemented and tested in `cairn-crypto::verification`,
  but nothing displays it to a user yet, and there is no contact store persisting
  verification state. Until a client shows the number and a user compares it out of band,
  the end-to-end encryption still holds only against an honest-but-curious server, **not
  a malicious one**. Key transparency — which makes server equivocation detectable without
  manual comparison — remains unimplemented. See `docs/01-threat-model.md` §4.
- **No authentication.** The server accepts anything from anyone.
- **No persistence.** The franking key is regenerated on every restart, invalidating all
  historical reports.
- **No group franking.** The franking implementation is sound for 1-to-1 only.
- **No transport security of its own.** Must sit behind a TLS-terminating proxy.

A full list is in `docs/03-protocol-evaluation.md`.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Use GitHub's private vulnerability reporting on this repository
(Security → Report a vulnerability). A dedicated security contact address will be published
before the first release.

Please include: what the issue is, how to reproduce it, what an attacker gains, and any
suggested fix. If you would like credit, say so and how you want to be named.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 72 hours |
| Initial assessment | 7 days |
| Fix or mitigation plan | 30 days for high severity |
| Public disclosure | Coordinated; 90 days default |

These are targets for a pre-alpha project run by volunteers, not a contractual SLA. We
would rather state modest numbers and meet them.

## Scope

**In scope:** the protocol design, the cryptography, the crates in `crates/`, tier
enforcement bypasses, franking forgery or framing, and anything that lets a server read
T1/T2 content.

**Out of scope right now:** the absence of features already documented as missing above and
in `docs/03-protocol-evaluation.md`. We know. Reports that Cairn lacks authentication are
not findings at this stage.

**Always in scope, regardless of status:** any way to make the product *claim* a protection
it does not provide. A UI that says a room is encrypted when it is not is a security bug of
the most serious kind, because users calibrate their behaviour to that claim.

## Design commitments

These are structural, not aspirational:

1. **No backdoors, no key escrow, no exceptional access** — for anyone, including us. See
   `docs/07-regulatory-posture.md`.
2. **No mandatory client-side scanning.** See `docs/04-safety-architecture.md` §3.
3. **Tier immutability.** A room's encryption tier never changes after creation.
4. **No claimed protection beyond the threat model.** Marketing copy is reviewed against
   `docs/01-threat-model.md`.

## Before v1

An **external cryptographic review** by someone unconnected to the project is required
before any release described as usable. It is the cheapest security spend available and it
is not optional.
