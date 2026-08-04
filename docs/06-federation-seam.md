# The Federation Seam

**Status:** Draft
**Decision record:** [ADR-003](adr/003-islands-first.md)

Cairn ships as self-hosted islands: anyone runs an instance, instances do not interoperate.
This document specifies the boundary that keeps federation an *addition* later rather than
a rewrite.

## Why islands first

MLS requires strictly ordered, append-only group commits. Within one instance the server
sequences them and the problem disappears. Across federating servers you need distributed
agreement on commit ordering for every encrypted room — which is exactly why Matrix's MLS
proposal (MSC4244) requires a designated **hub server per room**, reintroducing a central
point per room.

Doing federation and MLS together in v1 means solving the hardest open problem in the space
before shipping anything.

## The rule

**Every operation that would cross an instance boundary goes behind an explicit internal
interface, from the first commit, even though only one implementation exists.**

The seam is the deliverable. Federation is a later implementation behind it.

## Operations that cross the boundary

| Operation | Today | Federated later |
|---|---|---|
| Resolve an identity | Local lookup | Remote instance query |
| Room membership | Local | Cross-instance membership |
| Message delivery | Local fanout | Server-to-server relay |
| MLS commit ordering | Local sequencer | **The hard problem** |
| Media fetch | Local blob store | Remote fetch + cache |
| Policy list subscription | Local | **Federates first** |
| Presence | Local | Optional; a large metadata leak |

## Policy lists federate first

Subscribable ban lists ([`04-safety-architecture.md`](04-safety-architecture.md) §2) are
the right first federated capability:

- **Read-mostly** — published occasionally, read often
- **Plaintext** — no MLS ordering constraint
- **Eventually consistent** — staleness is tolerable
- **Immediately valuable** — instances become useful to each other long before user
  federation exists
- **Low risk** — a bad list is unsubscribed; nothing is corrupted

This exercises the seam under real conditions without touching the hard problem.

## Keeping the seam honest

A boundary that is never crossed rots. Countermeasures:

1. **Types, not conventions.** Cross-boundary operations return types that model remote
   failure — timeouts, partial results, unavailability — even when the local implementation
   cannot produce them. Code that assumes infallibility is code that will break on the
   first real network hop.
2. **Never assume synchronous local access** in code above the seam.
3. **No shared database access** across the boundary. The interface is the only contract.
4. **Review pressure.** New cross-boundary operations get explicit review, or the seam
   quietly stops existing.
5. **Consider a loopback implementation** in tests that adds latency and failures, so the
   seam is exercised adversarially before there is a second instance.

## What federation must not compromise

- **Tier immutability.** A federated room cannot have a different tier on different
  instances. If instances disagree about whether a room is encrypted, the guarantee is
  meaningless.
- **The threat model.** Federation adds adversaries: a malicious *remote* instance is not
  the same as a malicious local one. `01-threat-model.md` needs a revision, not a footnote,
  before federation ships.
- **Moderation authority.** Local operators must keep the ability to refuse remote content
  and remote users unconditionally.

## Revisit when

- A credible design exists for ordering MLS commits across servers without a per-room hub,
  **or** the hub model proves acceptable in practice
- Policy list federation has run long enough to validate the seam
- There is more than one instance operator who wants it

## Honest risk

If federation is deferred indefinitely, Cairn ends up as "Stoat with encryption". That is an
acceptable outcome, but it should be a decision someone makes, not a drift nobody notices.
