# ADR-003: Self-hosted islands first, federation as a designed seam

**Status:** Accepted
**Date:** 2026-08-04

## Context

"Self-hostable" and "federated" are routinely conflated. They are different properties:

- **Self-hostable** — anyone can run their own instance. (Discord: no. Stoat: yes.)
- **Federated** — instances interoperate; a user on instance A participates in a community
  on instance B. (Matrix: yes. Stoat: no.)

Cairn requires the first. The second is desirable but expensive, and its cost is not
evenly distributed: federating an *encrypted* platform is substantially harder than
federating a plaintext one.

The reason is [ADR-002](002-mls-for-groups.md). MLS requires strictly ordered, append-only
group commits. In a single-server deployment the server sequences them and the problem is
trivial. Across federating servers, you need distributed consensus on commit ordering for
every encrypted room. This is not a hypothetical difficulty — it is exactly why Matrix's
MLS proposal (MSC4244) requires a designated **hub server per room**, which reintroduces a
central point per room and complicates the very decentralization federation exists to
provide.

Attempting both federation and MLS in v1 means solving the hardest open problem in the
space before shipping anything.

## Decision

**Ship self-hosted islands first. Design the server-to-server boundary from day one, but do
not implement federation in v1.**

1. Anyone can run an instance. Instances do **not** interoperate initially.
2. All logic that would cross an instance boundary — identity resolution, room membership,
   media fetch, key distribution, policy list subscription — goes behind an **explicit
   internal API** from the first commit, even though there is only one implementation of it.
   The seam is the deliverable; federation is a later implementation behind it.
3. **Policy lists federate before anything else.** Subscribable ban lists
   (see [`04-safety-architecture.md`](../04-safety-architecture.md)) are read-mostly,
   plaintext, and eventually consistent — none of the MLS ordering problem applies. They
   are the highest-value, lowest-risk thing to share across instances, and they make
   instances useful to each other long before user federation exists.
4. **State the intent publicly.** The README says islands now, federation planned. Nobody
   should adopt Cairn believing it federates today.

## Consequences

### Positive

- v1 becomes achievable. The hardest distributed-systems problem in the category is
  deferred rather than blocking launch.
- Encrypted rooms get a natural sequencer — the instance server — with no consensus
  protocol required.
- Moderation is simpler: an instance operator has clear authority over their instance, and
  the liability question has a clear answer.
- The seam means federation is an addition later, not a rewrite. That distinction is worth
  the up-front discipline.

### Negative

- **Network effects fragment.** Users on different instances cannot talk. This is the main
  cost, and it is real — it is the thing Matrix genuinely does better.
- We will be criticized by the fediverse community for shipping "yet another silo." Partly
  fair. The honest answer is sequencing, not principle, and this document is the evidence.
- Discipline is required to keep the seam clean with only one implementation behind it.
  Boundaries that are never exercised tend to rot; the internal API needs review pressure
  from the start.
- If federation is deferred indefinitely, we end up as Stoat with encryption. Acceptable,
  but it should be a decision rather than a drift.

## Alternatives rejected

**Full federation from day one.** Rejected: MLS commit ordering across servers is an open
design problem. Solving it before shipping anything risks shipping nothing.

**Federate, but only unencrypted (T3) rooms.** Genuinely tempting — T3 has no MLS ordering
constraint, so it is technically the easy subset. Rejected for v1 because it inverts the
message: the *public* rooms federate and the *private* ones do not, which teaches users
exactly the wrong intuition about what the platform protects. Reconsider once T1/T2
federation has a credible design.

**Matrix for federation, custom for encryption.** Rejected: two protocols, two security
models, two sets of bugs.

## Revisit when

- A credible design exists for ordering MLS commits across servers without a per-room hub,
  **or** the hub model proves acceptable in practice.
- Policy list federation (item 3) has been running long enough to validate the seam.

## References

- [ADR-002](002-mls-for-groups.md) — MLS ordering constraint, the root cause of this decision
- [`06-federation-seam.md`](../06-federation-seam.md) — the boundary in detail
- Matrix MSC4244 — RFC 9420 MLS for Matrix, and its per-room hub server requirement
