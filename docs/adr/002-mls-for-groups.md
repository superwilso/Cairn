# ADR-002: MLS (RFC 9420) for all group cryptography

**Status:** Accepted
**Date:** 2026-08-04

## Context

Encrypted tiers (T1, T2 per [ADR-001](001-tiered-encryption.md)) need group key agreement
that scales past a handful of participants. Two families exist in practice:

**Sender keys / pairwise fanout** (Signal's approach, and WhatsApp's). Each member
distributes a sending key to every other member over pairwise channels. Adding or removing
a member, or rotating after a compromise, costs O(n²) messages across the group. This is
fine at 10 members and painful at 200. Above roughly 1,000 it is not viable — which is why
products using it cap group sizes there.

**MLS (RFC 9420).** A ratchet tree gives O(log n) group operations, with forward secrecy
and post-compromise security as protocol properties rather than add-ons.

As of 2026, MLS is no longer an emerging bet:

- Google Messages and Apple Messages began rolling out MLS E2EE over RCS in May 2026.
- Discord uses MLS for E2EE voice and video group keying.
- Multiple mature independent implementations exist (`mls-rs`, OpenMLS, MLS++), with
  cross-implementation interoperability testing.

## Decision

**All group cryptography in encrypted tiers uses MLS, per RFC 9420.**

1. Use a **vetted third-party implementation** — `mls-rs` (AWS Labs, 100% RFC 9420
   conformance) or OpenMLS (Rust, MIT). Final selection happens in the protocol spike,
   [ADR-005](005-protocol-core.md).
2. **Do not implement MLS ourselves.** Not the ratchet tree, not the key schedule, not the
   AEAD wrapping. There is no version of this project where writing our own group ratchet
   is a good use of risk budget.
3. **Treat a 1-to-1 DM as a two-member MLS group.** One code path, not two. Avoids a
   separate pairwise protocol and its separate bugs.
4. **Pin a specific ciphersuite** in the protocol spec, and define the upgrade path before
   launch rather than after.

## Consequences

### Positive

- Groups of thousands are cryptographically feasible — the difference between a 200-person
  cap and a 5,000-person encrypted community actually working.
- Forward secrecy and post-compromise security come from the protocol. After a device
  compromise, the group *heals* once the affected member updates or is removed.
- A standards-track RFC with independent implementations is far easier to get externally
  reviewed than a bespoke design, and vastly easier for others to trust.
- Interoperability with the wider MLS ecosystem stays possible.

### Negative

- **MLS requires strictly ordered, append-only group commits.** Every member must apply
  commits in the same order. In a single-server deployment this is straightforward: the
  server sequences them. Across federating servers it is genuinely hard — it is precisely
  why Matrix's MLS proposal (MSC4244) requires a designated **hub server per room**. This
  constraint is a direct input to [ADR-003](003-islands-first.md).
- A practical gap exists between the RFC and a production deployment: delivery service
  semantics, state persistence, recovery from missed commits, and multi-device handling are
  all left to the application. Budget real engineering time for this; the RFC is the
  starting line.
- MLS state is heavier on the client than sender keys. Mobile storage and battery under
  commit churn must be measured, not assumed — it is criterion #2 in the spike.
- `mls-rs` is conformance-validated but, per its own README, has not had a full third-party
  security audit. Track this and budget for review.

## Alternatives rejected

**Signal-style sender keys.** Rejected: O(n²) group operations cap practical encrypted
community size at roughly the point where the product becomes interesting.

**Megolm** (Matrix's scheme). Rejected: it works, but it is being migrated away from by
its own ecosystem. Adopting it in 2026 means adopting a migration.

**Roll our own.** Rejected without qualification.

## References

- RFC 9420 — The Messaging Layer Security (MLS) Protocol
- `mls-rs` (AWS Labs), OpenMLS
- [ADR-003](003-islands-first.md) — federation, constrained by MLS ordering
