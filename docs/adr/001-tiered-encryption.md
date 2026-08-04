# ADR-001: Tiered encryption, not blanket E2EE

**Status:** Accepted
**Date:** 2026-08-04
**Supersedes:** none

## Context

The initial instinct for a privacy-first platform is to encrypt everything end-to-end.
Applied to a Discord-shaped product, this collides with reality in four places:

1. **It buys nothing on public surfaces.** A 50,000-member community with an open invite
   link is already readable by anyone who clicks it, including any adversary who wants in.
   Encrypting the transport to that room protects against an observer who could not have
   simply joined. That adversary is nearly empty.
2. **It destroys search.** Server-side search over years of community history is a core
   feature. Client-side search over E2EE history requires every client to hold every
   message, which is untenable on mobile at community scale.
3. **It destroys moderation.** Server-side spam filtering, hash matching, and admin
   review are impossible over ciphertext. The surfaces where abuse *scales* are exactly
   the large public ones.
4. **It destroys mobile sync.** A phone joining a 50,000-member encrypted room must process
   the group's key material and backfill. Cost grows with membership churn, which at that
   size is continuous.

Meanwhile, the surfaces users actually consider private — DMs, small group chats, private
communities — have none of these problems. They are small, low-churn, and search is
tractable client-side.

## Decision

Encryption is **tiered by surface**, matched to the surface's actual privacy.

| Tier | Surface | Protection | Server can read | Moderation & search |
|---|---|---|---|---|
| **T1** | DMs, group chats | E2EE via MLS | ❌ | Client-side; franking for reports |
| **T2** | Private communities | E2EE via MLS | ❌ | Client-side; franking; admin tooling |
| **T3** | Large / public communities | TLS + encryption at rest | ✅ | Full server-side |

Binding rules, all of which are part of the decision and not implementation detail:

1. **The tier is displayed in the UI at all times**, on the room, in the composer, and in
   the member list. Not in a settings submenu.
2. **The tier is immutable after room creation.** A room cannot be downgraded from T1/T2
   to T3, by anyone, including the instance operator. Downgrade requires creating a new
   room with a new, visible identity.
3. **The tier assignment rule is public and deterministic** — documented in
   [`02-encryption-tiers.md`](../02-encryption-tiers.md), not chosen ad hoc per room.
4. **Upgrade is also forbidden.** Converting T3 → T2 would imply retroactive protection of
   history the server already holds in plaintext. Misleading; disallowed.

## Consequences

### Positive

- The privacy-versus-safety tension largely dissolves. The surfaces where abuse scales are
  the ones that can be moderated conventionally; the surfaces users treat as private get
  real cryptographic protection.
- Public communities get server-side search, spam filtering, and hash matching — features
  a blanket-E2EE competitor structurally cannot offer.
- Mobile performance at community scale becomes achievable.
- The security claim is *narrow enough to be true*, which makes it defensible under
  scrutiny.

### Negative

- **We will be criticized for not encrypting everything**, including by people who have not
  read the reasoning. Accepted. The alternative is a claim we could not honor. This
  document exists to be linked in that argument.
- Users must understand a distinction, which is a UX burden. Mitigated by making the tier
  unmissable rather than by hiding it.
- Public community content is exposed to a malicious instance operator. Stated plainly in
  [`01-threat-model.md`](../01-threat-model.md) §3.2.
- The immutability rule means a community that outgrows T2 cannot convert in place. This is
  a real product limitation and it is deliberate — the alternative is a silent downgrade,
  which is strictly worse than never having encrypted at all, because users calibrate their
  behavior to the badge.

## Alternatives rejected

**Encrypt everything.** Rejected: costs search, moderation, and mobile viability across the
entire community product, in exchange for protection against an adversary who could have
joined the room by clicking a link.

**Encrypt nothing** (the Stoat/Discord position). Rejected: this is the entire reason the
project exists.

**Let admins choose per room, freely.** Rejected: makes the guarantee unpredictable to
users, and admin-controlled downgrade is a wiretap with extra steps.

**Encrypt everything, with a server-side "moderation key."** Rejected: this is key escrow.
It would be the single most damaging thing we could do to the project's credibility, and
it is a permanent target for legal compulsion.

## References

- [`02-encryption-tiers.md`](../02-encryption-tiers.md) — full tier rules and UI treatment
- [`01-threat-model.md`](../01-threat-model.md) — adversaries per tier
- [ADR-002](002-mls-for-groups.md) — the group crypto used by T1 and T2
