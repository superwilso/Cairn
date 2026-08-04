# Vision

**Status:** Draft — open for comment

## The thesis

Every existing option makes you give something up.

- **Discord** has the best product in the category and the deepest community features.
  It is proprietary, centralized, ad-adjacent, and reads everything you write.
- **Matrix / Element** is genuinely decentralized and encrypted, but the community
  experience is not competitive with Discord, and encryption at public-server scale
  fights the product rather than serving it.
- **Stoat** (formerly Revolt) is the most usable open-source Discord alternative and the
  benchmark to beat, but is not end-to-end encrypted.
- **Signal** has the best cryptography and the best safety-preserving design instincts,
  but is not trying to be a community platform.

Cairn's bet: **the reason nobody has combined these is not that it is impossible, but that
everyone has treated encryption as all-or-nothing.** Once you accept that a 50,000-member
public server with open invites is *already public* — and that encrypting it buys no real
confidentiality while destroying search, moderation, and mobile sync — the conflict
largely dissolves. Encrypt what is actually private. Moderate what is actually public.

That single decision ([ADR-001](adr/001-tiered-encryption.md)) is what makes the rest of
this project tractable.

## What Cairn is

An open-source, self-hostable communication platform with:

- **Communities** — servers, channels, roles, voice, the full Discord surface area
- **DMs and group chats** — end-to-end encrypted with MLS (RFC 9420), no exceptions
- **Tiered encryption** — matched to the actual privacy of the surface, always visible in
  the UI, immutable once a room is created
- **A safety stack that is honest** — message franking, subscribable policy lists,
  server-side hash matching on public surfaces, and on-device filters that are described
  as filters rather than as enforcement
- **Rich embeds without surveillance** — the sender's device fetches and renders link
  previews, so the server never learns the URL and the recipient never contacts the
  platform

## What Cairn is not

- **Not a metadata-privacy tool.** The server sees who talks to whom. See
  [`01-threat-model.md`](01-threat-model.md) §3.1.
- **Not federated at launch.** Self-hosted islands first, with a designed seam.
  See [ADR-003](adr/003-islands-first.md).
- **Not a Discord bridge or a drop-in replacement.** Compatibility with Discord's API is
  explicitly not a goal — Spacebar occupies that niche.
- **Not safe against a targeted state-level attacker.** See
  [`01-threat-model.md`](01-threat-model.md) §3.4.
- **Not a cryptocurrency, token, or blockchain project.** In any form.

## Differentiation

| | Discord | Matrix | Stoat | Signal | **Cairn** |
|---|---|---|---|---|---|
| Community features | ✅ Best | ⚠️ Weak | ✅ Good | ❌ No | ✅ Target |
| Open source | ❌ | ✅ | ✅ | ✅ | ✅ |
| Self-hostable | ❌ | ✅ | ✅ | ⚠️ Impractical | ✅ |
| E2EE private chats | ❌ | ✅ | ❌ | ✅ | ✅ |
| MLS group crypto | ⚠️ Calls only | ⚠️ Experimental | ❌ | ❌ | ✅ |
| Franking / verifiable reports | ⚠️ Internal | ❌ | ❌ | ⚠️ Partial | ✅ |
| Subscribable ban lists | ❌ | ✅ Best in class | ❌ | ❌ | ✅ Adopting |
| Privacy-preserving embeds | ❌ | ❌ | ❌ | ⚠️ Unauthenticated | ✅ Authenticated |

The two cells nobody else fills: **community features plus real E2EE in the same product**,
and **authenticated on-device embeds**.

## Why now

- **MLS stopped being a research bet.** Google Messages and Apple Messages began rolling
  out MLS over RCS in May 2026; Discord uses MLS for E2EE voice and video group keying.
  RFC 9420 now has multiple mature implementations. Building on MLS in 2026 is the
  conservative choice, not the adventurous one.
- **Trust in centralized platforms is declining**, with a visible 2026 push toward age
  verification and identity collection across the category.
- **The moderation tooling problem has a proven answer.** Matrix's subscribable ban lists
  (Mjolnir, then Draupnir) work in the wild. It can be adopted rather than invented.

## Non-negotiables

Principles that override feature requests, roadmap pressure, and growth targets:

1. **Never weaken an encryption tier after launch.** A room's tier is immutable. No
   silent downgrades, ever — users calibrate their behavior to the badge.
2. **Never ship client-side scanning as an enforcement mechanism.** As a user-controlled
   filter, yes. As a mandate, never. This is the line that costs us the privacy community
   if crossed.
3. **Never claim a protection the threat model does not support.** Marketing copy is
   reviewed against [`01-threat-model.md`](01-threat-model.md).
4. **No ads, no message-content-derived monetization, ever.**
5. **The flagship instance gets no protocol privileges** that a self-hosted instance
   cannot have.

## Success criteria

**v1 is successful if** a community of ~500 people moves from Discord and stays for three
months; DMs are E2EE with verifiable safety numbers; moderators say the tooling is better
than Discord's; and an outside cryptographer reviews the protocol without finding a
structural flaw.

**v1 has failed if** we shipped encryption users cannot verify, a safety stack that only
works against people who did not try to evade it, or a product that is merely a worse
Discord with a privacy label.

## Roadmap

See [the plan](../README.md#status) for phases. Documentation and threat model first,
then a timeboxed protocol spike ([`03-protocol-evaluation.md`](03-protocol-evaluation.md)),
then a vertical slice, then product.
