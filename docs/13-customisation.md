# Customisation, and why most of Nitro is free here

**Status:** Design. Nothing here is built.

The question this answers: can Cairn match Discord's customisation, and give away what Nitro
charges for? Mostly yes — and the reason is not generosity. **Most of Nitro is artificial
scarcity.** It is a server-side limit Discord chose in order to sell removing it, and on an
instance you run yourself there is nothing to remove.

That is the easy half. The useful half of this document is the part where "free" is not
free, because there are three categories where the honest answer is different, and one
hazard that would quietly break a non-negotiable.

---

## 1. Free by construction

These cost an operator nothing meaningful and should never be gated:

| Nitro feature | Why it is free here |
|---|---|
| Longer messages (2,000 → 4,000 chars) | A constant in the code. There is no cost being recovered |
| Custom themes, app icons | Pure client-side presentation; the server is not involved at all |
| Profile banners, bios, animated avatars, avatar decorations | Small static assets, fetched once and cached |
| Per-community profiles | A row keyed by (account, community). No new machinery |
| Custom emoji and stickers | Small assets — but see §3, the design is not the obvious one |
| Soundboard | Same shape as emoji, same caveat |
| Custom badges | Cosmetic metadata |

**None of this needs a subscription tier, and there should not be one.** `00-vision.md` §4
already forbids ads and message-content-derived monetization; charging to raise a limit the
operator is not actually paying for would be the same instinct wearing a different hat.

## 2. Where "free" means someone else's bill

Two Nitro features are not artificial scarcity. They are the ones that cost real money:

- **Large file uploads.** Storage plus egress, every time anyone downloads.
- **HD and 4K streaming.** See [`12-realtime-media.md`](12-realtime-media.md) §10 — an SFU's
  egress scales with the square of the participant count, and screen share is the worst case.

On a self-hosted instance, "unlimited uploads for free" means *your friend who runs the
server* pays for it, and they will find out when the bill arrives. So the design is
**operator-set limits with conservative defaults**, which is what `08-feature-parity.md`
already says for file size, and the UI should be honest that the limit is the instance's
choice rather than a paywall.

That leaves the question of **how a flagship instance funds itself.** Ads and content-derived monetization are out permanently, and
non-negotiable #5 says the flagship gets no protocol privileges a self-hosted instance
cannot have — but resource limits are not protocol privileges, so a funded flagship with
higher upload ceilings does not violate it. Donations, paid hosting, and paid-tier
*capacity* (never features, never protocol) are all consistent with the rules as written.
**DECIDED (owner): a flagship instance may fund itself, because using it is optional.**
Nobody is obliged to use the flagship — the software is self-hostable and a Raspberry Pi in
a spare room is a legitimate deployment (`11-self-hosting.md` §7). That is what makes paid
*capacity* on the flagship acceptable where it would not be in a product people are locked
into: the alternative is not "pay", it is "run your own", and that alternative is real.

The limits that stay fixed regardless: no ads, no content-derived revenue, and no protocol
privilege the flagship holds that a self-hosted instance cannot. Capacity is not a protocol
privilege. A feature gated behind payment would be.

## 3. Custom emoji is a content oracle if built the obvious way

This is the part that is genuinely different in an E2EE product, and it is not obvious.

On Discord, a custom emoji in a message is a reference the client resolves by fetching
`.../emojis/12345.webp` when it renders. Copy that design into a T1 or T2 room and the
server learns **which emoji you used and when** — from the fetch, not from the ciphertext it
cannot read. The message body stays encrypted and the decoration leaks anyway.

It is worse than it first looks, for two reasons:

- A rare custom emoji is close to a **fingerprint**. "Who fetched `:blobsad:` within 200ms
  of message 4471" identifies a reader, and reactions make it worse, since a reaction is a
  much smaller set of possible values than a message.
- It is a **side channel that survives everything else being right**. The tier badge is
  honest, MLS is working, franking is intact — and the server still learns a usable signal
  about content, which is exactly the shape of failure `01-threat-model.md` §3 does not
  concede.

**The fix is to decouple fetching from rendering.** A client joining a community downloads
that community's whole emoji, sticker and soundboard set up front, and renders locally
thereafter. Fetching the set says only "I joined this community", which the server already
knows because it holds the membership. Nothing is fetched at render time, so nothing
correlates to a message.

Consequences worth stating before anyone builds it:

- Sets need a size ceiling, since every member downloads all of it.
- Updates need to arrive as a set, not per-emoji on first use — a lazily fetched *new*
  emoji reintroduces the exact leak.
- A **user's personal** emoji used in a DM has no set to hide in. Either carry it inside the
  encrypted envelope as an attachment, or accept the leak and say so. Leaning: carry it,
  since DMs are the tier where the claim is strongest.
- Attachments are the prerequisite either way, so this sits behind
  [ADR-007](adr/007-server-storage.md)'s successor work.

## 4. Themes yes, plugins are a different question

Open source can genuinely beat Discord here. BetterDiscord exists because people want
client theming badly enough to run an unsupported patcher that breaks on every update and
violates the ToS. Cairn can just support it.

But **theming and plugins are not the same risk**, and lumping them together would be a
mistake:

- **Themes** — colours, spacing, fonts, backgrounds — are declarative presentation. Safe,
  and should be first-class.
- **Plugins** run code inside a client that holds group keys and plaintext. That is the bots
  question from `01-threat-model.md` §10.4 wearing an even friendlier face: not a member of
  the room with its own keys, but code inside *your* client with *your* keys. If plugins
  ever ship, they need a permission model, and the answer cannot be "it is open source, read
  the code".

**Nothing here goes below the FFI line.** Per ADR-006 a customisation layer must never
construct an envelope, decide a tier, or touch a key — it decorates what `client-core`
already produced.

## 5. The hazard: a theme must never be able to lie about encryption

The one that would quietly break a non-negotiable.

`02-encryption-tiers.md` UI rule 8 requires the tier badge to be derived locally and always
visible, and the client already refuses to show a clean badge over `http://` because that
would claim a protection that does not exist. A theming system powerful enough to restyle
the whole interface is powerful enough to **restyle the badge** — to hide
`plaintext-transport`, or to make a T3 room look end-to-end encrypted.

That is not a hypothetical abuse by a malicious theme author; a careless theme that sets a
uniform background could do it by accident.

So: **the tier badge, the safety-number state, and membership warnings are outside theming
control.** Not "themes are discouraged from restyling them" — structurally unreachable, the
same way the tier has no setter. A customisation system that can repaint the security
indicators has made those indicators worthless, and per non-negotiable #3 an indicator that
can lie is worse than no indicator.

## 6. What this is worth

Discord charges roughly $10/month for a bundle that is mostly configuration. Cairn gives it
away because it has nothing to protect: no ads, no content-derived revenue, and an operator
who sets their own limits. That is a real, defensible marketing claim — the *only* one on
this page that costs nothing to keep.

The two things that must not be over-claimed alongside it: uploads and streaming are bounded
by whoever pays for the server, and custom emoji is free **only** if it is built as a set
download rather than a per-message fetch.
