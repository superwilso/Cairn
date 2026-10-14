# ADR-009: The instance unfurls links, not the sender

**Status:** Superseded before it was built (2026-10). The sender-side unfurl of
[`05-embeds.md`](../05-embeds.md) is what ships, with per-platform opt-in, every platform off
by default. The text below is kept as the record of why the instance-side design was
considered.

## Why it was superseded

- **It was a concession the threat model had to carry** (`01-threat-model.md` §3a): the
  instance would have seen every URL its users send, in every tier, T1 DMs included. The
  sender-side unfurl keeps the URL inside the encrypted message, so that concession is not
  needed.
- **Its main practical argument fell away.** "No thumbnails" was the strongest item below;
  the sender's device now fetches, shrinks and re-encodes the thumbnail and carries it in the
  encrypted card (`05-embeds.md`, Status).
- **The SSRF argument cuts both ways, and sender-side is now defended.** The sender's fetcher
  refuses non-public addresses after DNS resolution and on every redirect hop, which this
  ADR assumed only a server would bother to do.
- **What is accepted instead:** the sender's device reveals its IP address to each site it
  previews. That is why each platform has its own switch and all are off by default. Also
  accepted: there is no shared cache, every client carries every adapter, and two senders
  can produce different cards for one link.

The recipient-fetches-nothing rule, which this ADR kept, is unchanged.

---

## Context

`05-embeds.md` put the unfurl on the sender's device so the server never learns the URL. The
recipient-fetches-nothing rule that sits beside it is excellent and is **kept**. The
sender-side half has not worked out:

- **Every client needs every adapter.** Instagram's login wall, X's hostility, per-platform
  breakage — all of it multiplied by each client, forever.
- **No shared cache.** A link posted in a busy room is fetched once per sender. The instance
  cannot cache what it never sees.
- **Cards disagree.** Two people posting the same link produce different previews depending
  on what each client's fetch happened to return.
- **No thumbnails.** `Card::image_url` records where an image was and nothing re-hosts it,
  because re-hosting needs a fetch the sender's device is a bad place to do.

The Instagram work made this concrete: the only rung shippable from a client was a
third-party proxy, and it could not even be verified.

## Decision

**The instance runs an unfurl service.** A client posts a URL to its own instance; the
instance fetches, parses, caches and returns a card, re-hosting the thumbnail as an
attachment.

**The recipient still fetches nothing.** The card and its thumbnail travel inside the message
— in T1/T2, inside the encrypted body. That property was always the important half and it is
untouched: a recipient's device never contacts a platform because someone sent them a link.

## What this costs, plainly

**Your instance sees the links you send** — in every tier, including T1 DMs. It does not see
the message they sit in, who else is in the room, or anything else about the conversation;
it sees a URL and which account asked about it.

That is a genuine reduction and it must be stated in `01-threat-model.md` rather than
inferred. The bounding facts, which are real and worth knowing:

- It is **your instance**, not Instagram or X. On a self-hosted deployment that is a machine
  you own.
- The instance already holds who-talks-to-whom and when — `01-threat-model.md` §3 concedes
  that metadata. A URL is new information, but it is new information for a party that
  already has a lot.
- **Cached, so repeats cost nothing.** A link the instance has already fetched is answered
  without a new request, which also means the second person to post it discloses nothing.

**Clients must be able to turn it off.** A user who would rather have a bare link than tell
their instance about a URL gets that choice, per-conversation. Off means no card, which is
the honest outcome rather than a degraded one.

## What it buys

One adapter set, maintained in one place, in Rust, on a machine with a stable IP and no
login wall problem. Consistent cards. Thumbnails, because the instance can re-host into blob
storage that already exists. And the authenticated rung of `05-embeds.md` becomes reachable
without ever putting a user's session cookie on their own device — an operator can give
their instance credentials instead, which is a different and more manageable risk.

## What is explicitly *not* changed

- **Recipients still fetch nothing.** Non-negotiable.
- **A card is still a claim, not a fact.** It is now the instance's claim rather than the
  sender's, which is not obviously better — an instance can lie about a link exactly as a
  modified client could. `Card::claimed_source` and the UI rules in `05-embeds.md` §3 stand
  unchanged.
- **The address policy stands.** `is_fetchable` moves to the server, where refusing loopback
  and private ranges stops being politeness and becomes real SSRF defence: the fetcher is now
  a machine with an internal network worth reaching.
