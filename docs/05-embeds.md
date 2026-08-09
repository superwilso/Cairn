# Embeds — Authenticated On-Device Unfurl

**Status:** Draft — open for comment

The genuinely novel piece of Cairn, and the feature most likely to be copied.

## The problem

Every platform unfurls links server-side. The server fetches the URL, renders a card, and
serves it to everyone. This means the server learns every link anyone shares — and in an
E2EE product it is worse, because the server cannot see the message but *can* see the URL
it was asked to unfurl, which frequently gives away the content anyway.

The workarounds people use today are proxy domains — `fxtwitter.com`, `kkinstagram.com` and
friends — which fix the *rendering* problem but hand the link to a third party and cannot
see logged-in-only content at all.

## The design

**The sender's client fetches the link with the sender's own session, renders the card
locally, and sends it as an attachment inside the encrypted envelope.**

```
Sender's device                    Server              Recipient
──────────────                     ──────              ─────────
1. user pastes URL
2. fetch, authenticated
   as the sender
3. render card locally
4. card + message ──encrypted──►  relays  ──────────►  5. displays card
                                  (opaque)                 no fetch,
                                                           no URL leak
```

The server never learns the URL. The recipient never contacts the platform. Signal does the
unauthenticated version of this already; the **authenticated** fetch is what unlocks
content that requires a logged-in session.

**On the objection that clients cannot do this because of CORS:** they can. CORS is a
browser mechanism governing cross-origin requests made by page scripts. A native client
issuing an ordinary HTTP request is not subject to it — no preflight, no
`Access-Control-Allow-Origin` check. Cairn's clients are native on all five targets
([ADR-006](adr/006-platform-architecture.md)), so the objection does not apply. It would
apply to a web client, which is one more reason a web client's guarantees are weaker
(`01-threat-model.md` §4).

## Fallback chain

Try in order, degrade gracefully:

1. **Authenticated fetch** — the sender has linked that platform, opt-in
2. **Public oEmbed / OpenGraph** — no session needed
3. **Third-party proxy** — `fxtwitter` and similar, with an explicit privacy notice
4. **Bare link** — always works

Never silently skip to a less private step. If step 1 is unavailable, the UI should make it
visible that a less private path was used.

## Four things that can sink this

### 1. Privacy — it is a leak by construction

The sender's device contacts an external platform, revealing the sender's IP, session, and
by implication their identity and interest in that link. Cairn deliberately moves the leak
from the *server* to the *sender's device*, which is better — but it is not zero.

**Requirements:**

- **Opt-in per platform.** Never globally on. Linking X does not imply linking Instagram.
- **A clear, one-time explanation** of exactly what is revealed and to whom.
- **Visible indication** in the composer when an authenticated fetch is about to happen.
- **Never fetch automatically on paste** for a platform the user has not enabled.
- Consider routing through the user's own proxy where they have one.

### 2. ToS and platform hostility

Authenticated scraping violates X's and Instagram's terms of service, and their
anti-automation systems will actively fight it. This is not a risk to mitigate once; it is
a permanent operating condition.

**Requirements:**

- Isolate each platform behind a **versioned adapter interface**. Assume adapters break
  regularly and independently.
- **Graceful degradation is mandatory** — a broken adapter falls to step 2 or 3, never
  errors at the user.
- Adapters ship **independently of the client** so a break does not need a full release.
- **Document the legal position honestly** for self-hosters, who may be in different
  jurisdictions with different exposure.
- Accept that some platforms may become permanently unavailable.

### 3. Attribution — a sender-rendered card is the sender's claim, not a fact

The card is produced on the sender's device, so the sender controls every pixel and every
word of it. A modified client can render a card that carries a reputable outlet's name,
favicon, and styling over text that outlet never published. The server cannot check this,
because in T1/T2 it cannot read the message at all — and in a self-hostable, open-source
client, stripping the check is an afternoon's work (`01-threat-model.md` §7, A12).

**This is not fixable, and it must not be papered over.** It is the direct cost of moving
the unfurl off the server, and it is worth paying — the alternative hands every link to
the server or to a third party. But a fabricated card that *looks* server-verified is
precisely the false assurance `01-threat-model.md` forbids, and it is more dangerous than
no embed at all, because users calibrate to the card.

**Requirements:**

- **A card is visibly sender-supplied.** Never style it as verified, checked, or fetched
  by the instance. Whatever visual language means "we vouch for this" must not appear.
- **The claimed source is presented as a claim.** Showing a domain next to content the
  sender assembled invites the reading that the domain vouched for it.
- **The underlying link stays visible and inspectable,** so a recipient can go and check.
- **No trust indicator may ever be derived from the card's own contents** — that is asking
  the attacker what to believe.
- T3 is different: a server-side unfurl there *is* server-fetched, and may say so. Do not
  reuse one visual treatment across both, or the T3 treatment launders T1/T2 cards.

### 4. Takedowns and liability

The sender re-uploads someone else's media into the encrypted envelope. That is a copy, and
copies attract takedown requests.

**Open questions, all legal rather than technical:**

- Who is responsible for a re-hosted image — the sender, the instance, or the project?
- How does a takedown reach content the server cannot read?
- Does re-hosting change the analysis versus hotlinking?
- What is the self-hoster's exposure, and does it differ by jurisdiction?

These need an actual legal answer before the feature ships publicly, and they interact with
[`07-regulatory-posture.md`](07-regulatory-posture.md). Re-hosted **video** sharpens all
four questions rather than raising new ones — it is the media type takedown requests
actually target.

## Tiered behaviour

| Tier | Unfurl behaviour |
|---|---|
| T1 / T2 | Sender-side only. Card travels inside the encrypted envelope. |
| T3 | Server-side unfurl is acceptable — the server already sees the content. Cheaper, cached once, and avoids every sender fetching the same URL. |

## Carousels and multi-media posts

An Instagram carousel is one post carrying several images. So is an X post with four
attachments, and a Bluesky post with a gallery. **The card model is therefore a list of
media items, not a single image**, and it has to be a list from the first version.

This is a wire-format decision, not a rendering one. Retrofitting a list into a card format
that assumed one image means a second format and a migration, in a payload that travels
inside the encrypted envelope where both ends must agree. Cheap now, expensive later.

**Requirements:**

- A card carries an **ordered list** of media items, each with its own dimensions, alt
  text, and content type. One image is the list of length one, not a special case.
- **Item count is bounded**, and the bound is part of the size limit, not separate from
  it. Ten images at full resolution is a file transfer wearing a carousel's clothes.
- **Preserve order.** A carousel whose panels arrive shuffled misrepresents the post.
- **Carry alt text** where the platform provides it. Dropping it makes Cairn's rendering
  less accessible than the original, which is not a trade worth making for a card.
- Partial retrieval **degrades to what was fetched**, labelled as partial — never silently
  present three of five panels as though that were the whole post.

Worth knowing before anyone estimates this: **Instagram's public oEmbed endpoint was
deprecated in 2020** and the replacement requires a Facebook app token, and neither returns
carousel children. So carousels are reachable through the authenticated path and
essentially nowhere else. That makes them a good demonstration of why the authenticated
unfurl exists — and it also means carousel support is hostage to §2's adapter breakage in
exactly the way the rest of the Instagram adapter is.

## Video

Two different features get called "video", and conflating them produces bad decisions.

### Sending your own video

This is **attachments**, not embeds. It is table stakes against every product in
`08-feature-parity.md`, and it needs a subsystem Cairn does not have: encrypted blob
storage, chunked upload and download, a per-attachment key travelling inside the encrypted
message, and resumable transfers. That belongs in its own ADR and its own roadmap item.
Nothing in this document constrains it, and the size ceilings here do not apply to it.

### Embedding someone else's video

Here the constraint is real, and it comes from a rule three lines up in this document:
**no scripts, no iframes.** The inline player Discord shows for a YouTube link is an
embedded iframe streaming from the platform. Cairn cannot do that — it executes remote code
in the client and it contacts the platform from the *recipient's* device, which is the leak
the whole design exists to avoid.

So inline playback of a linked video is not a rendering choice. It requires the sender to
re-host the file inside the envelope, and that is the only way to get it. The options are:

| Approach | Cost |
|---|---|
| Thumbnail + link out | Cheap. Playing it contacts the platform, but that is the recipient's informed click. |
| Sender re-hosts the file | Inline playback works and leaks nothing. Costs bandwidth, storage, and takedown exposure (§4). |

**The default is thumbnail plus link.** Re-hosting is permitted for short clips under an
explicit size ceiling, opt-in, and never silently: a recipient on a metered connection
should not discover a 40 MB autoplay after the fact. An earlier draft of this document said
video was "never the file", which was wrong — it stated a default as a prohibition, and
the costs here are bandwidth, storage, and copyright rather than security. Those are
trade-offs to price, not lines to hold.

What does *not* move: the ceiling is enforced, the recipient still fetches nothing, and
re-hosted video is subject to §4's takedown questions in exactly the way re-hosted images
are — more so, since video attracts more of them.

## GIF pickers — the same problem, quietly

A GIF picker is an embed surface with the same leak. Querying a GIF provider reveals the
search term, which is often more revealing than the message. Requirements: proxy queries
through the instance where possible, never send the room or recipient, and treat the
provider as untrusted (`01-threat-model.md` §8).

## Implementation notes

- Rendering happens **locally**; never execute remote code to produce a card.
- Cards are **static**: image, title, description, attribution. No scripts, no iframes.
- **The recipient fetches nothing.** The card renders from what arrived inside the
  envelope. A client that resolves the URL to draw the card has moved the IP leak onto the
  recipient, who never opted in to that platform and cannot see that it happened.
- Enforce **size limits** — see "Video" below for where the ceiling actually binds.
- This lands on a storage limit that already exists: `03-protocol-evaluation.md` records
  that the server rewrites all state per message. Media in envelopes makes that materially
  worse, so **that gap closes before embeds ship**, not after.
- **Strip EXIF** from re-hosted images. Location data in a re-uploaded photo is a leak the
  sender did not intend.
- Cache per-sender, never cross-user, or the cache becomes a side channel revealing what
  other people have linked.
