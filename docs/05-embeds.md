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

**Decided (owner): the sender is responsible, and the instance offers a removal path.**

The sender chose to re-host someone else's media, so the obligation follows the choice. The
instance operator provides a documented way to have stored media removed on request, and
nothing more — a self-hoster running Cairn for six friends must not inherit a moderation
duty they cannot discharge.

This is also the only option consistent with the rule that the flagship instance gets no
protocol privileges a self-hosted one cannot have: an operator-responsibility model would
oblige every self-hoster to run moderation, which in practice means only the flagship could.

What it requires, and none of it exists yet:

- A removal endpoint, and an operator-facing way to act on a request.
- A written policy, in the repository, saying who to contact and what happens.
- Retention rules — how long removed media is actually gone for.

Note the limit honestly: in **T1 and T2 the server holds ciphertext it cannot read**, so
"remove this image" means removing bytes identified from outside, not content the operator
can find by looking. A takedown story that assumes the operator can search is a story for
T3 only.


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

## Linking an account and extracting the media

The proposal: the user links their Instagram account, a lightweight background browser
extracts the images or video, and **only those files** are sent, with the original link as
metadata. `kkinstagram.com` as the fallback when there is no session or the extraction
fails.

**The shape is right and is already step 1 of the fallback chain.** Sending files rather
than Instagram's iframe is what preserves the recipient-fetches-nothing rule, and it is the
only way to show gated content at all. What follows is what it costs, so the cost is chosen
rather than discovered.

### It does not remove the account leak — it concentrates it

An authenticated fetch means Instagram observes: *this named account requested this post at
this time.* Anonymous fetching leaks an IP; a linked account leaks an identity. The
**recipient** is fully protected either way, and the **sender** is more exposed, not less.
Any UI that presents linking as a privacy improvement is claiming a protection that does not
exist. It is a capability improvement.

Two consequences that must reach the user before they link:

- **Instagram may ban the account.** Automated fetching from a logged-in session is what
  their anti-automation systems exist to catch, and the penalty lands on the user's real
  account, not on Cairn. This is a materially different risk from a card that fails to load.
- **The session cookie is a credential.** `cairn_crypto::store` writes client state
  unencrypted at `0600`. A stored Instagram session grants access to someone's actual social
  account, which is a worse thing to hold at rest than group keys are. **Blocked on platform
  keystore storage**, not shippable before it.

### The browser is the expensive part

Extraction needs a renderer, because the media URLs come out of Instagram's JavaScript.
That means executing hostile remote code on the sender's device, inside a project that is
`#![forbid(unsafe_code)]` with a deliberately small supply chain.

**Bundling a browser engine is not acceptable** — it would be the largest single addition to
the attack surface and the supply chain, and per-app Chromium is not viable on mobile
anyway (ADR-006 targets five native clients).

The defensible form is the **platform's existing WebView** — WKWebView on Apple, Android
WebView, WebView2 on Windows — driven off-screen, with JavaScript enabled only for the
fetch and the result treated as untrusted input. That keeps the engine out of the supply
chain and puts it where the OS already patches it.

So the seam is a trait, not an implementation:

```
client-core:  trait MediaFetcher { fn fetch(&self, url) -> Result<Vec<Media>> }
platform:     supplies one backed by the OS WebView
```

Card construction, clamping, EXIF stripping, and the tier rules stay below the FFI line
(ADR-006). Only the fetch crosses it. A platform that supplies no fetcher degrades to the
proxy rung, which is the correct behaviour rather than a broken one.

### It needs attachments first

"Send only those files" is the attachments subsystem: encrypted blob storage, chunking,
size ceilings, a per-attachment key inside the encrypted message. It does not exist,
`EnvelopePayload` has no variant for it, and it lands on the server's per-message
full-state rewrite. **This is the same blocker that keeps thumbnails out of text cards**,
and it does not get smaller because the files are larger.

It also makes Cairn the **host** of someone else's photo or video, which is exactly the
takedown and liability question in §4 — unanswered, and a legal design question rather than
a technical one.

### kkinstagram as the fallback

Correct choice, and it is already modelled: `CardSource::Proxy`, whose `caveat()` a client
must display. The honest framing is that the proxy **sees the URL** — the leak moves from
Instagram to a third party rather than disappearing. That is often the better trade, and it
is still a trade the user should be told about, per the rule that a less private path is
never taken silently.

### Order of work

1. Attachments subsystem (own ADR), which needs the storage rewrite fixed first.
2. Platform keystore storage, before any session credential is held.
3. `MediaFetcher` trait plus one platform implementation.
4. Per-platform opt-in, with the account-ban and identity-exposure warnings above.
5. `kkinstagram` proxy rung, which can ship **before** any of the others and is the cheapest
   real improvement available today.

Step 5 is worth doing on its own. Steps 1 and 2 are large, and neither is an embed problem.

## Instagram: music and comments

Asked directly, so recorded. **Neither can be embedded**, and the reason is structural
rather than a gap in the implementation.

**Instagram's oEmbed returns an embed — not data.** Its payload is HTML: a `blockquote`
plus a script, or an iframe, which Instagram then renders. That is how every product with
rich Instagram embeds does it, and it is why theirs show music playing and comments
underneath — *Instagram is serving them at display time*. It also requires a Meta app and
an access token; the unauthenticated endpoint has been gone since 2020.

Cairn cannot use that payload. Rendering it means the **recipient's** device contacts
Instagram, which is the exact leak this design exists to prevent (see "The design", and the
recipient-fetches-nothing rule under Implementation notes). The privacy property and the
sanctioned mechanism are mutually exclusive. That trade is deliberate, and it costs
precisely this.

So each would have to come from scraping with the sender's session, and each fails for its
own additional reason on top of §2's ToS and fragility problems:

**Comments** are third-party content. Copying them into an encrypted conversation means
re-hosting words written by people who are not in it and did not consent, with a takedown
path we do not have (§4). Worse, it collides with §3: a card is unverifiable, so a modified
client could fabricate comments **attributed to named real people**. A made-up headline is
bad; a made-up quote under a real person's handle is defamation with a UI around it. If
comments are ever shown, a count is defensible and their text is not.

**Music** on a Reel is licensed audio. Re-hosting it is a copyright question that a
thumbnail mostly avoids, and it needs the attachments subsystem that does not exist. The
audio track is also not exposed as metadata — you would be extracting it from a scraped
media URL.

**What is achievable**, within the model that already exists:

- The caption, author, and thumbnail *URL* from OpenGraph, subject to Instagram's login
  wall, which unauthenticated fetches usually hit.
- Carousels as the list-shaped card already designed above.
- The audio track's **name** as text — "Original audio — handle", or a song title — shown
  as a sender claim like every other field. No playback.
- A comment or like **count**, same footing. Not the text.

Everything past that requires either an iframe, which forfeits the recipient's privacy, or
re-hosting other people's media and words, which forfeits the takedown story.

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

## Status

**Text cards ship; images do not.**

Implemented in `cairn-client-core::embed` and wired into `cairn-cli chat`: the sender's
client fetches the URL, parses OpenGraph/`<title>`, and the finished card travels inside the
encrypted body. Verified over a real socket by
`a_link_card_reaches_the_recipient_and_the_server_never_sees_the_url`, which asserts the
serialized envelope contains neither the URL nor the title.

**Images are deliberately not fetched.** `Card::image_url` records where an image was and
nothing re-hosts it, because re-hosting means bytes in the envelope and the note below —
that the server's per-message full-state rewrite closes first — still stands. A text card is
a few hundred bytes and does not move that; a thumbnail would. Images land with attachments.

Known gaps, recorded rather than implied away:

- **The address check is host-based.** `is_fetchable` refuses loopback, RFC1918, link-local,
  CGNAT and unique-local addresses, but it **does not resolve DNS**, so a hostname pointing
  at a private address still passes, and **redirects are followed without re-checking**.
  Closing both needs a resolver hook in the HTTP client.
- **The fetch is not yet opt-in per platform.** §1 requires that, and today any pasted link
  is fetched with the sender's IP. This is the leak the design accepts by construction; what
  is missing is the consent step, not the mitigation.
- **No authenticated fetch and no proxy step.** `CardSource` models all three rungs of the
  fallback chain, but only `Public` is implemented. `Authenticated` needs per-platform
  session storage; `Proxy` needs the explicit privacy notice §1 describes.
- **No per-sender cache**, so the same link is refetched each time.

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
