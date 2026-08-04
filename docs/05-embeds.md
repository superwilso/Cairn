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

## Fallback chain

Try in order, degrade gracefully:

1. **Authenticated fetch** — the sender has linked that platform, opt-in
2. **Public oEmbed / OpenGraph** — no session needed
3. **Third-party proxy** — `fxtwitter` and similar, with an explicit privacy notice
4. **Bare link** — always works

Never silently skip to a less private step. If step 1 is unavailable, the UI should make it
visible that a less private path was used.

## Three things that can sink this

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

### 3. Takedowns and liability

The sender re-uploads someone else's media into the encrypted envelope. That is a copy, and
copies attract takedown requests.

**Open questions, all legal rather than technical:**

- Who is responsible for a re-hosted image — the sender, the instance, or the project?
- How does a takedown reach content the server cannot read?
- Does re-hosting change the analysis versus hotlinking?
- What is the self-hoster's exposure, and does it differ by jurisdiction?

These need an actual legal answer before the feature ships publicly, and they interact with
[`07-regulatory-posture.md`](07-regulatory-posture.md).

## Tiered behaviour

| Tier | Unfurl behaviour |
|---|---|
| T1 / T2 | Sender-side only. Card travels inside the encrypted envelope. |
| T3 | Server-side unfurl is acceptable — the server already sees the content. Cheaper, cached once, and avoids every sender fetching the same URL. |

## GIF pickers — the same problem, quietly

A GIF picker is an embed surface with the same leak. Querying a GIF provider reveals the
search term, which is often more revealing than the message. Requirements: proxy queries
through the instance where possible, never send the room or recipient, and treat the
provider as untrusted (`01-threat-model.md` §8).

## Implementation notes

- Rendering happens **locally**; never execute remote code to produce a card.
- Cards are **static**: image, title, description, attribution. No scripts, no iframes.
- Enforce **size limits** — an embed must not become a file-transfer channel.
- **Strip EXIF** from re-hosted images. Location data in a re-uploaded photo is a leak the
  sender did not intend.
- Cache per-sender, never cross-user, or the cache becomes a side channel revealing what
  other people have linked.
