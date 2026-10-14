# GIF pickers, and the provider problem

**Status:** Built, in the shape below — relay on the instance, picker in the desktop client,
both KLIPY and GIPHY. See §7 for what exists and §1 for what KLIPY's terms turned out to say.

A GIF picker is table stakes — `08-feature-parity.md` lists it, and it is one of the
everyday things whose absence makes a messenger feel unfinished. It is also, built the
obvious way, **a content oracle on an end-to-end encrypted conversation**, and the market
for providers changed materially in 2026.

---

## 1. What changed

| Provider | State as of August 2026 |
|---|---|
| **Tenor** (Google) | **API shut down 30 June 2026.** Not an option |
| **Giphy** (Shutterstock, acquired 2023) | Beta keys ~100 requests/hour. Production access is a **negotiated paid contract** with no public price. Requires "Powered by GIPHY" attribution |
| **Klipy** | Founded by ex-Tenor engineers, API deliberately near-identical to Tenor's. Advertises a free tier. Funds itself through a **separate Ads API** |

Tenor's shutdown is the important one: it was the default free choice, and every project
that depended on it needed a migration this summer. That is why Klipy exists in the shape it
does — it is a drop-in for the thing that just died.

**KLIPY's terms, read October 2026** (`docs.klipy.com` was reachable this time). The content
API works without the Ads API: search and trending parameters such as `customer_id` are
documented as optional, and an advert arrives as a result with `type: "ad"` carrying HTML to
render. But KLIPY's standard
[integration requirements](https://docs.klipy.com/integration-requirements) say requests and
media must come from the end-user's device and *not* through partner proxies, that media must
not be re-hosted, and that search results must not be filtered — each "without prior written
approval". This design does all three deliberately: §3's relay, §3's re-hosting, and §4's ad
removal. So **KLIPY is usable on an instance only with KLIPY's written approval**, and
`11-self-hosting.md` tells operators so before they set the key. KLIPY also *requires* the
search box placeholder "Search KLIPY", which the client shows.

GIPHY's API terms page was not reachable from this environment (403), so its terms remain
unread here; its API documentation was, and confirms the "Powered by GIPHY" attribution and
that trending must be called "from the client side" — which the tunnel satisfies, since the
request is built and encrypted on the client.

## 2. The privacy problem, which is the real design

This is the same failure `13-customisation.md` §3 identifies for custom emoji, and it is
worse here because a GIF search is *text the user typed*.

Naive implementation, the one every tutorial shows:

1. User types "eye roll" into the picker → the client queries Giphy directly.
2. Client renders results by fetching from Giphy's CDN.
3. User sends one; the message carries a Giphy URL.
4. **The recipient's client fetches that URL from Giphy to display it.**

Every step leaks, and step 4 leaks on the *receiving* side of a conversation the recipient
believes is end-to-end encrypted:

- Giphy learns the **sender's search terms** — free-text, typed, often about the subject of
  the conversation — plus their IP and a stable client fingerprint.
- Giphy learns **who received it and when**, because the recipient's client contacts Giphy
  on render. Two IPs fetching the same rare GIF within a second of each other **is** the
  social graph, reconstructed by a third party from a conversation whose bodies are
  ciphertext.
- The message body stays encrypted throughout. MLS is working perfectly. The leak is
  entirely outside it.

Per non-negotiable #3, a product that ships this and calls the room end-to-end encrypted is
claiming a protection the threat model does not support.

## 3. The fix, which Signal already demonstrated

Signal's design is the reference and it predates the Facebook acquisition of Giphy — worth
noting, because it means they built it before there was a specific reason to distrust the
provider. The Giphy SDK is not in the app at all. Instead:

- The client opens a connection to the **Signal service**, which relays bytes to Giphy's
  HTTPS endpoint. TLS runs end to end between client and Giphy through that relay.
- **Giphy sees the search term but not who is searching.** **Signal sees that a search is
  happening but not what it is** — the query is inside the TLS session it is only relaying.
- The split is the whole point: neither party holds both halves.

Signal has also written about the residual weakness: a malicious relay could infer content
from **response sizes**, which is why padding is the natural next step rather than a
refinement.

**Cairn should copy this, with one addition that follows from ADR-003.** Cairn is
self-hostable islands, so the relay is *your instance*, not a flagship service. That is
better than Signal's position on one axis and worse on another, and both should be said
plainly:

- **Better:** you can run the relay yourself, so "trust the relay operator" becomes "trust
  the person already holding your metadata", which `01-threat-model.md` §3 concedes anyway.
  No new party enters the picture.
- **Worse:** a small instance is a *small anonymity set*. Signal's relay hides a search among
  millions; a Raspberry Pi with five users hides it among five. Against a provider that
  correlates by IP, an instance with one active user provides **no anonymity at all**, and
  saying otherwise would be exactly the kind of overclaim this project forbids.

The honest framing: the relay stops Giphy from building a profile keyed to a user identity,
and it does not make a small instance's users anonymous to Giphy. Both are true; ship the UI
copy that says so.

**Sending must re-host, not link.** Whatever the picker does, the selected GIF has to travel
as an attachment inside the encrypted envelope — the same path `05-embeds.md` already
defines for media. A message that carries a provider URL puts the recipient back in step 4
no matter how private the search was. This makes attachments a hard prerequisite, and it
means each sent GIF costs an upload against the quota in `state.rs`.

## 4. The ad question, which is a non-negotiable

Klipy's free tier is funded by its Ads API — the pitch is that apps monetise by inserting
ads between GIF results.

**Cairn cannot do that.** Non-negotiable #4 is "no ads, no monetization derived from message
content", and an ad rendered inside the message composer is an ad in the product regardless
of who is paid. `13-customisation.md` §1 already rejected charging to lift limits an operator
is not actually paying for; taking payment to show ads in the picker is the same instinct
with a worse smell.

That does **not** rule Klipy out. Its Ads API reads as a separate, optional product, and
using the content API without it appears to be permitted. But it is the first thing to
confirm in the terms — a free tier that *requires* ad display is unusable here at any price,
and it would be a bad surprise to discover after building against it.

If the terms do require ads, the fallback order is: a paid Giphy production contract for the
flagship (capacity, not protocol privilege — `13-customisation.md` §2 already allows that),
self-hosted instances configuring their own key or going without, and a picker that is
**absent rather than dishonest** on instances with no provider.

## 5. What an instance operator faces

Because Cairn is self-hosted, a GIF picker is not a feature the project ships once — it is a
dependency each operator inherits:

- **An API key is per-instance.** A shipped default key would be rate-limited into
  uselessness by the first ten instances, and would put the project's name on everyone's
  quota. So it is operator configuration, like `CAIRN_INVITES`.
- **No key must degrade gracefully.** The picker says GIF search isn't configured on this instance,
  rather than breaking or vanishing without explanation, and the docs
  say a fresh instance has no GIF search until the operator adds a key.
- **The relay costs the operator bandwidth**, since every search and preview goes through
  them. Modest next to attachments, but it belongs in the same sizing conversation as
  `11-self-hosting.md` §5.

## 6. Sequencing

Behind attachments, which are behind the transport work already in flight. Concretely:

1. Attachments end to end *(done)*.
2. Relay endpoint on the instance, plus the operator key configuration *(done, §7)*.
3. Picker in a client that has a UI — per ADR-006 this is native-client work, and a terminal
   is not where a GIF picker earns its keep. *(Done in the desktop client, which ADR-008
   made the one web client.)*

Nothing here goes below the FFI line: the picker chooses bytes, and `client-core` seals and
sends them exactly as it would any other attachment.

## 7. What was built

- **Relay** — `crates/cairn-server/src/gif_relay.rs` holds the rules; `http.rs` the plumbing.
  `GET /v1/gifs` (signed) returns each configured provider with its key and host list;
  `GET /v1/gifs/tunnel/{host}:443` (signed over the target) upgrades to a byte pipe. Hosts
  are a fixed list per provider, port 443 only, one canonical spelling of the target,
  addresses that resolve inward are never dialled, and each account is bounded at 600
  tunnels and 200 MiB an hour, with idle and lifetime limits per tunnel. An HTTP/1.1
  `Upgrade` rather than `CONNECT`, because a path-routing reverse proxy will not forward
  `CONNECT`.
- **Client** — `crates/cairn-client-core/src/gifs/`. TLS to the provider runs inside the
  tunnel and is verified against the provider's name, so an instance answering in the
  provider's place fails the handshake (tested). Results are parsed into opaque ids; KLIPY
  adverts and any result type other than `gif` are dropped; media URLs off the relayed hosts
  are dropped; bytes are sniffed and only GIF or WebP is accepted. No `customer_id`, locale
  or device parameters are sent. A sent GIF is fetched through the relay and then sealed,
  uploaded and sent by the attachment path, so recipients fetch ciphertext from the instance
  and contact no provider (tested: the stand-in provider sees no request from the recipient).
- **Desktop** — `ui/gifs.js`: trending on open, search, a tab per provider, each provider's
  required placeholder and attribution (decided in Rust), and "GIF search isn't configured on
  this instance" when there is none. The page never holds a provider URL.
- **Probed** (`crates/cairn-server/tests/gifs_http.rs`): the relay was asked, with valid
  signatures, for the instance itself, loopback, cloud metadata, private ranges, the
  providers on other ports, and look-alike and percent-encoded names; all refused with
  nothing dialled. One got through — `api.klipy.com:0443` was accepted as port 443. Harmless
  (same host, same port), but the target is what the device signs, so it now has exactly one
  spelling.
- **Not done:** response-size padding (§3 — a relay operator can still infer something from
  how big an answer was); pagination beyond the first 24 results; the instance cannot tell a
  member's quota abuse from a busy picker beyond the per-account limits.

---

**Sources:** [Signal and GIPHY](https://signal.org/blog/giphy-experiment/) ·
[Expanding Signal GIF search](https://signal.org/blog/signal-and-giphy-update/) ·
[GIPHY API Terms of Service](https://support.giphy.com/hc/en-us/articles/360028134111-GIPHY-API-Terms-of-Service) ·
[Klipy GIF API](https://github.com/KLIPY-com/Klipy-GIF-API) ·
[GIF API comparison](https://medium.com/klipy-blog/best-gif-apis-for-developers-in-2025-giphy-vs-tenor-vs-klipy-5e4f868e4381)
