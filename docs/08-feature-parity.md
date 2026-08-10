# Feature Parity

**Status:** Draft — open for comment

Cairn is measured against **Discord, Signal, WhatsApp, Instagram DMs, and Telegram**. This
document is the running scorecard. It exists to keep the project honest: the aim is to beat
these products, and a feature list that quietly omits what they do well is not a plan.

Legend: ✅ has it · ⚠️ partial or qualified · ❌ lacks it · 🎯 Cairn target

---

## 1. Messaging core

| Feature | Discord | Signal | WhatsApp | Instagram | Telegram | Cairn |
|---|---|---|---|---|---|---|
| 1:1 DMs | ✅ | ✅ | ✅ | ✅ | ✅ | 🎯 v1 |
| Group chats | ✅ | ✅ | ✅ | ✅ | ✅ | 🎯 v1 |
| Threads / replies | ✅ | ⚠️ replies | ⚠️ replies | ⚠️ replies | ✅ | 🎯 v1 |
| Reactions | ✅ | ✅ | ✅ | ✅ | ✅ | 🎯 v1 |
| Edit / delete | ✅ | ✅ | ✅ | ⚠️ | ✅ | 🎯 v1 |
| Disappearing messages | ❌ | ✅ | ✅ | ✅ | ✅ | 🎯 v2 |
| Read receipts (optional) | ⚠️ | ✅ | ✅ | ✅ | ✅ | 🎯 v1, opt-out |
| Typing indicators | ✅ | ✅ | ✅ | ✅ | ✅ | 🎯 v1, opt-out |
| Message search | ✅ | ✅ local | ✅ local | ✅ | ✅ server | 🎯 tiered |
| Scheduled messages | ❌ | ❌ | ⚠️ | ❌ | ✅ | 🎯 v2 |
| Voice messages | ✅ | ✅ | ✅ | ✅ | ✅ | 🎯 v1 |

**Note on search.** Telegram's server-side search over all history is a genuine advantage
that E2EE products structurally cannot match. Cairn's tiering means public communities get
server-side search and private surfaces get local search — better than Signal, worse than
Telegram, and the trade is explicit rather than hidden.

## 2. Communities

Discord is the benchmark; nobody else is close.

| Feature | Discord | Signal | WhatsApp | Instagram | Telegram | Cairn |
|---|---|---|---|---|---|---|
| Servers / spaces | ✅ | ❌ | ⚠️ Communities | ❌ | ⚠️ Channels | 🎯 v1 |
| Channels within a server | ✅ | ❌ | ⚠️ | ❌ | ❌ | 🎯 v1 |
| Roles & granular permissions | ✅ | ❌ | ⚠️ admin only | ❌ | ⚠️ admin only | 🎯 v1 |
| Voice channels (drop-in) | ✅ | ❌ | ❌ | ❌ | ⚠️ voice chats | 🎯 v2 |
| Screen share | ✅ | ⚠️ in call | ⚠️ in call | ❌ | ✅ | 🎯 v2 |
| Stage / broadcast | ✅ | ❌ | ❌ | ⚠️ Live | ✅ | 🎯 v3 |
| Custom emoji / stickers | ✅ | ⚠️ stickers | ⚠️ stickers | ⚠️ | ✅ | 🎯 v1 |
| Bots & app platform | ✅ | ❌ | ⚠️ Business API | ❌ | ✅ | 🎯 v2 |
| Server discovery | ✅ | ❌ | ❌ | ❌ | ✅ | 🎯 v2 |
| Large public groups | ✅ | ⚠️ 1,000 | ⚠️ ~1,000 | ❌ | ✅ 200,000 | 🎯 T3 |

**Voice channels and screen share are designed but unbuilt**, and the v2 marks above hide
how large they are: see [`12-realtime-media.md`](12-realtime-media.md). Three things from
that document change what the table implies. Calls need their own MLS group and an SFU, so
this is the biggest single component the project has considered. It lands **after** the
native clients, because a terminal cannot capture a microphone. And unlike Discord, Cairn
will refuse a call rather than downgrade it to plaintext for a client that cannot do E2EE
media — the badge is not allowed to lie.

**Customisation is a differentiator, not a footnote.** Most of what Discord charges for
under Nitro is artificial scarcity — a limit chosen in order to sell removing it — and on an
instance you run yourself there is nothing to remove. Designed in
[`13-customisation.md`](13-customisation.md), including the two places "free" is not free
(uploads and streaming cost the operator real money) and the one that is genuinely different
under E2EE: a custom emoji fetched at render time tells the server which emoji you used and
when, leaking content it could not otherwise read.

**Bots are not optional.** They are much of why Discord communities stay on Discord. A bot
in an E2EE room is a group member holding keys — an A6 adversary with a friendly name
(`01-threat-model.md` §5). The design must surface that to users, and it is an open
question in `01-threat-model.md` §10.

## 3. Media and embeds

| Feature | Discord | Signal | WhatsApp | Instagram | Telegram | Cairn |
|---|---|---|---|---|---|---|
| Image/video/file sharing | ✅ | ✅ | ✅ | ✅ | ✅ | 🎯 v1 |
| GIF picker | ✅ | ✅ | ✅ | ✅ | ✅ | 🎯 v1 |
| Link previews | ✅ server | ⚠️ sender-side | ⚠️ sender-side | ✅ | ✅ server | 🎯 **authenticated, sender-side** |
| Social embeds (X, Instagram) | ⚠️ often broken | ❌ | ❌ | ⚠️ own only | ⚠️ | 🎯 **the differentiator** |
| Large file limits | ⚠️ paywalled | ⚠️ | ⚠️ 2 GB | ⚠️ | ✅ 2 GB free | 🎯 operator-set |

Link previews are where Cairn does something none of them do — see
[`05-embeds.md`](05-embeds.md). Signal does the unauthenticated version; the authenticated
on-device unfurl is genuinely new.

## 4. Privacy and security

| Feature | Discord | Signal | WhatsApp | Instagram | Telegram | Cairn |
|---|---|---|---|---|---|---|
| E2EE DMs | ❌ | ✅ | ✅ | ⚠️ opt-in | ⚠️ **opt-in only** | 🎯 ✅ default |
| E2EE group chats | ❌ | ✅ | ✅ | ⚠️ | ❌ | 🎯 ✅ |
| MLS (RFC 9420) group crypto | ⚠️ calls | ❌ | ❌ | ❌ | ❌ | 🎯 ✅ |
| Open source client | ❌ | ✅ | ❌ | ❌ | ✅ | 🎯 ✅ |
| Open source server | ❌ | ✅ | ❌ | ❌ | ❌ | 🎯 ✅ |
| Self-hostable | ❌ | ⚠️ impractical | ❌ | ❌ | ❌ | 🎯 ✅ |
| No phone number required | ✅ | ⚠️ now optional | ❌ | ❌ | ❌ | 🎯 ✅ |
| Metadata protection | ❌ | ✅ sealed sender | ❌ | ❌ | ❌ | ❌ **not v1** |
| Key verification | n/a | ✅ | ✅ | ⚠️ | ⚠️ | 🎯 v1, required |
| Reproducible builds | ❌ | ✅ | ❌ | ❌ | ⚠️ | 🎯 v2 |

Two honest notes:

- **Telegram is weaker than its reputation.** Default chats are not end-to-end encrypted;
  E2EE is opt-in "secret chats", 1:1 only, mobile only. Cairn should not cite Telegram as
  a privacy benchmark, and should not let anyone else do so either.
- **Signal beats us on metadata**, and will keep doing so until sealed-sender-style
  protection is designed in. That is stated as a non-goal in `01-threat-model.md` §3.1, not
  glossed over. It is the single biggest privacy gap in Cairn's v1.

## 5. Safety and moderation

| Feature | Discord | Signal | WhatsApp | Instagram | Telegram | Cairn |
|---|---|---|---|---|---|---|
| Report a message | ✅ | ⚠️ limited | ✅ franking | ✅ | ⚠️ | 🎯 ✅ **transcript franking** |
| Verifiable reports from E2EE | ❌ | ❌ | ✅ | ❌ | ❌ | 🎯 ✅ |
| Multi-message report context | ⚠️ | ❌ | ❌ | ⚠️ | ❌ | 🎯 ✅ **nobody has this** |
| Subscribable ban lists | ❌ | ❌ | ❌ | ❌ | ❌ | 🎯 ✅ (adopting Matrix's) |
| Server-side hash matching | ✅ | ❌ | ⚠️ | ✅ | ⚠️ | 🎯 T3 only |
| User-controlled content filters | ⚠️ | ⚠️ | ⚠️ | ✅ | ❌ | 🎯 ✅ |
| Granular admin tooling | ✅ | ❌ | ⚠️ | ⚠️ | ⚠️ | 🎯 ✅ |
| Block / mute | ✅ | ✅ | ✅ | ✅ | ✅ | 🎯 v1 |

**Where Cairn can genuinely lead.** WhatsApp has franking, but for single messages in 1:1
chats. Nobody ships verifiable *multi-message* reports with cryptographic causality. That
is both a real moderation improvement and a defensible differentiator —
see [`04-safety-architecture.md`](04-safety-architecture.md).

## 6. Platform coverage

| Platform | Discord | Signal | WhatsApp | Instagram | Telegram | Cairn |
|---|---|---|---|---|---|---|
| Windows | ⚠️ Electron | ⚠️ Electron | ⚠️ Electron | ❌ | ✅ native | 🎯 **native, first** |
| macOS | ⚠️ Electron | ⚠️ Electron | ✅ native | ❌ | ✅ native | 🎯 native |
| Linux | ⚠️ Electron | ⚠️ Electron | ❌ | ❌ | ✅ native | 🎯 native |
| iOS | ✅ | ✅ | ✅ | ✅ | ✅ | 🎯 native |
| Android | ✅ | ✅ | ✅ | ✅ | ✅ | 🎯 native |
| Web | ✅ | ❌ | ✅ | ✅ | ✅ | ⚠️ v3, weaker guarantees |

Telegram is the parity benchmark here — it is the only one of the five with genuinely
native desktop clients. See [ADR-006](adr/006-platform-architecture.md).

A web client's security guarantees are inherently weaker, because the server serves the
code that holds the keys (`01-threat-model.md` §4). If one ships, the UI must say so.

---

## What "winning" looks like

Cairn does not need to beat all five on everything. It needs to be the only product where
these are simultaneously true:

1. Discord's community features
2. Signal-grade encryption on private surfaces
3. Fully open source and self-hostable
4. Moderation tooling that is *better* than the proprietary options, not worse
5. Genuinely native on every platform

No existing product has more than three of those.

## Where we will lose, and should admit it

- **Metadata privacy** — Signal wins until we design for it.
- **Server-side search over encrypted history** — structurally impossible; Telegram wins.
- **Network effects** — everyone wins; we start at zero.
- **Bot ecosystem** — Discord has a decade of head start.
- **Media limits and CDN quality** — funded competitors win on infrastructure.
