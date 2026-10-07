# Threat Model

**Status:** Draft — open for comment
**Every other document in this repository is downstream of this one.**

A threat model that lists only what a system defends against is marketing. This document
leads with **non-goals**, because the credibility of every protection claim Cairn makes
rests on being precise about what it does not do.

---

## 1. Assets

What an adversary might want, ordered by how much damage its loss causes.

| Asset | Description |
|---|---|
| **Message content** | What people actually said in DMs and private communities |
| **Long-term identity keys** | Compromise means impersonation and, with a malicious server, message interception |
| **Social graph** | Who talks to whom, and how often — frequently more sensitive than content |
| **Membership lists** | Which communities an account belongs to; can out people by association |
| **Presence and timing** | When someone is online, when they type, when they read |
| **Media** | Images, video, voice notes — often more identifying than text |
| **Moderation records** | Reports, bans, franking evidence; contains victim data by construction |
| **Account metadata** | Email, phone, IP, device fingerprints |

---

## 2. Adversaries

Listed with what Cairn does and does not do about each. "Partially" is used honestly and
is expanded in the sections below.

| # | Adversary | Defended? |
|---|---|---|
| A1 | Passive network observer (ISP, coffee-shop Wi-Fi) | **Yes** |
| A2 | Active network attacker (MITM, hostile CA) | **Yes** |
| A3 | Honest-but-curious server operator | **Yes** for E2EE tiers; **No** for public tiers |
| A4 | Malicious server operator | **Partially** — see §4 |
| A5 | Malicious community admin | **Partially** — they are inside the trust boundary |
| A6 | Malicious group member | **No** — they legitimately have keys; see §5 |
| A7 | Other users (harassment, spam, scams) | **Partially** — this is the safety stack's job |
| A8 | Compromised or stolen device | **Partially** — see §6 |
| A9 | Legal compulsion against a server operator | **Yes** for content in E2EE tiers; **No** for metadata |
| A10 | Global passive adversary (traffic correlation) | **No** — explicit non-goal |
| A11 | Targeted state-level attacker with client exploits | **No** — explicit non-goal |
| A12 | Malicious client fork | **No** — and cannot be; see §7 |

---

## 3. Explicit non-goals

Cairn does **not** protect against the following. These are design decisions, not gaps
awaiting a future release. If your safety depends on any of them, Cairn is the wrong tool
and we would rather you learn that here than from an incident.

### 3.1 Metadata privacy is not a v1 goal

The server necessarily learns who is talking to whom, when, how often, and how much. Cairn
does **not** implement sealed sender, onion routing, or cover traffic in v1.

This is the most consequential non-goal in the document. Content encryption without
metadata protection still leaks a great deal: a journalist's source is often exposed by
the *existence* of a conversation, not its contents.

Adding sealed-sender-style protection later is a **large architectural commitment** that
constrains the key hierarchy and the delivery path. It must be decided before the protocol
spec is frozen — it is listed as a Phase 1 open question for exactly that reason.

### 3.2 Public communities are not private

Content in large or public communities is readable by the server operator by design. This
is not a compromise forced by scale; it is the correct engineering answer, and the
reasoning is in [ADR-001](adr/001-tiered-encryption.md) and
[`02-encryption-tiers.md`](02-encryption-tiers.md).

### 3.3 We do not defend against a global passive adversary

An observer who can watch traffic entering and leaving many instances simultaneously can
correlate conversations regardless of encryption. Defeating this requires mix networks and
constant cover traffic, at a latency and battery cost incompatible with a real-time chat
application.

### 3.4 We do not defend against a compromised endpoint

If an attacker controls the device, they read messages as the user does. No messaging
protocol solves this. Cairn limits the *blast radius* (per-device keys, revocation,
forward secrecy) but does not claim to survive a compromised client.

### 3.5 Client-side scanning provides no adversarial security

Cairn is open source and self-hostable. Any client-side content scanner can be removed by
recompiling. On-device ML in Cairn is therefore a **user-controlled filter**, not an
enforcement mechanism, and is documented as such in
[`04-safety-architecture.md`](04-safety-architecture.md). Any claim that it *stops* a
motivated bad actor would be false.

### 3.6 We do not guarantee deniability alongside franking

Message franking exists to let a recipient *prove* who sent something. That is in direct
tension with the cryptographic deniability that protocols like OTR and Signal's Double
Ratchet aim for. Cairn chooses verifiable reporting over deniability in the surfaces where
franking applies. This is a real, permanent trade-off, and it is stated plainly rather
than buried.

### 3.7 Self-hosting does not mean we vouch for the host

An instance operator controls their deployment. Cairn cannot enforce that a third-party
instance runs unmodified code, honors its stated encryption tiers, or retains data as
claimed. Users trust *their instance operator*, plus the cryptography for E2EE tiers.

---

## 3a. Conceded by the 2026-08 direction change

Two protections were given up deliberately, pre-launch, and belong here rather than in the
documents that made the changes. Neither is a bug; both are choices, and #3 requires them to
be as visible as the guarantees.

**The instance sees URLs its users send.** [ADR-009](adr/009-instance-side-unfurl.md) moved
link unfurling from the sender's device to the instance, so a link posted in *any* tier —
including a T1 DM — is disclosed to the instance that hosts it. It sees the URL and which
account asked; not the message it sits in, not who else is in the room. Bounded by three
things: it is the user's own instance rather than the linked platform, the instance already
holds who-talks-to-whom under §3, and answers are cached so a repeat discloses nothing. A
client must offer to turn it off, and off means a bare link.

**In a browser, the instance serves the code that does the encryption.**
[ADR-008](adr/008-client-architecture.md) made the client a web application. An instance
serving malicious JavaScript can read anything the client can, so **end-to-end encryption in
the browser build is a claim against a network attacker, not against the instance operator.**
The Tauri desktop build is materially stronger — the code is shipped and signed rather than
fetched each session — and a user choosing between them is entitled to see that difference
stated. This does not change what the tiers mean; it changes who the browser build's E2EE
protects against, which is a smaller set than a reader would otherwise assume.

**A call may be transport-only inside an E2EE room.** The refusal-rather-than-downgrade rule
was dropped (`12-realtime-media.md` §5). A call now carries its own badge and announces a
fallback to every participant. Room messages are unaffected.

## 4. The malicious server operator (A4)

The most nuanced case, and the one most often overstated by messaging products.

**What the server cannot do in E2EE tiers:** read message content, or forge a message from
a user — content confidentiality and authenticity rest on MLS and on keys the server never
holds.

**What a malicious server *can* do, in every tier:**

- **Attempt key substitution.** The server distributes key material. A malicious server can
  hand Alice a key it controls and claim it is Bob's — the classic active MITM. The only
  real defense is **out-of-band key verification** (safety numbers / QR codes) plus **key
  transparency**, so that equivocation is detectable after the fact. Cairn must ship key
  verification in the same release as E2EE, not later. Without it, "end-to-end encrypted"
  is a claim the operator can quietly break.
- **Silently add a group member.** In MLS, membership changes are commits the server
  relays. A malicious server cannot forge a valid commit, but it can suppress, reorder, or
  delay them. Clients must therefore **display membership changes prominently** and
  validate the commit chain — a member added without a visible notice is a wiretap.
- **Deny service, drop, delay, or reorder messages.** Fully available to the server, and
  not preventable. Detectable via transcript integrity.
- **Harvest all metadata.** See §3.1.
- **Serve backdoored client code** to web clients. This is why native and
  reproducibly-built clients matter, and why a web client's guarantees are weaker. Say so
  in the UI.

**Consequence for the design:** key transparency and user-visible key verification are not
polish. They are what makes A4 a bounded adversary rather than an unbounded one, and they
belong in the same milestone as encryption itself.

**Status.** Safety numbers are implemented, tested, and now **shown to the user** by both
clients — `cairn-cli chat` (`/safety`, `/verify`) and the desktop client (from the member
list) — through one shared implementation in `cairn_client_core::verify`, with verification
state persisted across restarts and a loud, sticky warning when a verified contact's key
changes.

Two things had to be fixed before that display was worth anything, and both were found by
attacking the code rather than reading it:

- **The number was computed over the wrong key.** Nothing could read the MLS roster, so the
  only key a client could reach was the one the *server* published in its account
  directory. A malicious server could therefore hand Alice and Bob each other's real keys
  to display while committing a third leaf into the group: both sides saw the *same*
  number, compared it, and were reassured. Numbers are now derived from the group's own
  ratchet tree (`GroupHandle::safety_number_with`), which the server cannot alter without
  every member's client rejecting the commit.
- **Membership changes were invisible.** A commit adding a member was indistinguishable
  from any other handshake, so no client could have warned about one. Roster changes, and
  this device's own removal, are now distinct events the client prints in the timeline.

Two more surfaced when the desktop client gained the same display, again by probing:

- **A substituted key could still read as verified.** The contact store reports the state of
  the key it last *observed*, and the desktop session never showed it the roster. A contact
  verified once — the CLI shares the profile directory — and then replaced by a different
  key under the same credential was reported verified, with a tick. State is now reported
  only after observing the current roster, so the substitution reads as *key changed*.
- **Confirming by position could certify an unseen key.** `/verify <n>` marked whatever key
  held position *n* when the command ran; a commit landing after `/safety` printed the
  number changed which key that was. Both clients now hand back the number that was shown,
  and verification is refused if it is no longer the current one.

**A4 is bounded for a user who actually compares.** That is a narrower claim than "A4 is
bounded", and the gap is deliberate: verification is manual and per-peer, so it protects
exactly the conversations someone took the trouble to check. **Key transparency remains
unimplemented** (M5), and until it exists, a user who never compares a number is still
exposed to key substitution — the tool is now in front of them, but using it is their
decision.

---

## 4a. Other users of the same instance (A7, expanded)

An account on the same instance is not a passive bystander. Two vulnerabilities in this
class were found by probing shipped code rather than by reading it, and both are fixed:

- **Impersonation via device registration.** A user id is public — it is on every message
  the account sends — and any account could register a device against any id, then send as
  that account. Fixed by requiring accounts to be claimed and device linking to be
  authorized by a device already on the account.
- **Room access without membership.** Rooms had no membership concept, so any account
  could post into, and read the history of, any room it knew the id of — including private
  E2EE rooms. The read half broke §3.1 directly: metadata is conceded to the *server*, not
  to other users. Fixed by explicit membership, enforced on both the read and write paths
  and behind signed requests so it cannot be bypassed at the HTTP boundary.

Rooms now carry roles — owner, moderator, member — and only moderators and owners may
admit or remove accounts. A room always retains at least one owner, because a room with
none could never be moderated again.

What this class still permits: a removed account can be re-added by any moderator, and
there is no instance-wide ban. Removal is a room-scoped action, not a platform one, until
policy lists exist.

## 5. The malicious group member (A6)

There is no cryptographic defense against a participant who was legitimately given the
keys. They can read everything sent to the group and leak it. Screenshots exist.

This is precisely why the safety stack is **social and procedural**, not cryptographic:
franking, policy lists, admin tooling, and removal. Encryption protects a conversation
from outsiders; it has never protected it from participants, and any product implying
otherwise is lying.

---

## 6. Device compromise, loss, and recovery (A8)

- **Per-device keys.** Each device holds its own identity key; there is no shared master
  secret to steal once.
- **Forward secrecy and post-compromise security.** MLS provides both: past messages stay
  protected after a key compromise, and the group heals once the compromised member
  updates or is removed. This is a genuine advantage of MLS over static sender keys.
- **Revocation must be fast and obvious.** Removing a device is a group commit every member
  should see.
- **Recovery is an unsolved UX problem, and it is the one that decides adoption.** If a
  user loses every device, either they lose their history, or there is a server-side escrow
  that weakens the guarantee. Cairn must pick one deliberately and say which. This
  constrains the entire key hierarchy and is a Phase 1 open question.

---

## 7. The malicious client fork (A12)

Anyone can modify an open-source client to ignore retention rules, strip filters, log
plaintext, or misreport its state. **This is inherent to open source and is accepted.**

Design consequence: never place a security control **only** in the client where a server
check is possible. Client-side controls are UX, not enforcement. The corollary is that
rate limits, spam controls, and abuse limits must be enforced server-side to mean anything.

---

## 8. Trust boundaries

```
┌─────────────────────────────────────────────────────────────┐
│ User's device — TRUSTED                                     │
│   plaintext, private keys, unencrypted media                │
└────────────────────────────┬────────────────────────────────┘
                             │  TLS + MLS ciphertext
┌────────────────────────────▼────────────────────────────────┐
│ Instance server — SEMI-TRUSTED                              │
│   E2EE tiers  → ciphertext + full metadata                  │
│   Public tiers→ plaintext + full metadata                   │
│   Always      → routing, delivery, key distribution         │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│ Third parties — UNTRUSTED                                   │
│   embed targets, GIF providers, push services, object store │
└─────────────────────────────────────────────────────────────┘
```

Two boundary crossings deserve specific attention because they are easy to get wrong:

- **Push notifications.** iOS and Android push go through Apple and Google. Payloads must
  carry no plaintext content and no sender identity — only an opaque wake signal, with the
  client fetching and decrypting locally. A naive implementation leaks the social graph to
  a third party, which would undercut §3.1 even further than stated.
- **Embed fetches.** The authenticated unfurl deliberately has the *sender's* device
  contact an external platform. That reveals the sender's IP and session to that platform.
  This is why it must be opt-in per platform — see [`05-embeds.md`](05-embeds.md).

---

## 9. What a user should conclude

Plain-language summary, which should be reflected in the UI and in any public claims:

- **DMs and private communities:** your instance operator cannot read your messages.
  They can see who you talk to and when. Verify safety numbers to be protected against a
  malicious operator.
- **Public communities:** treat as public. Your instance operator can read everything, and
  so can anyone who joins.
- **Anyone in a conversation can leak it.** Encryption does not change this.
- **If your threat model is a nation-state targeting you personally, Cairn is not
  sufficient.**

---

## 10. Open questions blocking the protocol spec

1. Is metadata protection in scope for v2? The answer changes the key hierarchy and
   delivery path, so it must be decided before the spec freezes (§3.1).
2. What happens when a user loses every device? (§6)
3. Key transparency: build on an existing verifiable log design, or defer and ship only
   manual verification? Deferring is defensible; leaving it undocumented is not. Manual
   verification now exists as a primitive; the open question is whether it is sufficient
   for v1 and what surfaces it in the UI. (§4)
4. Are bots group members with keys, and how is that surfaced? A bot in an E2EE room is an
   A6 adversary with a friendly name.

---

## Revision policy

This document changes as the design does. Material changes to the adversary list or the
non-goals require an ADR, because downstream documents cite these sections directly.
