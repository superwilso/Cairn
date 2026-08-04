# Safety Architecture

**Status:** Draft — open for comment

Four mechanisms, each placed where it is both effective and defensible. The organising
principle: **put each control on the surface where it actually works, and describe its
limits accurately.** A safety feature that only stops people who were not trying to evade
it should be labelled as such.

---

## 1. Message franking — the centrepiece

**Where:** T1 and T2 (encrypted surfaces). **Status:** implemented in
`crates/cairn-crypto/src/franking.rs`.

Franking lets a recipient prove "this account sent me exactly this message" without the
server ever seeing plaintext. It is the mechanism that makes E2EE compatible with real
moderation, and it is the reason Cairn does not have to choose between the two.

### Construction

- **Commitment:** `HMAC-SHA256(key = opening, domain ‖ prev ‖ len ‖ plaintext)`. HMAC keyed
  by a random secret opening is a standard commitment: *hiding*, because the opening is
  uniform and secret, and *binding*, because a second preimage means breaking HMAC-SHA256.
- **Opening:** 32 random bytes, delivered to recipients **inside the encrypted payload**.
  The server never sees it. A recipient reports by choosing to disclose it.
- **Server tag:** `HMAC-SHA256(server_key, domain ‖ commitment ‖ room ‖ sender ‖ device ‖
  server_seq)`. Binds the commitment to who sent it, where, and in what order.

Domain separation strings distinguish the two constructions so one key can never be
misused across both.

### Why it is transcript-shaped from day one

The usual scheme covers **one** message in a **1-to-1** chat. Both limits are real
problems:

- **A single decontextualised line is close to useless to a moderator.** Abuse is a
  pattern, and the reported message is frequently the *response* to the abuse. A reporter
  who can only submit one message either fails to convey the problem, or submits the wrong
  message.
- **Retrofitting causality into a deployed report format is very expensive**, because old
  clients keep emitting the old format indefinitely.

So each message's **server attestation names its predecessor**, forming a chain. A report
can carry a contiguous run whose ordering the moderator verifies cryptographically rather
than trusting. v1 may populate a single message; the format does not need to change when
that stops being true.

**The server anchors the chain, not the sender.** An earlier design had each sender commit
to the predecessor it had seen. That works 1-to-1 and breaks in a group: two members
sending concurrently both believe they follow the same message, the chain forks, and the
transcript becomes unreportable — an honest-participant failure, not an attack. The server
assigns `server_seq` and is the only party that knows the true order when a message is
accepted. This costs no trust: `01-threat-model.md` §4 already concedes the server can
reorder and drop messages, so making it the ordering witness grants it nothing new.

This follows the 2025 transcript-franking line of work (arXiv:2507.19391).

**On group franking and AGMF.** The AGMF literature targets *metadata-private* systems,
where the server does not learn who sent a message and attribution must therefore be
carried cryptographically. Cairn is explicitly not metadata-private
(`01-threat-model.md` §3.1) and now authenticates every envelope, so the server knows the
sender directly and symmetric franking attributes correctly in groups. The genuine
group-specific problem was ordering, and that is what the server-anchored chain fixes.
Revisit AGMF if metadata privacy ever becomes a goal — it would make this reasoning
obsolete.

### Properties, verified by test

| Property | Test |
|---|---|
| Honest reports verify | `honest_transcript_verifies` |
| Edited plaintext is rejected | `tampered_plaintext_is_rejected` |
| Reattribution is rejected (unframeability) | `reattributing_to_another_account_is_rejected` |
| Forgery without the server key fails | `a_forged_message_cannot_be_tagged_without_the_server_key` |
| **Dropping context breaks the chain** | `omitting_a_middle_message_breaks_the_chain` |
| Concurrent group senders stay reportable | `concurrent_group_senders_still_produce_a_reportable_transcript` |
| Each group message attributed to its own sender | `a_report_from_a_group_attributes_each_message_to_its_own_sender` |
| The attested chain cannot be forged by a reporter | `a_reporter_cannot_forge_the_chain_the_server_attested` |
| Reordering is rejected | `reordering_is_rejected` |
| Cross-room splicing is rejected | `splicing_messages_from_another_room_is_rejected` |
| Commitments hide content | `commitment_hides_the_message` |

### What franking costs

**Deniability.** Franking exists to make sending provable, which is the opposite of what a
deniable protocol offers. Cairn accepts this trade on frankable surfaces and states it in
`01-threat-model.md` §3.6 rather than hiding it.

### What franking does not do

- It does not stop a determined sender from abusing someone. It makes reporting credible
  after the fact.
- It does not work if the recipient never reports.
- A malicious server can refuse to issue tags, or discard them. It cannot forge one.
- **The franking key must be persisted.** Losing it invalidates every historical report.
  This is now implemented: the key is stored with owner-only permissions and loaded on
  start, and a corrupt or unreadable key file is a hard error rather than a silently
  minted replacement — which would discard the ability to verify history without telling
  the operator.

---

## 2. Policy lists and ACLs — the highest-leverage item

**Where:** all tiers. **Status:** designed, not implemented.

Matrix's subscribable ban lists (Mjolnir, then Draupnir) are the most effective federated
moderation tool that exists in the wild. Communities publish ban lists as data; other
communities subscribe; enforcement is local, revocable, and auditable.

**Copy this design directly.** Do not invent an alternative. Specifically:

- Lists are **data, not code** — subscribing must never let a publisher execute anything.
- Enforcement is **local**. Subscribing is a recommendation the instance applies, and can
  stop applying at any time.
- Scope covers **accounts, servers, and rooms**, not just per-room bans.
- Lists are **versioned and auditable**, so a community can see what changed and why.
- Subscriptions must be **revocable without losing local decisions**.

This is the highest leverage per unit of effort in the whole safety stack: it works
cross-instance, it is protocol-independent, and it is proven. It is also the first thing
that should federate ([ADR-003](adr/003-islands-first.md)), because it is read-mostly,
plaintext, and eventually consistent — none of the MLS ordering problem applies.

**Governance risk, stated plainly.** Subscribable lists concentrate real power in list
maintainers, and disputes about a widely-subscribed list become disputes about who may
speak across many communities. The mitigation is that subscription is voluntary,
revocable, and visible — not that the problem does not exist.

---

## 3. On-device ML — a filter, not a scanner

**Where:** client, user-controlled. **Status:** designed, not implemented.

**The blunt version:** Cairn is open source and self-hostable. Any client-side scanner can
be removed by recompiling. Client-side scanning provides **zero adversarial security** in
this threat model — only friction against casual misuse.

Two consequences follow, and both are non-negotiable:

1. **Never ship it as an enforcement mechanism.** Mandatory client-side scanning is what
   killed Apple's 2021 CSAM plan, and it would cost Cairn the privacy community
   permanently — the exact community this project depends on.
2. **Never describe it as protection it cannot deliver.** Saying it "prevents" anything
   would be false.

**What it should be:**

- Blur suspected nudity before display, with a tap to reveal
- Flag likely scam and phishing patterns
- Warn on suspected grooming patterns in DMs to minors
- **Default-on for accounts registered as minors; every user can disable it**
- **Nothing is ever reported anywhere without the user taking an action**

All inference is local. No content, hashes, or scores leave the device unbidden. Framed
this way it is genuinely useful — most harm reaching most users is not from a
sophisticated adversary — and it is honest about what it is.

---

## 4. Hash matching and PSI — server-side, unencrypted surfaces only

**Where:** T3 only, plus public metadata surfaces. **Status:** designed, not implemented.

Run perceptual hash matching where it is both effective and defensible:

- Public community content (T3)
- Server directory listings and discovery entries
- Avatars, banners, emoji
- Invite previews

These are already server-visible, so there is **no privacy loss and no encryption
backdoor**. Detection quality is as good as any centralized platform's, because it is the
same operation on the same plaintext.

**Do not run hash matching against E2EE content.** Doing so requires either breaking the
encryption or moving the scan client-side — the latter being client-side scanning wearing a
different hat, which §3 rules out. PSI does not rescue this: it changes who learns the
match, not the fact that the client must scan.

---

## 5. How the pieces fit

| Surface | Franking | Policy lists | On-device ML | Hash matching |
|---|---|---|---|---|
| T1 DMs / groups | ✅ primary | ✅ blocks | ✅ user filter | ❌ |
| T2 private communities | ✅ primary | ✅ bans | ✅ user filter | ❌ |
| T3 public communities | ⚠️ redundant | ✅ bans | ✅ user filter | ✅ full |
| Public metadata | n/a | ✅ | n/a | ✅ full |

Franking is marked redundant in T3 because the server already holds the plaintext — it can
show what was said without needing a proof.

The pattern: **as content becomes more private, moderation shifts from server-side
detection to recipient-initiated, cryptographically verifiable reporting.** No surface is
unmoderated; the mechanism changes to match what is technically possible there.

---

## 6. Open questions

1. **Group franking.** Resolved for Cairn's threat model — see the AGMF note above. The
   ordering bug it depended on is fixed and tested. Reopen if metadata privacy becomes a
   goal.
2. **Report handling.** Franking proves a message was sent. It does not decide what to do
   about it. Moderator tooling, appeals, and review workflows are unspecified and are at
   least as much of the work as the cryptography.
3. **Franking key rotation.** Rotating invalidates old reports; never rotating is its own
   risk. Needs an epoch design.
4. **Reporter privacy.** A report identifies the reporter to the moderator. In a small
   community that can expose them to retaliation.
5. **Abuse of the report channel.** Mass false reporting is itself an attack. Verifiable
   reports help — a false report of a fabricated message simply fails to verify — but
   volume-based harassment with *genuine* messages remains open.
