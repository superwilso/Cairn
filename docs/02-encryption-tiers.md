# Encryption Tiers

**Status:** Draft — open for comment
**Decision record:** [ADR-001](adr/001-tiered-encryption.md)

This document specifies the tier rules in full. The *reasoning* for tiering lives in
ADR-001; this is the operational specification.

---

## 1. The tiers

### T1 — Private (DMs and group chats)

- **Applies to:** direct messages, ad-hoc group chats up to the T1 ceiling
- **Crypto:** MLS (RFC 9420), every member a leaf; a 1-to-1 DM is a two-member group
- **Server sees:** ciphertext, plus full metadata (participants, timing, sizes)
- **Search:** client-side only, over locally held history
- **Moderation:** recipient-initiated reports via franking; no server-side content access
- **Media:** encrypted client-side; the server stores opaque blobs

### T2 — Private community

- **Applies to:** invite-only communities under the T2 ceiling
- **Crypto:** MLS, one group per channel; membership changes are commits
- **Server sees:** ciphertext, plus full metadata including channel structure
- **Search:** client-side only
- **Moderation:** franking reports plus admin tooling operating on client-supplied
  evidence; admins cannot read history they were not present for
- **Media:** encrypted client-side

### T3 — Public community

- **Applies to:** communities over the ceiling, or any community with a public invite,
  discovery listing, or published directory entry
- **Crypto:** TLS in transit, encryption at rest; **no** end-to-end encryption
- **Server sees:** everything
- **Search:** full server-side, including history predating a user's join
- **Moderation:** full server-side — spam filtering, hash matching on media, automated
  detection, admin review
- **Media:** server-side storage, scanned per
  [`04-safety-architecture.md`](04-safety-architecture.md)

---

## 2. Tier assignment — deterministic and public

A room's tier is computed **at creation** from its properties. Users must be able to
predict the tier before they create the room.

```
if room is a DM or ad-hoc group chat:
    T1
else if community has a public invite, discovery listing, or directory entry:
    T3
else if community member ceiling > T2_MAX:
    T3
else:
    T2
```

`T2_MAX` is a published constant, **pending the spike** — it is the point at which MLS
commit churn makes mobile sync unacceptable, which is criterion #2 of
[`03-protocol-evaluation.md`](03-protocol-evaluation.md). It must be set from
measurements, not chosen for marketing reasons.

**Provisional working values, to be confirmed or replaced by measurement:**

| Constant | Provisional | Meaning |
|---|---|---|
| `T1_MAX` | 256 | Above this, an ad-hoc group chat must become a community |
| `T2_MAX` | 2,000 | Above this, a community is T3 |

Do not treat these as decided. They are placeholders so that downstream documents have
something concrete to reference.

---

## 3. Immutability

**A room's tier never changes after creation.** No exceptions, no admin override, no
operator override.

**Why downgrade is forbidden.** Users calibrate what they say to the badge they can see. A
room that silently becomes readable is worse than one that was never encrypted, because it
retroactively betrays disclosures already made under a stated guarantee. There is no UI
warning that fixes this — consent obtained after the fact is not consent.

**Why upgrade is also forbidden.** Converting T3 → T2 would imply protection of history the
server already holds in plaintext. The badge would assert something false about existing
messages.

**What happens when a community outgrows T2:** it does not convert. An admin creates a new
T3 community, with a new visible identity, and members join deliberately. History does not
migrate. This is a real product limitation, accepted knowingly — see ADR-001.

**Enforcement:** the tier is part of the room's creation record and is covered by the room's
cryptographic identity. It must not be a mutable database column that a `UPDATE` statement
or a compromised admin account can flip. Design it so that changing the tier is
*structurally* impossible rather than merely forbidden by policy.

---

## 4. UI requirements

These are normative, not suggestions. The security claim depends on the user understanding
which tier they are in.

1. **Persistent indicator** on every room — header, always visible, never behind a menu.
2. **Composer indication.** The message box itself shows the tier. This is where the
   decision to disclose actually gets made.
3. **Distinct, learnable visual language.** T1/T2 and T3 must not be distinguishable only
   by a small icon or by color alone (accessibility: never encode this in color alone).
4. **Join-time disclosure.** Joining a T3 room shows a one-time, explicit notice that
   content is readable by the operator.
5. **Room creation preview.** Show the resulting tier *before* the room is created.
6. **Membership changes are prominent in T1/T2.** A member added to an encrypted room is a
   security event. Per [`01-threat-model.md`](01-threat-model.md) §4, a silently added
   member is a wiretap — so this must be visible in the timeline, not a toast.
7. **No dark patterns toward T3.** Never make the less-private option the default styling,
   the pre-selected choice, or the faster path.
8. **The badge is derived locally, never taken from the server.** The client's own
   `RoomSeal` decides whether it encrypts, so a badge sourced from the instance's response
   could describe something other than what the client does with the message.
   `Client::create_room` derives the tier from the room's shape — a pure function of the
   published rule in §2 — and **refuses the room** if the instance disagrees in either
   direction, including when the instance claims *more* protection than the rule allows.
9. **A badge covers content, not the connection.** An E2EE indicator over a plaintext
   transport tells the user something true about their message body and something false
   about everything around it. The client states the transport separately.

**Status.** 1, 5, 6, 8, and 9 are implemented in `cairn-cli chat`; 2 is met trivially by a
line-based client whose prompt *is* the composer. 3, 4, and 7 await a graphical client and
a T3 implementation — the current client creates only T1 rooms.

---

## 5. Verification checklist

Per the plan's verification step: for every protection claimed, name the adversary it does
**not** stop. A tier row with an empty right-hand column is an incomplete specification.

| Tier | Protects against | Does **not** protect against |
|---|---|---|
| T1 | Network observers; honest-but-curious operator; legal compulsion for content | Metadata analysis; malicious operator without key verification; any group member; compromised device |
| T2 | Same as T1, across a community | Same as T1, plus: any member can leak, and communities have more members |
| T3 | Network observers only | The operator; anyone who joins; legal compulsion; anyone who obtains a public invite |

---

## 6. Open questions

1. **`T1_MAX` and `T2_MAX` must come from spike measurements.** Blocking on
   [ADR-005](adr/005-protocol-core.md).
2. **Do T3 communities get optional E2EE private channels inside them?** Attractive, but it
   means one community spans two tiers, and the per-room indicator would need to be
   exceptionally clear. Leaning yes, with strict UI requirements — needs a decision.
3. **What happens to a T2 community whose invite is made public?** Under §2 it *would* be
   T3, but §3 forbids conversion. Current answer: publishing an invite for a T2 community is
   **disallowed**; admins must create a T3 community instead. Confirm this is workable in
   practice, since it is the most likely source of user frustration in this design.
4. **Voice and video tiers — DECIDED (owner): calls inherit, with an upgrade-only choice at
   creation.**

   A call takes its room's tier by default. At the moment a call is created, the creator may
   additionally choose to make it end-to-end encrypted — but **only upwards**. A T3 room may
   host an E2EE call; a T1 or T2 room may never host a transport-only one. The choice is made
   once, at creation, and there is no setter afterwards, exactly as with a room's own tier.

   That asymmetry is the whole of it. An option that could go either way would be a tier
   downgrade with a friendlier name, and non-negotiable #1 forbids it. An upgrade-only option
   cannot weaken anything: the badge on a T3 call that opted up says more protection, and it
   is true.

   The UI consequence is that a call's badge and its room's badge can now legitimately
   differ, which is precisely what §12.1 of [`12-realtime-media.md`](12-realtime-media.md)
   worried about. It is acceptable *because the difference is always in the safer direction*
   and because the user chose it deliberately. A client must show the call's own badge, never
   inherit the room's on screen.

   Superseded reasoning, kept so it is not re-litigated: Discord uses MLS for E2EE calls; do calls inherit the room's
   tier, or are they always E2EE? The original leaning here was always-E2EE, since call media
   is not searched or moderated server-side anyway.
   [`12-realtime-media.md`](12-realtime-media.md) argues the opposite — calls should
   **inherit** — because an always-E2EE call inside a T3 room makes the room's badge and the
   call's badge disagree, and a user calibrated to "this room is public" would be in a surface
   with different rules. Still an owner decision; see §12.1 of that document for the full
   argument, and §5 for why a Discord-style downgrade to plaintext mid-call is forbidden here
   whichever way this lands.
