# ADR-011: Spaces, channels and roles

**Status:** Accepted. **Roles stay instance-held** by the owner's decision; moving them into
the MLS group is a design for the M5 external review, not before (§"Decision on where roles
live").

## Context

Discord's shape is a server holding channels, with roles that decide who sees and does what.
[`08-feature-parity.md`](../08-feature-parity.md) marks all three as v1 and nothing in Cairn
did any of it: every room stood alone, with a three-step role ladder (owner, moderator,
member) of its own.

The tier model ([ADR-001](001-tiered-encryption.md)) says what is encrypted. It says nothing
about who may create a channel or remove a member, and that question is where this project's
three shipped vulnerabilities lived (`CLAUDE.md`): impersonation, room access without
membership, and no removal path. So this ADR is as much about what it does *not* protect as
about what it builds.

## Decision

### A space is a container of channels; a channel is a room

- A **space** has a name, an owner, a member list, roles, and channels. It is created with a
  **member ceiling that is sealed**, exactly like a room's.
- A **channel** is an ordinary room. It gets its own `RoomSeal` at creation, its tier derived
  by the same published `derive_tier` from `{ is_direct: false, is_publicly_discoverable:
  public, member_ceiling: space's ceiling }`. A private channel in a space of ≤ 2,000 is **T2,
  end-to-end encrypted, its own MLS group**. A public channel is T3. A space larger than
  2,000 cannot hold an encrypted channel at all, and the desktop client refuses to make one
  rather than hand back a readable space under a "private" label.
- **A channel's tier is immutable**, by the same structure that makes a room's immutable:
  there is no setter on `RoomSeal`, and the channel record holds **no tier field of its own**
  — the space reads the room's seal every time, so there is no second copy to edit. Renaming
  takes a name and nothing else, and its body refuses unknown fields. "Changing" a tier means
  deleting the channel and creating another, which mints a different room id with an empty
  history. Each client also records a channel's tier the first time it sees it, and its
  local index refuses the same channel at a different tier afterwards.

### Roles carry permission bits

Six bits, named in `cairn_proto::Permissions`:

| Bit | Grants |
|---|---|
| `read` | see a channel and its history |
| `send` | post into it (never without `read`) |
| `invite` | mint space invites |
| `kick` | remove a lower-ranked member, which also bars them from rejoining by invite |
| `manage_channels` | create, rename, delete channels; set their overrides and timers |
| `manage_roles` | create, edit, delete, assign, unassign lower-ranked roles |

`@everyone` holds `read | send` by default. A member's space-wide set is `@everyone` plus every
role they hold. The **owner** holds every bit, outranks every role, cannot be kicked, and is
exempt from channel overrides — a space whose owner a moderator could lock out of a channel
would have nobody left able to fix it.

**The hierarchy rule** is what stops escalation, and it has three clauses, all enforced in
`crates/cairn-server/src/state.rs`:

1. **Rank.** Each role has a position; a member's rank is their highest. An actor may only
   create, edit, delete, assign or unassign a role **strictly below** their own rank, and
   may only kick or re-role a member strictly below them (or re-role themselves). Equal is
   not below: two moderators cannot strip each other.
2. **No granting what you lack.** A role created, a role assigned, a bit added to an existing
   role or to `@everyone`, and a bit allowed by an override must all be within the actor's
   own permissions. Without this, `manage_roles` would be a way to pick up `kick` from a
   lower role someone else had defined.
3. **No managing what you cannot see.** Managing a channel requires being able to read it,
   so `manage_channels` cannot un-hide a private channel by editing the overrides that hid it.

### Per-channel overrides

Per channel, `@everyone` and any role may have an allow set and a deny set, touching **only
`read` and `send`**. Order follows Discord, because people arrive with Discord's intuition:
space-wide bits, then the `@everyone` override, then the union of the member's role overrides
(deny, then allow over it). With no `read` after that, `send` goes too. Space-wide powers
cannot be granted per channel; a `kick` that depended on which channel a request named would
be a rule nobody could reason about.

### One access check

A channel's room has **no member list of its own**. Every read and write path — messages,
attachments, the member list, the timer — asks one function, `Instance::room_access`, which
computes from the space on each request. The room-level membership calls (`add_room_member`,
`join_room`, room invites, room roles) refuse a channel with `ManagedBySpace`. Two lists that
could each admit someone would be two places to forget to remove them.

### Kicks

A kick removes the member from the space — and from every channel at once, because nothing
was copied — **bars** them from rejoining by invite until someone with `kick` lifts the bar,
and revokes the invites they minted. Leaving voluntarily bars nothing.

### Over HTTP

New routes in `crates/cairn-server/src/spaces_http.rs`, translation only. Every request is
signed over the space **and** the path's other targets (`cairn_proto::space_action`), so a
captured "assign role R to Bob" cannot be replayed inside the window as "assign R to
Mallory".

### Clients

`cairn-client-core` builds and signs the requests (`spaces.rs`) and assembles the session
calls a frontend makes (`session/spaces.rs`). **The instance decides every permission.** A
space's view arrives with the viewer's permissions and flags — `manageable`, `assignable`,
`roles_editable`, `can_send` — already computed by `state.rs`, and the UI draws them; a UI that
worked out the hierarchy would be a second copy of the rule that nobody tests. What the client
*does* decide is cryptographic: it founds each channel's MLS group, checks each listed tier
against the published rule (refusing, for example, an "encrypted" channel in a space whose
ceiling forbids one), and admits or removes people from a channel's group only as an
explicit action.

## What the instance can see, and what this does not protect

This is the section `CLAUDE.md` non-negotiable #3 exists for.

**Membership and roles are server-enforced metadata, and the instance sees all of it in the
clear:** the space's name, every channel's name, every role's name, bits and rank, who holds
which role, who is in the space, who was kicked and is barred, every override, and which
channels each member can read. It needs all of that to enforce anything. This is
`01-threat-model.md` §3.1 (metadata is conceded to the server) applied to a new structure, and
"membership lists" are an asset in §1 of that document precisely because they can out people.

What **is** protected is unchanged: in a T2 channel the instance stores MLS ciphertext and
cannot read the messages. Roles have no bearing on that.

### A malicious instance can fabricate roles and moderators

Because the instance holds the role table and enforces it on its own say-so, **a malicious
instance (A4) can make anyone a moderator, an owner, or nobody**: it can invent roles, assign
them, report a fabricated hierarchy to every client, honour requests the rules refuse, refuse
ones they allow, list channels as hidden or visible as it likes, and kick or un-kick anyone.
Nothing in this design detects it. Clients render the instance's flags, and no client can
verify that the person shown as a moderator was ever made one by the owner. A space's
permission structure is therefore **exactly as trustworthy as the instance operator** —
the same bound `01-threat-model.md` §3.7 already states for self-hosting.

What a fabricated role **cannot** do in an end-to-end encrypted channel is read it. Moving
someone into a channel's server-side reader list makes them "waiting", not a reader: the
MLS group only gains them when an existing member's client commits the Add, and that is an
explicit action a person takes (`admit_waiting`), never automatic. The worst a lying instance
achieves there is persuading a member to press the button — which is why the waiting list is
shown by account id, and why safety numbers matter.

### A kick is two things, and the instance does only one

The instance stops serving a kicked member every channel immediately. **It cannot take back
keys.** In a T2 channel the kicked device still holds the MLS group state until a member
commits its removal. Until then that device could read new messages if anyone handed it the
ciphertext — and the only party holding the ciphertext is the instance. So, until removal, a
kick holds against everyone **except** the instance. The client shows such accounts as
*unlisted* (in the encrypted group, no longer on the instance's list), and
`Session::remove_departed` commits their removal as an explicit action; after it, MLS
post-compromise security means the removed device cannot read what follows. This is not
automatic, for the mirrored reason that admitting is not: the list is the instance's word.

### Other limits, stated

- **A joiner learns a channel's tier from the instance.** A creator derives it locally from
  what it asked for; a member who did not create the channel can only check the instance's
  listing against the rule (and its own record of the channel, once it has one). An instance
  listing a T2 channel as T3 to a newcomer is caught only where the rule forbids it.
- **Request bodies are not signed**, as for every other endpoint; path targets are. TLS is
  what protects a body in transit (A1/A2).
- **Deleted channels keep their messages**, unreachable by anyone. They are evidence, as a
  removed member's messages are.
- **Space-wide powers cannot be scoped to a channel**, and there are no per-member overrides,
  only per-role. Both are deliberate simplifications, not oversights.
- **The desktop client creates private channels only**; T3 channels exist in the API.
- **Admitting each member to each channel's group is per channel and manual**. In a space of
  many channels that is real friction, and it is the price of never admitting on the
  instance's word.

## Decision on where roles live

**Owner, pre-launch: roles stay instance-held.** The alternative — carrying the role table
inside each channel's MLS group, so that a role change is a commit signed by someone the
group already accepts as entitled to make it — would let clients detect a fabricated
hierarchy and refuse it. It is also a change to what MLS commits carry and to how clients
validate them, which is `cairn-crypto` territory and exactly the kind of design this project's
record says not to self-review. It is **listed for the M5 external cryptographic review**
([`10-roadmap.md`](../10-roadmap.md)) and is not to be built before then.

## Probes, and what they showed

Written before trusting any of it, per `CLAUDE.md`. Each tried an attack and printed the
outcome; then each was kept as a property-named test and checked by **removing the rule it
defends and confirming it went red**.

- **A non-member reads a channel** — messages, attachments, the member list, the space
  view, the timer, and every room-level side door (`join_room` on a public channel, a room
  invite, `add_room_member` by the space's owner): all refused. Over HTTP too
  (`crates/cairn-server/tests/spaces_http.rs`).
- **A member without permission creates a channel or assigns a role**: refused, in-process
  and over HTTP.
- **Escalation**: taking a higher or equal role, building a role at or above your rank,
  lifting your own role, lifting a lower role past yourself, adding `kick` to a role or to
  `@everyone` without holding it, assigning a lower role that carries a bit you lack,
  overriding your own or a higher role, granting a non-channel bit by override, and kicking
  a peer of equal rank: all refused. A signed assignment replayed against a different member
  is refused (401).
- **A kicked member keeps access**: refused on every channel at once, including after a
  restart, and refused re-entry by their own hoarded invite or anyone else's.
- **A channel's tier gets changed**: no path found. Renames carrying `tier`, `public` or a
  ceiling are refused; plaintext into a T2 channel is refused; delete-and-recreate yields a
  different room and the old one keeps its seal.

**None of the attacks above succeeded against the first draft of the rules.** Running the
mutations is what found the gaps, and they were in the tests and in one place in the code:

- Two rules could be deleted without any test noticing. *No SEND without READ* was hidden by
  a second READ check in `room_access`, so the property was asserted at the source as well.
  *A refused change leaves the space as it was* was not load-bearing for refusals — none
  mutates before it refuses — so it was replaced by a test that makes **storage fail**.
- That test found a real fault in `kick_from_space`: it marked the kicked member's invites
  revoked **in memory before the write**, so a failed commit would have left them revoked
  until the next restart quietly un-revoked them. It now commits first and applies after.
- The full local CI run found one in the UI: `spaces.js` iterated whatever the space list
  returned, so an instance without spaces (a `null`) threw and **aborted sign-in** before
  link-preview settings loaded. The link-card browser test, whose stand-in knew nothing of
  spaces, went red; `an instance without spaces does not stop the rest of sign-in` now
  guards it, and fails with the fix removed.
- And `the_view_says_what_the_viewer_may_do_and_the_rules_agree` checks every `manageable`
  and `assignable` flag the UI draws against an actual attempt, because a flag that only
  approximated the rule would have the UI offering what the instance refuses.

End to end through real sessions (`crates/cairn-server/tests/spaces_session.rs`): a space, a
channel, two members invited and admitted to its MLS group, a conversation, a kick that the
kicked device sees as refusals everywhere, the kicked account listed as *unlisted* in the
roster, its leaf removed with `remove_departed`, and the remaining member told it left.

## Consequences

- Two new tables (`spaces`, `space_invites`) in the backup set; `every_table_is_included_in_a_backup`
  covers them.
- Rooms gain a `space` link, `default` so older rooms load as ordinary rooms.
- `01-threat-model.md` §4a records the new class of things a malicious instance can do, and
  `10-roadmap.md` M5 carries the review item.
- `state.rs`, `cairn-proto` and the membership paths are CODEOWNERS territory: this lands as a
  PR for the owner, not a self-merge.
