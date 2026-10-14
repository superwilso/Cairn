# ADR-010: Profiles travel inside the encrypted stream

**Status:** Accepted. **Implements [`13-customisation.md`](../13-customisation.md) §1's profile rows.**

## Context

Discord-level profiles — display name, pronouns, about me, avatar, banner, accent colours,
custom status, per-community nickname — are the most-used customisation there is. Discord
keeps them on its server. Doing the same here would hand the instance the thing an E2EE room
exists to keep from it: a name, a face and a bio chosen for the people in the room, often
more identifying than anything said in it.

## Decision

**A profile is a record a client sends into each room as an ordinary encrypted message.**
It rides in the MLS-encrypted body beside the text, like a reaction does
(`cairn_client_core::profile::Profile`, `Conversation::send_profile`). Avatar and banner are
**encrypted attachments uploaded to that room**, each sealed under its own single-use key,
the key inside the record. Recipients keep the latest record per member per room.

- **No field says whose profile it is.** It is filed under the envelope's sender, which the
  recipient checks against the group's own roster (below). A member cannot publish a profile
  "for" someone else.
- **Per room, not per account.** A nickname is sent only into its own room, and the images
  are uploaded per room because a room's blob store only serves its members.
- **Re-sent when someone joins.** A new member cannot read what was sent before the welcome,
  so every member re-sends after seeing the commit (the admitter after committing it). The
  images are not re-uploaded: the existing blob and key are re-sent.
- **Validated on both ends.** Lengths, one line for names, no control, invisible or bidi
  characters, no mixing of Latin with Cyrillic or Greek letters, nothing that passes for an
  account id. The receiver's check is the one that counts; a failing record is dropped whole.
- **A name is never an identity.** Names whose skeletons collide (case, spacing, fullwidth
  and a table of common Cyrillic/Greek/digit lookalikes folded) are both marked
  `ambiguous`, and a client shows 12 hex digits of the id beside them. Security UI — safety
  numbers, the verified mark, membership notices — shows ids, never names.

## What probing found

Building this needed "the envelope's sender" to mean something, so it was attacked first.
**It did not.** The instance verifies envelope signatures on the way in, and no client
checked them on the way out. A probe rewrote `sender` on a relayed envelope and the
recipient accepted it; over HTTP, through a proxy that relabelled mallory's envelopes as
alice's, bob displayed alice's profile as "Not Alice" and would have shown mallory's words
under alice's id. That is a malicious instance (A4) forging attribution, which
`01-threat-model.md` §4 said it could not do.

`Conversation::receive` now verifies every application envelope's signature under the
roster leaf whose credential names that exact account and device. The device key *is* the
leaf key, and the roster is the group's own state, so the instance cannot supply a key of
its choosing. `an_instance_cannot_relabel_one_members_profile_as_anothers` fails with the
check disabled.

## What this costs, plainly

- **Not private from the room.** Everyone in a room sees the profile sent to it; that is the
  point. Different rooms can be given different nicknames, not different names.
- **The instance learns that a profile changed** — a message of a typical size at a
  typical moment, plus a blob upload when an image changes. Not what changed.
- **A room this device never opens never hears about a change.** Sending is lazy, from the
  poll of the open room, so it happens at the group's current epoch. The desktop client only
  polls the open room.
- **Costs scale with the room.** Every member downloads every other member's images, so
  images are capped at 1 MiB and the client downscales (256² avatar, 960×340 banner).
- **Not reportable.** Like a reaction, the record rides beside an empty, franked body; a
  hostile name or bio can be screenshotted, not proven with franking.
- **Not removed by the disappearing-message timer.** A profile is state, not a message. It
  is dropped when this device is removed from the room.
- **Multi-device:** each device holds its own copy of "my profile"; the last one sent wins.
- **The lookalike check is a heuristic**, not Unicode TR39. Account ids are minted by
  clients, so even the 12-digit tag can be ground (2^48). The safety number is the check.
- **The ciphertext is not bound to the envelope's signer.** Binding them needs the sender
  leaf of the decrypted message, which `cairn_crypto::mls::GroupEvent::Application` does not
  expose. A member re-wrapping another member's ciphertext in their own envelope fails as an
  MLS replay when the original is delivered first; an instance colluding with that member
  could reorder them, attributing alice's words to mallory — or her profile, so that mallory
  wears alice's name and avatar (still flagged ambiguous, still under mallory's id). Closing it is a
  `cairn-crypto` change, left for the owner.
- **Older clients** decode a profile message as an empty one (as they do reactions).
