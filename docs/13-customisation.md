# Customisation, and why most of Nitro is free here

**Status:** Design. **Profiles are built** (§1a, [ADR-010](adr/010-encrypted-profiles.md)),
**custom emoji, stickers and the soundboard are built** (§3a) and §4's themes and §5's
protection are built in the desktop client (`clients/desktop/ui/settings.js`); a user's
personal emoji, plugins and the rest are not.

The question this answers: can Cairn match Discord's customisation, and give away what Nitro
charges for? Mostly yes — and the reason is not generosity. **Most of Nitro is artificial
scarcity.** It is a server-side limit Discord chose in order to sell removing it, and on an
instance you run yourself there is nothing to remove.

That is the easy half. The useful half of this document is the part where "free" is not
free, because there are three categories where the honest answer is different, and one
hazard that would quietly break a non-negotiable.

---

## 1. Free by construction

These cost an operator nothing meaningful and should never be gated:

| Nitro feature | Why it is free here |
|---|---|
| Longer messages (2,000 → 4,000 chars) | A constant in the code. There is no cost being recovered |
| Custom themes, app icons | Pure client-side presentation; the server is not involved at all |
| Profile banners, bios, animated avatars, avatar decorations | Small static assets, fetched once and cached |
| Per-community profiles | A row keyed by (account, community). No new machinery |
| Custom emoji and stickers | Small assets — but see §3, the design is not the obvious one |
| Soundboard | Same shape as emoji, same caveat |
| Custom badges | Cosmetic metadata |

**None of this needs a subscription tier, and there should not be one.** `00-vision.md` §4
already forbids ads and message-content-derived monetization; charging to raise a limit the
operator is not actually paying for would be the same instinct wearing a different hat.

## 1a. Profiles, built so the instance never sees them

"A row keyed by (account, community)" above is the Discord shape, and it would put every
name, bio and face on the instance. What is built instead ([ADR-010](adr/010-encrypted-profiles.md)):

- Display name, pronouns, about me (190 characters, 8 lines), avatar, banner, a two-colour
  banner gradient, a custom status (emoji, text, optional expiry) and a **per-room nickname**.
- The profile is a **record inside the encrypted message stream**, sent into each room; the
  images are **encrypted attachments** in that room's blob store, keys inside the record.
  The instance relays ciphertext and stores ciphertext.
- It is attributed to the envelope's sender — the record names nobody — and the recipient
  checks that sender against the group's roster. Building this found that no client did,
  and that a malicious instance could relabel anyone's messages; see the ADR.
- Names are sanitised on both ends and **lookalike names are flagged, not trusted**: two
  members whose names collide are both shown with part of their id. Safety numbers, the
  verified mark and membership notices show ids, never names. A name is a label.
- A nickname reaches only its own room. A profile change reaches a room the next time this
  device has it open.

Discord's per-server *avatar* and animated decorations are not built; a GIF avatar is
carried as-is, so it animates.

## 2. Where "free" means someone else's bill

Two Nitro features are not artificial scarcity. They are the ones that cost real money:

- **Large file uploads.** Storage plus egress, every time anyone downloads.
- **HD and 4K streaming.** See [`12-realtime-media.md`](12-realtime-media.md) §10 — an SFU's
  egress scales with the square of the participant count, and screen share is the worst case.

On a self-hosted instance, "unlimited uploads for free" means *your friend who runs the
server* pays for it, and they will find out when the bill arrives. So the design is
**operator-set limits with conservative defaults**, which is what `08-feature-parity.md`
already says for file size, and the UI should be honest that the limit is the instance's
choice rather than a paywall.

That leaves the question of **how a flagship instance funds itself.** Ads and content-derived monetization are out permanently, and
non-negotiable #5 says the flagship gets no protocol privileges a self-hosted instance
cannot have — but resource limits are not protocol privileges, so a funded flagship with
higher upload ceilings does not violate it. Donations, paid hosting, and paid-tier
*capacity* (never features, never protocol) are all consistent with the rules as written.
**DECIDED (owner): a flagship instance may fund itself, because using it is optional.**
Nobody is obliged to use the flagship — the software is self-hostable and a Raspberry Pi in
a spare room is a legitimate deployment (`11-self-hosting.md` §7). That is what makes paid
*capacity* on the flagship acceptable where it would not be in a product people are locked
into: the alternative is not "pay", it is "run your own", and that alternative is real.

The limits that stay fixed regardless: no ads, no content-derived revenue, and no protocol
privilege the flagship holds that a self-hosted instance cannot. Capacity is not a protocol
privilege. A feature gated behind payment would be.

## 3. Custom emoji is a content oracle if built the obvious way

This is the part that is genuinely different in an E2EE product, and it is not obvious.

On Discord, a custom emoji in a message is a reference the client resolves by fetching
`.../emojis/12345.webp` when it renders. Copy that design into a T1 or T2 room and the
server learns **which emoji you used and when** — from the fetch, not from the ciphertext it
cannot read. The message body stays encrypted and the decoration leaks anyway.

It is worse than it first looks, for two reasons:

- A rare custom emoji is close to a **fingerprint**. "Who fetched `:blobsad:` within 200ms
  of message 4471" identifies a reader, and reactions make it worse, since a reaction is a
  much smaller set of possible values than a message.
- It is a **side channel that survives everything else being right**. The tier badge is
  honest, MLS is working, franking is intact — and the server still learns a usable signal
  about content, which is exactly the shape of failure `01-threat-model.md` §3 does not
  concede.

**The fix is to decouple fetching from rendering.** A client joining a community downloads
that community's whole emoji, sticker and soundboard set up front, and renders locally
thereafter. Fetching the set says only "I joined this community", which the server already
knows because it holds the membership. Nothing is fetched at render time, so nothing
correlates to a message.

Consequences worth stating before anyone builds it:

- Sets need a size ceiling, since every member downloads all of it.
- Updates need to arrive as a set, not per-emoji on first use — a lazily fetched *new*
  emoji reintroduces the exact leak.
- A **user's personal** emoji used in a DM has no set to hide in. Either carry it inside the
  encrypted envelope as an attachment, or accept the leak and say so. Leaning: carry it,
  since DMs are the tier where the claim is strongest.
- Attachments are the prerequisite either way, so this sits behind
  [ADR-007](adr/007-server-storage.md)'s successor work.

## 3a. As built: room emoji, stickers and soundboard

The fix above, implemented (`cairn_client_core::custom`, `session/custom.rs`; desktop
`emoji.js`, `customise.js`, `soundboard.js`).

- **A room's set is one record inside the MLS-encrypted stream**, like a profile. Each image
  or clip is an encrypted attachment in the room's blob store under its own single-use key,
  the key inside the record. The instance stores ciphertext and relays ciphertext; it never
  sees a name, a type or an image (`the_instance_stores_no_emoji_name_or_image_in_plaintext`).
- **Fetched whole, when it changes.** A device that accepts a new set downloads every asset
  it lacks at once, used or not. Drawing a custom emoji, a reaction, a sticker or the picker
  reads the local cache by the id the set gave it; that path has no network call in it
  (`drawing_a_custom_emoji_makes_no_request`, through a request-counting proxy; the browser
  test counts one read per image however many messages use it). An emoji not yet downloaded
  is shown as its `:name:`, never fetched on demand.
- **Messages refer by name.** `:party_parrot:` in text is ordinary text, encrypted like the
  rest. A reaction may be `:name:` — the only ASCII reaction allowed — and one outside the
  room's set is drawn as a placeholder, not words. A sticker is a message whose franked body
  is `:name:`, so it stays reportable and older clients show the name.
- **Limits** — every member downloads all of it, so: 100 emoji at 256 KiB, 40 stickers at
  512 KiB, 24 sounds at 512 KiB and five seconds, 16 MiB for the whole set. PNG, GIF and WebP
  images; Ogg/Opus, MP3 and WAV clips. Names are `[a-z0-9_]`, 2–32 characters, so a name
  cannot be a lookalike. Types are sniffed from the bytes, before upload and again after
  every download. Clip length is measured by Rust for WAV and Ogg and by the uploading UI for
  MP3, and every client stops a clip at five seconds whatever the file says.
- **Who may change it.** Only an account the **instance's member list** names as `owner` or
  `moderator`; every recipient checks the envelope's sender (already verified against the
  group's roster) against that list, because the instance cannot read the set to refuse it.
  Roles are read when a room opens and then every ten seconds, never because a set arrived —
  a request triggered by a set would mark which message was one. A set from a sender not yet
  known to be permitted is held until the next read of roles and then applied or dropped,
  so a set a plain member sent cannot come into force later on an unrelated promotion. The
  probe: a member whose client was told (by a lying proxy) that it was the owner sent a set;
  every other member ignored it (`a_plain_members_set_is_ignored_by_everyone_else`, which
  fails with the check removed).
- **A new member gets the set** from any owner or moderator device that holds it, re-sent
  after the commit that added them — the uploaded blobs are reused, not uploaded again.

What this costs, plainly:

- **Roles are the instance's word.** They are instance state, not part of the encrypted
  group, so **a malicious instance (A4) can let a member of its choosing change a room's
  set**, by listing them as a moderator. It cannot write a set itself, read one, or learn a
  name. Binding roles into the group is a `cairn-crypto` change, left for the owner.
- **A demotion takes up to ten seconds** to reach a device with the room open, during which
  a set from the demoted account is still accepted.
- **The instance learns that the set changed** — a message, uploads, and every member
  downloading those blobs shortly after. Not what changed, and nothing when one is used.
- **A room with no owner or moderator online** cannot give a new member its set until one
  opens the room. Members cannot pass it on, because the record names no author they could
  vouch for.
- **A user's personal emoji in a DM** (the third consequence above) is not built.

### The soundboard

A clip goes out on **its own audio track**, separate from the microphone, and plays locally
at the same level. In a rung call that is a second audio line per peer, negotiated up front
beside the empty video line (`CairnCall.playClip`); in a voice channel it is a second track
to the SFU (`CairnVoiceChannel.playClip`), sealed end to end like the voice and marked as a
clip by a flag *inside* the seal. There is no "play X" message. Muting still mutes, and a
muted participant cannot play a clip. (Decided by the owner over the earlier design, which
mixed clips into the microphone.)

**What each listener controls, on their own device only:** a per-person soundboard volume and
"mute their soundboard" in the same popover as that person's voice volume, and **"Mute
everyone's soundboard clips"** in Settings → Voice & video. None of it is sent anywhere; the
person is not told. The slider in the soundboard panel is the sender's: how loud their clips
go out. A listener knows which incoming track is a soundboard from the call's own structure —
the second audio line in the mesh, the sealed flag in an end-to-end voice channel — so in an
E2EE voice channel the SFU cannot pass a voice off as a clip or the reverse.

**What this costs: whoever carries the media can tell when a clip is playing.** The clip's
track is silent between clips and carries audio while one plays, so its packet activity and
timing show each moment someone presses a soundboard button — and for how long. In a voice
channel that is **the instance's SFU**, for every participant; in a rung call it is only
the other participants' devices, plus the operator's TURN relay when a call goes through
one. What they cannot tell, in an end-to-end call, is *which* clip: the audio is sealed like
the voice. Under the earlier mixed design the instance learned nothing it did not already
see from the voice.

Tested between two real browsers (`soundboard.browser.test.js`): the clip arrives on the
soundboard track and not in the voice; muting the sender's soundboard silences what the
listener's device plays for it while the sender's voice keeps arriving; "mute everyone's"
does the same; no signal is sent. And through the real SFU (`voicechannel.browser.test.js`):
every soundboard frame the SFU held was sealed, opens under the sender's key in Rust, and
carries the clip flag; muting it leaves the voice slot playing.

## 4. Themes yes, plugins are a different question

Open source can genuinely beat Discord here. BetterDiscord exists because people want
client theming badly enough to run an unsupported patcher that breaks on every update and
violates the ToS. Cairn can just support it.

But **theming and plugins are not the same risk**, and lumping them together would be a
mistake:

- **Themes** — colours, spacing, fonts, backgrounds — are declarative presentation. Safe,
  and should be first-class.
- **Plugins** run code inside a client that holds group keys and plaintext. That is the bots
  question from `01-threat-model.md` §10.4 wearing an even friendlier face: not a member of
  the room with its own keys, but code inside *your* client with *your* keys. If plugins
  ever ship, they need a permission model, and the answer cannot be "it is open source, read
  the code".

**Nothing here goes below the FFI line.** Per ADR-006 a customisation layer must never
construct an envelope, decide a tier, or touch a key — it decorates what `client-core`
already produced.

## 5. The hazard: a theme must never be able to lie about encryption

The one that would quietly break a non-negotiable.

`02-encryption-tiers.md` UI rule 8 requires the tier badge to be derived locally and always
visible, and the client already refuses to show a clean badge over `http://` because that
would claim a protection that does not exist. A theming system powerful enough to restyle
the whole interface is powerful enough to **restyle the badge** — to hide
`plaintext-transport`, or to make a T3 room look end-to-end encrypted.

That is not a hypothetical abuse by a malicious theme author; a careless theme that sets a
uniform background could do it by accident.

So: **the tier badge, the safety-number state, and membership warnings are outside theming
control.** Not "themes are discouraged from restyling them" — structurally unreachable, the
same way the tier has no setter. A customisation system that can repaint the security
indicators has made those indicators worthless, and per non-negotiable #3 an indicator that
can lie is worse than no indicator.

**As built (desktop client).** Three layers, and the limit of the third stated plainly:

1. Themes are data — hex colour tokens and enumerated choices, validated key by key on
   import. A theme cannot carry a selector, and the indicators take no colour from tokens.
2. The indicators' rules live in the first-declared CSS cascade layer with every
   declaration `!important`; for important declarations the earliest layer beats every
   later layer and all unlayered CSS, so no theme or user CSS can restyle the badge element.
   User CSS that declares or joins a layer is refused, checked by the browser's own parser.
3. User CSS can still act on an ancestor or paint over a badge. A tripwire measures each
   indicator (visibility, size, ancestor opacity and filters, the colours the layer paints,
   and a hit-test at its centre) and switches user CSS off when one fails. That is a check of
   what the page can measure, not structural: an overlay with `pointer-events: none` is
   invisible to hit-testing. Regression tests: `clients/desktop/tests/settings.browser.test.js`.

## 6. What this is worth

Discord charges roughly $10/month for a bundle that is mostly configuration. Cairn gives it
away because it has nothing to protect: no ads, no content-derived revenue, and an operator
who sets their own limits. That is a real, defensible marketing claim — the *only* one on
this page that costs nothing to keep.

The two things that must not be over-claimed alongside it: uploads and streaming are bounded
by whoever pays for the server, and custom emoji is free **only** if it is built as a set
download rather than a per-message fetch.
