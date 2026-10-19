# Voice, video, and screen sharing

**Status:** Design, with **two rungs of it now shipped** — the mesh (§0) and drop-in voice
channels through an SFU (§0a, [ADR-012](adr/012-sfu-voice-channels.md)). Still design: the
per-call MLS group (§1–§3), SFrame proper, video through the SFU.

Discord's voice channels are, along with its bot ecosystem, the reason communities stay on
Discord. `08-feature-parity.md` §2 lists drop-in voice channels and screen share as v2
targets and says nothing about how either works. This document fills that in, because the
gap between "add WebRTC" and what this actually costs is the largest in the project, and
one of the design choices here is forced by a non-negotiable rather than a preference.

The reference design is Discord's own: **DAVE**, their Audio & Video End-to-End Encryption
protocol, published as a whitepaper with an accompanying Trail of Bits audit. It is the
closest thing to prior art that exists — an MLS-keyed, SFU-compatible E2EE media stack
shipped to a community-messaging product at scale. Most of what follows either adopts it or
says precisely why Cairn diverges.

---

## 0. What is actually built

`clients/desktop` makes voice, video and screen-sharing calls today. It is **not** the design
below; it is the rung underneath, and the distinction matters because a reader who takes this
document as a description of the product would credit the client with protections it does not
have.

| | Built (mesh, a call you ring) | Built (voice channel, §0a) | Designed (§2–§4) |
|---|---|---|---|
| Topology | **Mesh**, capped at 6 | **SFU** in `cairn-server`, 16 per channel, audio only | SFU |
| Media encryption | **DTLS-SRTP**, hop-free — peer to peer | DTLS-SRTP to the SFU **plus** frames sealed end to end (`cairn_crypto::media`) | SFrame over an MLS-derived key |
| Call keying | **None of its own** | Per-sender keys from the **room's** MLS group exporter, rotated per epoch | A per-call MLS group, rotated on removal |
| Signalling | **Inside the encrypted message body** | SDP offer to the instance over signed HTTP (it is the far end) | The same as the mesh |
| Media path | **Never touches the instance** | Through the SFU, which forwards ciphertext | Through the SFU, which cannot read it |

What the two share is the property that mattered most: the instance sees ciphertext. In the
mesh it never sees the media at all, and the SDP handshake rides inside the encrypted body
rather than beside it — an offer names the sender's codecs, ICE candidates and addresses, and
the instance has no use for any of it. `crates/cairn-server/tests/group_chat_session.rs` reads
what the instance actually stored and asserts the SDP is not in it.

What the mesh does not have:

- **No SFU**, so nothing to deploy and nothing for an operator to pay for — but every
  participant uploads their stream once *per other participant*. `MAX_MESH_PARTICIPANTS` is
  six, which is where refusing beats degrading and blaming the network.
- **No SFrame and no call MLS group.** Media is protected by DTLS-SRTP between the two peers,
  which is end-to-end *because there is no middle*, not because of anything Cairn built.
  Adding an SFU is exactly what makes §4 necessary.
- **No downgrade badge** (§5) in the mesh. Nothing there can downgrade, because there is
  only one mode. Voice channels have one; see §0a.
- **A TURN relay only if the operator runs one.** An instance configured with
  `CAIRN_TURN_URLS` and `CAIRN_TURN_SECRET` (`11-self-hosting.md` §2) hands short-lived
  coturn REST-auth credentials to authenticated members of the room a call is in; anyone
  else is refused without learning whether a relay exists. Without one, traversal is
  STUN-only and fails on some home networks, and the client says so rather than leaving a
  user to conclude their connection is broken.
- **Every participant learns every other participant's IP address** — unless they switch on
  *Always use the relay* (Settings → Voice & video), which sets `iceTransportPolicy: "relay"`
  so the browser offers relay candidates only. Then the other participants see the relay's
  address, and **the relay's operator sees theirs** instead, which the setting says. On an
  instance with no relay it refuses to start a call rather than hang. This is the reverse of
  §10's recommendation, which is to relay by default: that needs every instance to run a
  relay, and until a default can rely on one, direct is the default and the relay is a
  per-person choice. That decision is open, not settled.
- **Ringing reaches the room you have open, and nowhere else.** The client polls the open
  room only, so a call started in another room does not ring until you open it. A ring
  lasts 45 seconds and then becomes a missed call; declining sends an encrypted `decline`
  addressed to whoever rang, so the instance learns that a message went to the room and not
  what it said.
- **A call has no roster of its own**, so it cannot tell a participant from a room member who
  is merely nearby. In the window between joining and the first offer, any member of the room
  can rename a device's call and split the call in two, each half waiting for answers the
  other will never send. It buys an attacker nothing — they are already in the room and could
  disrupt a call by joining it — but the failure is silent and looks like a network fault, so
  it is written down rather than left to be discovered. §2's per-call MLS group is what
  supplies the roster that closes it.

**Mute, deafen and push-to-talk never reach the instance.** Whether someone is muted or
deafened travels on a WebRTC data channel per peer connection — DTLS between the two devices,
like the media — rather than as a signal through the room, which would have given the
instance a timestamped log of every mute. Push-to-talk is not signalled at all, and it works
only while the Cairn window is focused: a webview cannot see keys pressed in other apps, and
the client says so. What the instance's view of a call does not change: per §6, packet
timing still shows who speaks to anyone on the media path — which, in the mesh, is the other
participants and, with a relay, its operator.

Per-person volume (0–200%) and "mute for me" are this device's alone, stored locally, and the
person is not told. Noise suppression, echo cancellation and automatic gain are the webview's
own `getUserMedia` processing, switchable in the same settings section.

Four layers of test cover it, because each catches what the others cannot: the transport in
`group_chat_session.rs` (and the relay credentials over HTTP in `turn_http.rs`), the mesh's
decisions against a fake `RTCPeerConnection` in `clients/desktop/tests/mesh.test.js`, a real
call between two Chromium pages in `call.browser.test.js`, and the same in the whole UI in
`calls.browser.test.js` — ring and accept, decline, mute crossing to the other side and not
through the instance, the speaking ring, push-to-talk, and relay-only offering no address of
the device's own. The third found a bug nothing else could: a transceiver the answering side
pre-created that a remote offer will not reuse, which left every call reporting "connected"
while carrying video in one direction only.

---

## 0a. Voice channels, as built

A voice channel is a call attached to a room that people drop into and out of; nobody is
rung. It is shown in the sidebar under the room list, with who is in it, and it goes
through an SFU the instance runs (`CAIRN_SFU_BIND`, `11-self-hosting.md` §2a). The decision
and its alternatives are [ADR-012](adr/012-sfu-voice-channels.md); this is the state of it.

**The switchover rule.** A call somebody rings is a mesh call; a voice channel is an SFU
call. Nothing moves a live call between them. An instance with no SFU shows no voice channel.

**What protects the audio.** In an E2EE room each device seals every Opus frame in its
webview — an `RTCRtpScriptTransform` worker, or Chromium's `createEncodedStreams` — with
AES-128-GCM under a per-sender key `cairn-client-core` exports from the room's MLS group for
the current epoch. The webview receives those keys from the `voice_keys` command as raw bytes
once per epoch and imports them non-extractable; it never derives one, picks an epoch, or
decides whether to encrypt. A receiver picks the key by the frame's trailer, so attribution is
by key, not by the SFU's slot mapping. In an end-to-end call a frame that does not open is
dropped — including plaintext the SFU might inject.

**What the SFU sees**: who is connected, from which address, when; per-sender packet sizes
and timing, which show who is speaking; the SDP offer; each frame's epoch and leaf. Not the
`ssrc-audio-level` header — the SFU's answer leaves it out, so browsers do not send a loudness
value in the clear.

**The §5 fallback, as built.** A device whose webview cannot transform frames announces
`transport_only` inside the room's encryption when it joins; every capable device announces
`e2ee`. `Session::voice_state` makes the call transport-only exactly while a connected
participant has *announced* transport-only, so **the instance cannot force a downgrade** —
it cannot forge the announcement, and suppressing one only means the fallback device's
plaintext is dropped. The call carries its own badge (*End-to-end* / *Transport only*) beside
the room's unchanged tier badge; everyone in the call gets a notice in the panel and the
timeline naming who caused it, and another when it returns to end to end. Anyone may set
*Settings → Voice & video → Leave a voice channel that stops being end-to-end encrypted*.

**Who may be in it** is `state.rs`'s rule: room members only, one seat per device, 16 per
channel. The SFU asks the registry before every forward and closes any connection whose seat
has gone, and removal from the room evicts the seat. **Found by probing:** as first written,
removing a member left their seat — and the SFU's forwarding — in place.

**Not done.** The per-call MLS group (§1–§3), so the roster of who is *in the channel* is the
instance's word — the client marks any listed device the room's group does not contain, but
cannot prove who is listening; removal is immediate at the SFU and only eventual in the
cryptography (until the removal commit, old-epoch keys still open frames). SFrame (RFC 9605)
itself — the format is SFrame-shaped, not SFrame. Video and screen share through the SFU. A
TURN relay in front of the SFU's UDP port. A voice channel in a room you do not have open:
switching rooms leaves it, because the client polls the open room only. Per-person volume
and the speaking ring in voice channels (the mesh has both).

**Tests.** `cairn-crypto` pins the frame format with a vector Node's WebCrypto produced, and
re-runs §2's exporter premises as `voice_media_keys_agree_across_members_and_rotate_when_someone_is_removed`.
`state.rs` and `crates/cairn-server/tests/voice_sfu.rs` attack the rules over real HTTP and
real WebRTC (str0m clients): a non-member joining, media crossing between rooms, a removed
member still connected, the clear audio-level header. `clients/desktop/tests/mediaframe.test.js`
checks the JavaScript against the Rust vector, `voicepanel.browser.test.js` the panel and
badges, and `voicechannel.browser.test.js` real Chromium pages through the real SFU with real
sessions: audio arrives, every frame the SFU held is sealed and opens in Rust, the fallback is
announced to everyone and leaves the SFU holding plaintext (the counterfactual), and a removed
member is dropped.

---

## 1. Calls are not the room

The first thing that falls out of the design, and the thing most likely to be got wrong by
someone reasoning from the messaging code: **the set of people in a call is not the set of
people in the room**, and it changes on a timescale of seconds rather than days.

The room's MLS group therefore cannot be the call's group. A call needs its own MLS group,
created when the call starts, whose membership is the participants, and which is discarded
when the call ends. Discord does exactly this — one MLS group per media session. Cairn
would have two group lifecycles where it has one today.

This is not a large cryptographic change; `cairn-crypto`'s `Session` already creates and
joins groups. It is a large *state* change, because the server becomes responsible for a
second kind of ordering (§3), and because the client holds two live MLS groups whose
membership sets overlap but are not equal.

## 2. MLS gives us the call key, and removal rotates it

MLS's exporter is the mechanism. Both DAVE and the design here derive a per-sender media
key from the group's exported secret, using the sender's id as the exporter context so each
sender's key is distinct.

This was probed against the `mls-rs` version the project already depends on, rather than
assumed from the RFC. Exporting with label `"Cairn media key v0"` and the sender's identity
as context, across an Alice/Bob group that Mallory joins and is then removed from:

```
epoch a=1 b=1
alice-for-alice   a5c5bfe0154c0d4b55f7ce1617e5fb41
bob-for-alice     a5c5bfe0154c0d4b55f7ce1617e5fb41   <- same key, different member
alice-for-bob     e6618ff251210635973a523b0aba2f85   <- different context, different key
--- after adding mallory, epoch 2
alice-for-alice   dceb9704fd6abe1193ec2867a8de9936   <- epoch change rotated it
mallory-for-alice dceb9704fd6abe1193ec2867a8de9936
--- after removing mallory, epoch 3
alice-for-alice   79aebb2af3257df979bb8ed8d57f7818
bob-for-alice     79aebb2af3257df979bb8ed8d57f7818
mallory-for-alice dceb9704fd6abe1193ec2867a8de9936   <- stuck at epoch 2
mallory epoch 2 vs alice 3
```

Four premises confirmed: every member derives the same key, distinct contexts give distinct
keys, an epoch change rotates them, and a removed member is left at her old epoch and cannot
derive the new one.

**The last line is also the limitation.** Mallory still holds epoch 2's key. Removing her
does not retract media already sent, and it does not stop a sender who has not yet processed
the removal commit from producing frames she can still read. The gap is bounded by how fast
the commit reaches every sender; Discord bounds it explicitly with a transition timeout of
about two seconds and moves on without stragglers. Any Cairn implementation needs the same
bound, and the UI should not imply that "remove" is instantaneous.

The probe was deleted rather than kept, per the project's method — it found no defect, only
confirmed premises this document now depends on. Re-run it as a named regression test at the
point the feature is actually built, because at that point there will be production code
that a refactor can break.

## 3. The server becomes a sequencer

MLS requires strictly ordered, append-only group changes. Two people leaving a call at the
same moment produce two commits from the same epoch, and exactly one can win.

For messaging this is already solved: Cairn's server orders envelopes, and membership
changes are rare enough that a loser can simply retry. For a call it is not, because joins
and leaves race constantly and a retry storm is audible. Discord's voice gateway resolves
this by picking a winning commit and announcing a transition, having every client confirm it
is ready, and only then executing the switch to new keys.

This is the same requirement that keeps Matrix's MLS work (MSC4244) tied to a designated hub
server per room, and it is one of the places where **ADR-003 pays off**: an islands-first
design already has exactly one authority per room, so the sequencer role is available for
free. A federated design would have had to invent it.

## 4. SFrame, not MLS, encrypts the media

MLS supplies the key. It does not supply a frame format that survives a media server, and
this is the part that surprises people: an SFU has to read enough of each packet to do its
job — forwarding decisions, congestion feedback, codec-specific packetisation — so media
cannot simply be an opaque blob.

The standard answer is **SFrame (RFC 9605)**, published August 2024: two layers, hop-by-hop
SRTP between endpoint and SFU, end-to-end SFrame inside it, with codec headers left legible
so forwarding still works. DAVE uses the same shape via WebRTC encoded transforms.

Two consequences worth writing down before anyone implements this:

- **The unencrypted headers are attack surface.** The Trail of Bits audit of DAVE found
  exactly this: unauthenticated metadata ranges that a network attacker could modify to crash
  receivers, and an SFU able to inject synthesised silence packets because it is not a member
  of the E2EE group. Neither breaks confidentiality. Both are real, and both are the kind of
  thing that gets discovered after shipping if nobody wrote it down first.
- **AES-GCM is not key-committing.** The same audit flagged it. The project already knows
  this shape of problem — `04-safety-architecture.md` builds franking on committing AEAD for
  the same reason. Whatever Cairn does here should not quietly be weaker than what it does
  for messages.

## 5. The downgrade path, and what replaced the refusal

DAVE describes a **passthrough mode**: when a participant's client does not support E2EE,
the session transitions to protocol version 0, frames flow unencrypted, and clients display
the changed status. It is a sensible answer to a rollout problem across a fleet of clients
Discord does not control.

**Superseded (owner decision).** This section previously said Cairn would refuse rather
than downgrade. The refusal has been dropped, because "your friend cannot join, tell them to
update" is a worse product than a call that works and says what it is.

**A call may fall back to transport-only encryption.** What may *not* happen is the fallback
going unannounced.

The rule that replaces the refusal is narrower and, unlike the old one, costs nothing in
compatibility:

- **A call carries its own badge, derived from the call, not from the room.** A T1 room whose
  call fell back shows an E2EE room containing a transport-only call, and says exactly that.
  The room's tier is still immutable; the call is simply a different thing with its own
  protection, and conflating them is what would have made the badge lie.
- **The fallback is announced to every participant when it happens**, not only to the person
  who caused it. Somebody joining on an old build changes what protects everyone else's
  audio, and everyone else is entitled to know before they keep talking.
- **Anyone may decline.** A participant whose client would rather leave than continue on
  transport-only can be configured to do so. What is gone is the rule that made that
  everyone's behaviour by default.

This keeps non-negotiable #3 intact — nothing claims a protection it does not have — while
giving up the part of #1 that was doing more harm than good in a pre-launch product. Note
what is *not* given up: a room's tier still cannot be changed, and a T1 room's **messages**
are still E2EE regardless of what its calls do.

T3 public communities are unaffected — they are transport-encrypted by design, so a T3 voice
channel always was, and the badge already said so.

## 6. What a call still leaks

Per non-negotiable #3, this belongs next to the design and not in a footnote. Even with
SFrame working perfectly, the instance sees:

- **Who is in a call, with whom, when, and for how long.** Consistent with
  `01-threat-model.md` §3.1, which already concedes metadata — but a call is a much sharper
  signal than a message, because it is continuous and it implies both parties are present.
- **Who is speaking.** Packet timing and size track voice activity closely enough that
  turn-taking is visible to the SFU without decrypting anything. Constant-bitrate padding
  would blunt this and costs bandwidth; nobody in this class of product does it.
- **Codec-level frame headers**, per §4.

A drop-in voice channel is worse still: its occupancy is continuously known to the server and
displayed to the room, by design. That is the feature. It is worth naming because
`10-roadmap.md` declined typing indicators and read receipts specifically for broadcasting
presence continuously, and a voice channel does far more of it. The distinction that makes
this consistent rather than hypocritical: joining a voice channel is a deliberate act the
user takes, and the occupancy list is visible to the user too. A typing indicator is
involuntary and asymmetric.

**The call UI must not display a stronger claim than the message UI.** Same badge, same
derivation, same rule that it comes from the local tier and never from the server
(`02-encryption-tiers.md` UI rule 8).

## 7. Calls cannot be reported, and we should say so now

`04-safety-architecture.md` is built on transcript franking: a recipient can prove what was
said, with causality, without the server reading anything. **There is no equivalent for live
media**, and pretending otherwise later would be much worse than admitting it now.

The reasons are structural, not implementation gaps. There is no server-held commitment to a
stream nobody stored. A recipient-side recording is defeated trivially by an abuser who
stops when recording starts, and building always-on call recording into the client would be a
far larger privacy hazard than the abuse it documents. Discord now has this same problem for
exactly the same reason.

So calls in E2EE tiers get **block, leave, and account-level ban**, and no content report.
That is a real reduction in what the safety stack covers, it should be stated in
`04-safety-architecture.md` when this is scheduled, and it is an argument for keeping
account-level and instance-level bans strong — the subscribable policy lists in §2 of that
document are the mechanism that still works when content reporting does not.

## 8. Screen sharing

Technically it is another video track and needs no new cryptography. Everything interesting
about it is elsewhere.

- **It is the most expensive stream.** Screen share is high-resolution and, for anything
  scrolling or animated, high-bitrate. It is what turns a self-hosted instance's bandwidth
  bill from an afterthought into the binding constraint (§10).
- **It is the feature most likely to leak something the user did not intend** — a
  notification popping up mid-share, a second window, a password manager, a terminal with a
  token in scrollback. The mitigations are UI, not protocol: default to **window-scoped
  capture** rather than whole-screen, show a preview of what is about to be shared before it
  goes out, and keep an unmissable indicator running for the duration.
- **It interacts with the linked-account work.** `05-embeds.md` goes to some trouble to keep
  a linked account's session off the wire. A user screen-sharing that same logged-in session
  hands the room whatever is on it. Nothing to enforce here — just a reason not to describe
  linked accounts as "contained" once screen sharing exists.

## 9. Why this comes after the native clients

**Reachable now.** [ADR-008](adr/008-client-architecture.md) replaced five native clients
with one web client wrapped in Tauri, which means WebRTC supplies capture, echo cancellation,
jitter buffering, codec negotiation and simulcast rather than this project writing them five
times. That removes most of what made this "the largest component the project has
considered". What remains genuinely ours is the SFU choice, the MLS call group, and SFrame.

The CLI still cannot do this. Not "would be awkward" — an SFU-connected media client needs device
capture, echo cancellation, jitter buffering, and a rendering surface, none of which is a
terminal.

Per ADR-006 everything protocol-shaped lives below the FFI line, and that holds here: the
MLS group, the exporter-derived keys, and the SFrame layer belong in `cairn-crypto` and
`cairn-client-core`. But the media plumbing genuinely is platform work, and it is the first
feature where the native clients are a hard prerequisite rather than a quality bar.

The sequencing is therefore: storage (ADR-007) → attachments → native clients → **this**.
It is a v2 item at the earliest, and it is honestly the largest single component the project
has considered — larger than the server.

**Overtaken by events, and worth recording why.** The mesh in §0 shipped without any of that
sequence, because dropping the SFU drops nearly all of it: no server component, no SFrame, no
call MLS group, no simulcast. What is left is signalling and `RTCPeerConnection`, and the
browser supplies the second. That is not an argument against the design below — six
participants is a real ceiling and the reason an SFU exists — but it does mean the
prerequisite chain was for the *SFU*, not for calls.

## 10. What it costs a self-hoster

This is the finding most likely to change someone's mind about running an instance, so it
belongs in `11-self-hosting.md` before the feature ships, not after.

Messaging is cheap: a few hundred people exchanging text is negligible bandwidth. An SFU is
not. It forwards each sender's stream to every other participant, so egress scales with
N×(N−1). Five people on 720p video at roughly 1.5 Mbps each is about 7.5 Mbps in and
**30 Mbps out** — sustained, for one call. On a home connection that is the whole upstream
link, and screen share is worse.

Two mitigations, both with costs:

- **1:1 calls can skip the SFU entirely** via peer-to-peer WebRTC, which is free for the
  operator. But ICE hands each peer the other's IP address, so a call from someone you do not
  know becomes an IP disclosure. Signal relays through its own servers by default for exactly
  this reason. Cairn should **relay by default and make P2P an explicit opt-in**, which means
  the cheap path is the one users have to choose deliberately.
- **Audio-only is roughly an order of magnitude cheaper** than video and covers most of what
  a drop-in voice channel is for. Making video opt-in per call rather than default is a real
  operator-facing saving.

An operator must also be able to turn calls off entirely, and instance defaults should be
conservative.

## 11. Which SFU

**Decided for voice channels: an in-process SFU on `str0m`**, pure-Rust crypto backend — see
[ADR-012](adr/012-sfu-voice-channels.md) for why, and for what it does not cover (video). The
shape of the choice as it was framed before, kept because the tension has not gone away:

Building an SFU is out of scope; it is a specialist component and the mature ones represent
years of work on congestion control alone. The mature open-source options are **LiveKit**
(Go, Apache-2.0, ships browser E2EE via insertable streams), **mediasoup** (C++), **Janus**
(C), and **Jitsi Videobridge** (JVM). The Rust options — **str0m** and **webrtc-rs**, both
sans-IO — are real and would keep the stack in one language, but are libraries you assemble
an SFU from rather than an SFU.

The tension to resolve when the time comes: ADR-007 rejected SQLite partly to keep C out of
the build of a `#![forbid(unsafe_code)]` project, and a self-hosting story built on one
`docker compose up` gets worse with a second daemon in a second language. That argues for
the Rust libraries. Against them: an SFU is exactly the kind of component where "we wrote it
ourselves" has historically gone badly, and this project's own record — three vulnerability
classes shipped to `main` in reviewed, CI-green code — is not an argument for hand-rolling
more infrastructure.

## 12. Open questions

1. **~~Do calls inherit the room's tier?~~ DECIDED (owner): inherit, with an upgrade-only
   choice at creation.** A call takes its room's tier; at creation the creator may
   additionally opt *up* to E2EE, never down. A T3 room may host an E2EE call; a T1 or T2
   room may never host a transport-only one, and there is no setter afterwards. The
   badge-disagreement worry below is resolved by the asymmetry — the difference is always in
   the safer direction and the user chose it. See `02-encryption-tiers.md` §6.4.

   §5's rule governs what happens when a participant cannot do E2EE media: the call may
   fall back to transport-only, with its own badge, announced to everyone. (This paragraph
   used to say such a call refuses; that predates §5's owner decision, and contradicted it.)

   Original framing, kept so it is not re-litigated: This document assumes
   inherit — §5 depends on it, and it is what keeps the badge honest. It resolves the open
   question left at `02-encryption-tiers.md` §6.4, which leaned the other way ("always
   E2EE"). The reason for the change: an always-E2EE call inside a T3 public room means the
   room's badge and the call's badge disagree, and a user who has calibrated to "this room is
   public" is now in a surface with different rules. Consistency is worth more than the extra
   protection on a surface that is public by construction. **Owner decision — the tier model
   is not a session's to change.**
2. **Is there a participant ceiling?** `T1_MAX_MEMBERS` is 256 and `T2_MAX_MEMBERS` is 2,000,
   but no call has 2,000 live senders. A separate media ceiling is needed and it is a
   bandwidth question, not a cryptographic one.
3. **What happens to a call when the room's membership changes underneath it?** Removing
   someone from the room should eject them from its call. Two group lifecycles (§1) means
   this is not automatic.
4. **Stage / broadcast channels** (`08-feature-parity.md`, v3) invert the model: one sender,
   thousands of listeners. E2EE to an audience that large is a different problem, and it is
   very likely a T3-only feature.
5. **Do bots get to be in calls?** `01-threat-model.md` §10.4 already asks whether bots are
   group members with keys. A recording bot in an E2EE call is that question with the volume
   turned up.

---

## Sources

- [Discord DAVE protocol whitepaper](https://daveprotocol.com/) and the
  [protocol specification](https://github.com/discord/dave-protocol/blob/main/protocol.md)
- [RFC 9605 — Secure Frame (SFrame)](https://www.rfc-editor.org/rfc/rfc9605)
- [RFC 9420 — Messaging Layer Security](https://www.rfc-editor.org/rfc/rfc9420) (already
  ADR-002)
