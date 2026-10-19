# ADR-012: An in-process SFU for drop-in voice channels, with media sealed end to end

**Status:** Accepted, **partially built** — see "What is built" at the end. Touches media
encryption and room membership, so it is for the owner to review, not to self-merge.
**Implements the SFU half of [`12-realtime-media.md`](../12-realtime-media.md).** That
document's per-call MLS group (§1–§3) is **not** part of this decision.

## Context

The mesh in `12-realtime-media.md` §0 works and costs an operator nothing, but every
participant uploads once per other participant and it refuses past six. It is also a
*ring*: somebody calls, somebody answers. A Discord-style voice channel is something else —
a call that belongs to a room, that people drop into and out of without ringing anyone, and
whose occupancy the room can see. That needs something in the middle, and something in the
middle is precisely what the project's E2EE claims have so far not had to account for.

Three constraints are not open:

1. **Non-negotiable #3.** Nothing may claim a protection that does not hold. An SFU
   terminates DTLS-SRTP, so without a second layer it hears everything; a lock icon on such
   a call would be the `DeviceRecord` comment again.
2. **§5's fallback rule** (owner, narrowed): a call in an E2EE room may fall back to
   transport-only if a participant cannot do E2EE media, but it then carries its *own*
   badge and the fallback is announced to everyone in it.
3. **The FFI line** (ADR-008): the webview never derives, chooses or rotates a key.

## Decision

### 1. An in-process SFU in `cairn-server`, on `str0m`

`crates/cairn-server/src/sfu.rs`: one thread, one UDP socket, one `str0m::Rtc` per connected
device, audio only.

- **`str0m` 0.24** (MIT OR Apache-2.0, compatible with AGPL-3.0). Used with
  `default-features = false, features = ["rust-crypto"]`, so DTLS and SRTP are pure Rust
  (`dimpl`, RustCrypto) and no C enters the build — the same reason ADR-007 gave for
  rejecting SQLite. **That needed a patch**: the published `str0m-rust-crypto` also compiles
  in `aws-lc-rs`, and `dimpl` then prefers it, so as first built the handshakes ran on AWS-LC.
  `vendor/str0m-rust-crypto` is the published crate with its certificate generation replaced;
  `VENDORED.md` there has the details.
- **The SFU needs rustc 1.88**, above the 1.85 floor. `str0m` declares 1.85, but it, `str0m-proto`
  and `dimpl` depend on `time`, which needs 1.88 from 0.3.47 — and 0.3.47 is the fix for
  RUSTSEC-2026-0009, so it cannot be held back. Found by the MSRV job, not by reading. The SFU
  is therefore `cairn-server`'s default-on `sfu` feature: the MSRV job checks the server at
  1.85 without it, and the Docker image builds on 1.88 with it.
- **Why in-process rather than LiveKit/mediasoup/Janus.** §11 of the media document named
  the tension: a second daemon in a second language makes `docker compose up` worse, and a
  hand-rolled SFU is risky. `str0m` resolves most of it: ICE, DTLS, SRTP, RTCP and
  packetisation are the library's, and what Cairn writes is the forwarding loop — a few
  hundred lines that decide which packet goes to whom. The congestion-control and simulcast
  work that makes mature SFUs years of effort is video work; this SFU forwards audio only.
  An external SFU would also have needed its own membership and authentication, which is
  exactly the logic this project has a record of getting wrong; here it is `state.rs`'s.
- **No renegotiation, ever.** Each client's single offer carries one `sendonly` audio track
  and `MAX_VOICE_PARTICIPANTS − 1` (15) `recvonly` ones. The SFU assigns each other speaker
  to a free receive slot when they first send. Same reasoning as the mesh's empty video line:
  renegotiation is where call bugs live.
- **ICE-lite, one host candidate** (`CAIRN_SFU_BIND`, advertised as `CAIRN_SFU_ADVERTISE`).
  No TURN in front of it today; a client that cannot reach the SFU's UDP port cannot use
  voice channels.

### 2. Who may be in a voice channel is `state.rs`'s rule

`Instance::voice_join` / `voice_leave` / `voice_roster` / `voice_seat`, with the registry the
SFU consults (`VoiceRegistry`):

- **Room members only.** A non-member gets `NotAMember` before anything else is checked, so
  a stranger cannot even learn whether the instance runs an SFU (the TURN endpoint's rule).
- A seat is bound to the account *and device* that signed the request; any operation on
  someone else's session gets the same answer as a session that does not exist.
- A device holds one seat anywhere. A channel holds 16.
- **The SFU forwards a packet only while sender and receiver both hold seats in the same
  room**, checked per packet, and closes any connection whose seat has gone.
  `remove_room_member` evicts the seat under the rooms lock, so removal from the room is
  removal from the call within one forwarding decision.

### 3. Media in an E2EE room is sealed in the webview, under a key from the room's MLS group

`cairn_crypto::media` and `GroupHandle::media_key`:

- **Key:** one per sending device per MLS epoch, from the MLS exporter of **the room's**
  group, label `"Cairn voice media v1"`, context `len(room) ‖ room ‖ len(credential) ‖
  credential`. AES-128-GCM, because WebCrypto has AES-GCM and not ChaCha20.
- **Frame:** `ciphertext ‖ tag ‖ iv(12) ‖ epoch(u32) ‖ leaf(u32) ‖ 0xC1`, trailer as AAD; the
  plaintext is `flags ‖ opus`, where `flags` carries mute and deafen end to end. Random IV per
  frame. Not RFC 9605 SFrame and not described as such.
- **Who touches what.** `cairn-client-core` derives the keys and decides the call's
  protection (`Session::voice_state`); the Tauri command `voice_keys` hands the webview the
  current epoch's raw keys, which it imports into WebCrypto as **non-extractable** and drops.
  That is the honest statement of the FFI line here: raw key bytes do cross into the webview,
  once per epoch, because a per-frame round trip to Rust at 50 frames a second per speaker is
  not workable. The webview never derives a key, never picks which epoch is current, and
  never decides whether to encrypt. An `RTCRtpScriptTransform` worker (or Chromium's
  `createEncodedStreams` where that is all there is) seals each outgoing frame and opens each
  incoming one.
- **A receiver chooses the key from the frame's trailer** (epoch, leaf), not from the SFU's
  word about which slot is whose. Per-sender keys mean the SFU cannot relabel who is speaking:
  a frame opens only under its sender's key.
- **In an E2EE call a frame that does not open is dropped**, including plaintext. That is
  the Trail of Bits finding against DAVE — an SFU synthesising frames — closed for the
  instance, which holds no key.

**Why the room's group and not a per-call group.** §1 of the media document wants a call
group whose membership is the participants. A voice channel's audience *is* the room — any
member may drop in — so the room's group already has the right membership for confidentiality:
the people who can derive the keys are exactly the people allowed to join. What a per-call
group would add is a cryptographic roster of who is *in the call*, which today is the
instance's word (`voice_roster`). That gap is stated below rather than closed.

### 4. The §5 fallback, as built

- **The trigger is authenticated, not the instance's.** A client whose webview has no
  encoded-transform support announces `voice_media: transport_only` as an MLS-encrypted
  signal in the room; capable clients announce `e2ee`. `Session::voice_state` marks the call
  transport-only only while a participant the instance lists as connected has *announced*
  transport-only. **The instance cannot force a downgrade**: it cannot forge the announcement,
  and suppressing it only means the fallback client's plaintext is dropped by everyone — it
  fails closed, toward silence, never toward plaintext.
- **The call carries its own badge**, derived from the call, beside the room's: an E2EE room
  showing a transport-only voice channel says exactly that, and the room's tier badge does not
  change. Messages are unaffected.
- **Announced to everyone in the call** when it happens and when it ends: a notice in the
  voice panel and a notice in the room's timeline, naming who caused it. While it lasts, every client sends plaintext
  so the fallback participant can hear and be heard; when they leave, everyone returns to
  sealed frames.
- **Anyone may decline**: Settings → Voice & video, *Leave a voice channel that stops being
  end-to-end encrypted*.
- A T3 room's voice channel is transport-only by its tier, as the room badge already says.

### 5. Mesh or SFU: the switchover rule

**A call somebody rings is a mesh call; a voice channel is an SFU call.** No live call moves
from one to the other. The mesh keeps its six-person ceiling and its property that media
never reaches the instance; the voice channel trades that for scale and drop-in. A client on
an instance with no SFU shows no voice channel. Automatic migration of a ringing call that
outgrows the mesh is not built and not planned here — it would mean a mid-call change of who
can see the media, which deserves its own announcement design.

## What the SFU sees

Stated here and in `01-threat-model.md` §3a because it is new: for the first time the
instance is in the media path.

- **Who is connected, from which IP address and port, from when until when** — and the room
  shows the same occupancy to its members, by design (`12-realtime-media.md` §6).
- **Packet sizes and timing per sender**, which track speech closely: who talks, when, for how
  long. No padding is done.
- **The SDP offer**: codecs, the device's ICE candidates and addresses, its DTLS fingerprint.
- **Each frame's trailer**: the MLS epoch's low 32 bits and the sender's leaf index.
- **Not** the `ssrc-audio-level` header extension: the SFU's answer omits it, so browsers do
  not send a per-packet loudness value outside the encryption.
- **In a transport-only call, the audio.** That is what the badge says.

## What this does not protect, plainly

- **The roster is the instance's.** Which devices are "in the channel" comes from
  `voice_roster`; the client checks each one against the MLS group and marks a device that is
  not in it. What it cannot catch is the reverse: **a malicious instance can forward a
  channel's frames to a room member it leaves off the roster**, and that member, holding the
  room's group keys, can open them. A device *outside* the group gains nothing from this; a
  member who was never in the channel can listen unseen. Against an honest instance it does
  not happen — the SFU forwards only to seated connections and the roster lists every seat.
  A per-call MLS group would make the roster cryptographic and close it.
- **Removal is immediate at the SFU, eventual in the cryptography.** The SFU drops a removed
  member at once. Their keys stay valid until the removal commit is processed by the senders;
  until then, a removed member who somehow still received frames could open them. With an
  honest instance they receive nothing; against a malicious one, the commit is the bound.
- **Every room member can derive every sender's key**, so against another member (A6) sealing
  proves nothing about who sealed.
- **AES-GCM is not key-committing** (§4 of the media document).
- **Video and screen share do not cross the SFU.** Voice channels are audio only.

## Alternatives rejected

- **LiveKit as a sidecar.** Mature, Apache-2.0, has browser E2EE — and a second daemon, a
  second language, and a second authentication system to keep in step with room membership.
- **`webrtc-rs`.** Larger, async, and its own maintenance has slowed; `str0m`'s sans-IO
  shape fits a thread whose every decision we want to be able to test.
- **Encrypting each frame in Rust over IPC.** Keeps raw keys out of the webview, at the cost
  of an IPC round trip per frame per speaker. Not workable for real-time audio.
- **Refusing a non-E2EE participant.** The pre-launch rule §5 replaced.

## What is built

See `12-realtime-media.md` §0a for the current state, the tests that cover it, and what is
left.
