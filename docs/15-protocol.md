# 15 — Protocol specification (draft)

**Status: draft, version 0, describes `main` as built.** The wire format is not frozen and
will change without notice while `PROTOCOL_VERSION` is 0 (`crates/cairn-proto/src/lib.rs`).
This document is written so that someone who has not read the source could build a client
that interoperates with a Cairn instance. When it disagrees with the code, the code is what
an instance actually does, and the disagreement is a bug in this document.

Read [`01-threat-model.md`](01-threat-model.md) first. Nothing here claims a property the
threat model does not support. Where a property depends on a check that a *client* must
perform, this document says **MUST** and names the check. A client that skips it is not
"less strict". It is broken in a way the instance cannot detect.

Key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Scope

In scope:

- identities and request authentication (§3, §4)
- the message envelope and its signature (§5)
- rooms, tiers and membership (§6)
- MLS usage: key packages, groups, commits, welcomes (§7)
- the encrypted message body (§8)
- franking and abuse reports (§9)
- attachments (§10)
- the HTTP surface (§11)

Specified elsewhere, and only listed in §11:

- spaces ([ADR-011](adr/011-spaces-channels-roles.md))
- voice channels and calls ([ADR-012](adr/012-sfu-voice-channels.md),
  [`12-realtime-media.md`](12-realtime-media.md))
- encrypted profiles ([ADR-010](adr/010-encrypted-profiles.md))
- custom emoji ([`13-customisation.md`](13-customisation.md))
- the GIF relay ([`14-gifs.md`](14-gifs.md))

Not specified yet, and listed honestly in §13.

## 2. Encoding conventions

- **Transport.** HTTP/1.1 carrying JSON bodies (`Content-Type: application/json`), except
  blob upload and download (§10). An instance speaks plain HTTP and MUST be deployed
  behind TLS ([`11-self-hosting.md`](11-self-hosting.md) §3). MLS protects message bodies.
  It does not protect the metadata or the request headers.
- **Identifiers** are random (v4) UUIDs. In JSON they are bare hyphenated UUID strings. In
  user-facing text they carry a kind prefix and no hyphens (`usr_…`, `dev_…`, `rom_…`,
  `msg_…`, `blb_…`, `spc_…`, `rol_…`). Some responses use the prefixed form. A client MUST
  accept both, and MUST reject a prefix of the wrong kind rather than strip it
  (`crates/cairn-proto/src/ids.rs`).
- **Bytes** in JSON are lowercase hex strings, with one exception: the `body` field of the
  encrypted inner body (§8) is a JSON array of byte values. That is serde's default for
  `Vec<u8>`, and it is a known wart.
- **Times** are milliseconds since the Unix epoch, as a signed 64-bit integer.
- **Signing input** is always built by explicit concatenation, never by serialising a
  structure. `lp(x)` means the length of `x` as a big-endian u64, followed by `x`. Every
  variable-length field is length-prefixed, so two different field splits can never produce
  the same bytes.

## 3. Identity

### 3.1 Accounts and devices

An **account** (`UserId`) owns one or more **devices** (`DeviceId`). **The client mints
both ids.** The instance does not assign them. Each device has one **signature key pair**:
Ed25519, the signature scheme of the pinned MLS ciphersuite (§7.1). The same key serves
three purposes:

1. It authenticates HTTP requests (§4).
2. It signs envelopes (§5).
3. It is the MLS leaf's signature key (§7).

The public key travels as the raw 32-byte Ed25519 public key, hex-encoded. Signatures are
raw 64-byte Ed25519 signatures over the exact signing input, with no pre-hash and no
context, hex-encoded.

### 3.2 Claiming an account

`POST /v1/accounts` with `{user, device, public_key, invite?}`. This claims `user` and
registers `device` as its first device.

- An id that is already claimed is refused with 409.
- Under the default `invite_only` policy, `invite` must be an unspent registration invite.
  The instance checks the invite *before* it notices whether the account already exists.
  A returning client MUST therefore remember that it has already claimed, rather than
  claim again with a spent invite.
- Attempts are limited per source address (`MAX_REGISTRATION_ATTEMPTS_PER_ADDRESS` per
  hour). Failed attempts count.

### 3.3 Linking a further device

`POST /v1/devices` with `{user, device, public_key, authorizing_device, authorization}`.
`authorization` is a signature by `authorizing_device`, which MUST already be on `user`,
over:

```
lp("cairn/device-authorization/v1") ‖ lp(user uuid bytes) ‖ lp(new device uuid bytes) ‖ lp(new public key)
```

UUID bytes are the 16 raw bytes, not the string. Without this signature anyone could
attach a device to any account and speak as it. That vulnerability shipped once; see
`CLAUDE.md`.

### 3.4 MLS credential

Each MLS leaf uses an RFC 9420 *basic* credential whose identity is exactly:

```
"cairn device identity v1\0" (25 bytes) ‖ user uuid (16 bytes) ‖ device uuid (16 bytes)
```

That is 57 bytes, with fixed widths and no separators (`crates/cairn-proto/src/identity.rs`).
A credential is self-asserted, so carrying the ids is not the protection. **The checks
are:**

- The instance refuses a published key package whose credential does not name exactly the
  account and device that authenticated the publish (§7.2).
- A claiming client **MUST** refuse a claimed key package whose credential does not name
  the account it asked for (§7.2).
- A client **MUST** attribute a decrypted message to the leaf that sent it, as named by its
  credential, and MUST NOT attribute it to the envelope's `sender` field alone. See §8.3
  for the gap that remains.

A malicious *instance* can still hand out a key package it minted itself. Safety numbers
exist for that case ([`01-threat-model.md`](01-threat-model.md) §4).

## 4. Request authentication

Every request except account claiming, device linking, report submission and `/health`
carries three headers:

| Header | Value |
|---|---|
| `x-cairn-device` | the signing device's UUID |
| `x-cairn-timestamp` | `issued_at_ms`, decimal |
| `x-cairn-signature` | hex signature over the bytes below |

```
lp("cairn/request/v1") ‖ lp(action) ‖ resource ‖ issued_at_ms (i64, big-endian)

resource = 0x00                                  when the action names no resource
         | 0x01 ‖ lp(kind) ‖ lp(uuid bytes)      kind ∈ room, user, device, blob, space
```

The **action** is a fixed string per endpoint, listed in §11. The resource kind is part of
the signed input, so a signature over one room id cannot be presented for the account
with the same UUID.

The instance accepts a request when all of these hold:

- `|now − issued_at_ms| ≤ 60 000`
- the device is registered
- the signature verifies under that device's key

The acting account is then the device's owner.

**There is no nonce.** A captured request can be replayed within its 60-second window.
Message envelopes are the exception (§5.3).

## 5. The envelope

### 5.1 Shape

```json
{
  "version": 0,
  "id": "<uuid>",
  "room": "<uuid>",
  "sender": "<uuid>",
  "sender_device": "<uuid>",
  "sent_at_ms": 1739999999999,
  "payload": { "kind": "mls_application", "ciphertext": "<hex>" },
  "franking_commitment": "<64 hex chars>",
  "signature": "<hex>"
}
```

`payload.kind` is one of:

| kind | fields | legal in |
|---|---|---|
| `mls_application` | `ciphertext`: an RFC 9420 `MLSMessage` (`PrivateMessage`) | every tier |
| `mls_handshake` | `message`: an `MLSMessage` (commit, proposal or welcome); `epoch_seq`: reserved, omitted | every tier |
| `plaintext` | `body`: UTF-8 string | T3 only |

`franking_commitment` is omitted when absent. A sender MUST include it on every
`mls_application` envelope, because the reference client refuses one without it. A sender
MUST omit it on handshakes (§9). The instance accepts either, since it cannot see which
messages are worth franking.

`sent_at_ms` is the sender's claim. It MUST NOT be used for ordering. The order is
`server_seq` (§5.4).

`epoch_seq` is described in the source as "server-assigned", but no instance sets it.
Ordering comes from `server_seq` alone. Senders MUST omit it. It is signed as 0 when
absent.

### 5.2 Signature

`signature` is the sending device's signature over:

```
lp("cairn/envelope/v1") ‖ version (u16 BE) ‖ lp(id) ‖ lp(room) ‖ lp(sender) ‖ lp(sender_device)
  ‖ sent_at_ms (i64 BE)
  ‖ payload
  ‖ commitment

payload    = 0x01 ‖ lp(ciphertext)                          mls_application
           | 0x02 ‖ lp(message) ‖ epoch_seq-or-0 (u64 BE)  mls_handshake
           | 0x03 ‖ lp(UTF-8 body)                          plaintext
commitment = 0x00 | 0x01 ‖ lp(ASCII hex of the commitment)
```

The four ids are the 16 raw UUID bytes. Note that the commitment is signed **as its hex
text**, not as its 32 decoded bytes.

On every envelope, the instance checks that:

- the signature verifies
- `sender_device` is registered to `sender`
- the payload kind is legal for the room's tier

A plaintext payload in an E2EE room is refused even from a member.

### 5.3 Accepted once per room

A room accepts each envelope `id` once.

- A byte-identical resubmission of an envelope the room still holds is answered with the
  original receipt (the same `server_seq` and tag), and nothing new is stored. That makes
  a sender's retry after a lost response safe.
- Any other reuse of an id is refused with 409. That includes a different envelope under
  the same id, and an id whose message a disappearing-message timer has since purged.

This check exists because the signature does not cover where in the room a message
falls. Before it, any member could resubmit someone else's envelope and have it stored
again at a new position, with a fresh franking tag.

### 5.4 Sending and fetching

- `POST /v1/rooms/{room}/messages` with the envelope as the body returns
  `{server_seq, franking_tag?}`. The path's `{room}` is ignored, and `envelope.room` decides
  where the envelope goes. Envelopes need no request headers, because they carry their own
  signature.
- `GET /v1/rooms/{room}/messages?after=N` (action `read`) returns every message with
  `server_seq > N` as `[{envelope, server_seq, franking_tag?}]`, in order. There is no
  paging.

`server_seq` starts at 1 and increases by exactly one per accepted message in that room.
It is the single ordering authority. MLS requires its handshakes to be applied in one
agreed order, and this is that order ([ADR-002](adr/002-mls-for-groups.md)). A client
SHOULD persist its cursor after *each* message it processes. Re-processing an MLS message
whose keys were already consumed fails.

The instance refuses a send from a non-member (403). Sends are also limited per account:
1 800 per hour across all rooms.

## 6. Rooms, tiers and membership

### 6.1 Creating a room

`POST /v1/rooms` (action `create_room`, no resource) with
`{is_direct, is_publicly_discoverable, member_ceiling}`. Response:
`{room, tier: "T1"|"T2"|"T3", e2ee, ttl_ms?}`.

The tier is derived deterministically and can never change
([ADR-001](adr/001-tiered-encryption.md)):

| shape | tier |
|---|---|
| `is_direct`, `member_ceiling ≤ 256` | T1, end to end |
| `is_direct`, `member_ceiling > 256` | refused |
| not direct, not discoverable, `member_ceiling ≤ 2000` | T2, end to end |
| not direct, discoverable or `member_ceiling > 2000` | T3, transport only |

A client **MUST** derive the tier locally from the shape it requested and refuse a room
whose reported tier differs. It MUST NOT display a tier it was merely told. The tier badge
is the client's own claim. `GET /v1/rooms/{room}` (action `describe`) returns the same
shape. For a private room it answers members only.

### 6.2 Roles and membership

The instance keeps a member list for each room, with roles `member < moderator < owner`.
The creator is owner.

| Request | Action | Rule |
|---|---|---|
| `POST /v1/rooms/{room}/members` `{user}` | `add_member` | moderator or owner; respects the room's ceiling |
| `DELETE /v1/rooms/{room}/members/{user}` | `remove_member` | only someone strictly below the actor, or oneself |
| `PUT /v1/rooms/{room}/members/{user}` `{role}` | `set_role` | owner only; the last owner cannot step down |
| `GET /v1/rooms/{room}/members` | `list_room_members` | members only; returns `[{user, role}]` |
| `POST /v1/rooms/{room}/join` | `join` | T3 only |
| `POST /v1/rooms/{room}/invites` `{uses, expires_at_ms?}` | `create_room_invite` | moderator or owner; `1 ≤ uses ≤ 100`; returns `{token}` once |
| `POST /v1/invites/redeem` `{token}` | `redeem_room_invite`, no resource | adds the caller as a member and returns `{room}`; every failure is the same 401 |

A room invite token is a capability for one named person. It is not a public invite, so
it does not change the room's tier. The instance stores only its SHA-256 hash.

**Server membership and MLS membership are separate, and a client must reconcile them.**

- Server membership decides who may fetch and send.
- MLS membership decides who can read.

Someone who redeemed an invite is a server member who cannot read anything until an
existing MLS member adds them (§7.3). A client SHOULD list such accounts as "waiting".
Listing them is safe. Admitting them automatically on the instance's word is not, because
the list comes from the instance. Removal is the same in reverse: removing someone on the
server stops the instance serving them. Their MLS leaf, and so their ability to decrypt,
lasts until a member commits the removal (§7.4).

### 6.3 Disappearing messages

`POST /v1/rooms/{room}/ttl` `{ttl_ms | null}` (action `set_room_ttl`). Any member may set
it. It applies to messages sent after it is set. The instance deletes expired messages
from storage on read. Their ids are retained (§5.3).

## 7. MLS usage

### 7.1 Ciphersuite and wire choices

`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (RFC 9420 ciphersuite 0x0001), with basic
credentials (§3.4). The reference client uses `mls-rs` 0.55, and makes these choices.
All but the lifetime are `mls-rs` defaults, not explicit configuration.
`the_mls_wire_choices_the_protocol_spec_names_still_hold` in `cairn-crypto` fails if a
dependency bump changes them.

| Choice | Value | What it means for an implementation |
|---|---|---|
| Handshake wire format | `PublicMessage` | Commits are signed but not encrypted, so the instance can read who added or removed whom. It already knows this from server membership (§6.2). Receivers MUST accept `PublicMessage` commits. |
| Application wire format | `PrivateMessage` | As RFC 9420 requires. |
| Ratchet tree | in the welcome (`ratchet_tree` extension) | **Required.** A joiner has no other way to obtain the tree. |
| Welcomes per commit | one | One welcome covers every device added by the commit. |
| Update path in a commit | not required | An add-only commit may omit the path. Receivers MUST accept that, as RFC 9420 allows. |
| External commits | not allowed | Nobody joins a group without a member's commit. |
| Key package lifetime | 84 days, starting an hour before generation | Chosen for OpenMLS, which refuses a lifetime spanning more than 84 days and an hour, and refuses a leaf whose `not_before` is not strictly in the past. The `mls-rs` default (a year, starting now) met neither. |
| Group and key-package extensions | none | |
| Proposals | by value, inside the commit (Add, Remove) | Cairn never sends standalone proposals. |
| Padding of application messages | `mls-rs`'s step function | A sender's choice. Receivers accept any valid padding. |

**Checked against an independent implementation.** `interop/` puts OpenMLS 0.8 in the same
group as the reference client: each joins the other's group, messages and commits cross in
both directions, a removed OpenMLS member is cut off, and both derive the same voice media
key (ADR-012, not specified here). An OpenMLS client needs two settings that are not its
defaults:

- an incoming wire-format policy that accepts plaintext handshakes (`Mixed`). Its default
  accepts only encrypted ones and refuses every Cairn commit with
  `IncompatibleWireFormat`;
- `use_ratchet_tree_extension(true)` when it joins, not only when it creates a group.
  Otherwise its own welcomes leave the tree out, and a Cairn device it adds cannot join.

### 7.2 Key packages

- `POST /v1/devices/{device}/key-packages` `{packages: [hex MLSMessage]}` (action
  `publish_key_packages`, resource the device) returns `{remaining}`. The device must be
  the caller's. Each package's credential must name the caller's account and that device,
  or the publish is refused with 403. A device may hold at most 100 unclaimed packages.
- `POST /v1/users/{user}/key-packages` (action `claim_key_packages`, resource the user)
  consumes and returns one package for **every** device of the account, as
  `[{device, key_package}]`. Expired packages are skipped, never handed out. If any device
  has none left, it returns 409 and nothing is consumed. Claims are limited per actor, to 3 per target and 30 in total per hour.

A claimer **MUST**:

1. check that each package's credential names the account it asked for, and refuse the
   whole set otherwise;
2. add every returned package. Adding only some of them leaves the account's other devices
   unable to read, which looks like a bug to the user and cannot be diagnosed.

### 7.3 Groups, commits and welcomes

- **One group per E2EE room**, created by the room's creator. A DM is a two-member group.
- **Handshakes travel through the room** as `mls_handshake` envelopes, sequenced with
  everything else. A welcome is posted to the room unaddressed. Every client in the room
  sees it, and only the device it was sealed to can open it. A client with no group for a
  room tries each handshake envelope as a welcome and ignores the rest.
- **To add an account:**
  1. make it a server member (§6.2);
  2. claim its key packages (§7.2);
  3. stage a commit adding them;
  4. post the commit;
  5. only after the instance has accepted the commit, apply it locally and post the
     welcome.

**A client MUST NOT apply its own commit before the instance has accepted it.** If the
upload is lost, the instance's order does not contain the commit, and a client that has
already applied it is alone in an epoch nobody else will reach. If the outcome of the
upload is unknown, the next fetch settles it:

- If the commit appears in the log, process it as received, which applies it, and then
  send the held welcome.
- If the client has read to the end of the log and the commit is not there, discard it.

A client MUST NOT encrypt while one of its commits is unsettled. It SHOULD keep the held
welcome on disk alongside the pending commit, so that a restart in between does not
strand the newcomer. The decision "absent, so it never landed" is open to one narrow
race; see §13.

- **Concurrent commits.** If another member's commit is sequenced first, the client's own
  commit for the same epoch is void. It is dropped, and the person it was adding is still
  waiting.

### 7.4 Removal

A member's MLS leaf is removed by a commit, posted and settled exactly as in §7.3. Clients
SHOULD commit the removal of anyone the instance no longer lists. Until someone does, the
removed device can still decrypt what is sent, though the instance will refuse to serve it
new messages.

## 8. The encrypted body

### 8.1 Inner body

An `mls_application` ciphertext decrypts to a UTF-8 JSON object:

```json
{
  "body": [104, 105],
  "opening": "<64 hex chars>",
  "card": {...}, "attachment": {...}, "signal": {...}, "reply_to": {...},
  "reaction": {...}, "profile": {...}, "custom_set": {...}, "sticker": "name"
}
```

Only `body` and `opening` are required. Every other field is optional. A receiver MUST
ignore fields it does not know and MUST tolerate the absence of any optional field.
`body` is the message text as bytes. It is empty for reactions, profiles, call signals and
custom sets.

Optional fields:

| Field | Defined in |
|---|---|
| `reply_to`, `reaction` | `crates/cairn-client-core/src/conversation.rs` (`MessageRef`, `Reaction`) |
| `attachment` | §10 |
| `card` | [`05-embeds.md`](05-embeds.md) |
| `signal` | [`12-realtime-media.md`](12-realtime-media.md) |
| `profile` | [ADR-010](adr/010-encrypted-profiles.md) |
| `custom_set`, `sticker` | [`13-customisation.md`](13-customisation.md) |

**Edits and deletes** are fields of the same object, `edit` and `delete`, each a
reference (§8.2) to one of the sender's own earlier messages. An edit carries the new
text in `body` and nothing else. A delete carries an empty `body` and nothing else. A
receiver MUST drop either one if it carries any other field, or if it names someone
else's message. An edit is franked over a frame that binds it to its target (§9).
Delete-for-everyone is a request that honest clients honour, not a guarantee
([`01-threat-model.md`](01-threat-model.md) §3b).

### 8.2 Referring to a message

A message is named by `{sender, id}`, where `id` is the hex of its franking commitment.
The commitment is unique per message, but only per sender: anyone who holds the opening
can reproduce it. Resolving a reference MUST therefore match the sender as well as the id.

### 8.3 Attribution

The instance checks an envelope's signature (§5.2). A client **MUST** also check that the
sender's device is a leaf of the group whose credential names `(sender, sender_device)`.
Without that check, a malicious instance can relabel anyone's words.

**Not yet bound:** the ciphertext is not bound to the envelope's signer. The MLS sender of
the decrypted message is not compared with the envelope's `sender_device`. A member who
re-wraps another member's ciphertext in their own envelope fails as an MLS replay when the
original arrives first. An instance that colludes with them can reorder the two. See
[ADR-010](adr/010-encrypted-profiles.md). Closing this needs the MLS sender from
`cairn-crypto`.

## 9. Franking and reports

A recipient can prove to the instance what a sender said, without the instance ever
holding plaintext ([`04-safety-architecture.md`](04-safety-architecture.md)). The scheme is
unaudited.

- **Commitment.** The sender draws a random 32-byte `opening` and computes
  `commitment = HMAC-SHA256(key = opening, "cairn/franking/commitment/v1" ‖ len(f) as u64 BE ‖ f)`.
  For an ordinary message, `f` is `body`. For an edit (§8.1), `f` is
  `lp("cairn/franked/edit/v1") ‖ lp(target sender uuid bytes) ‖ lp(target commitment, 32 bytes) ‖ lp(body)`,
  so a report of an edit names what it replaced. An ordinary message whose body would
  parse as that frame MUST NOT be sent, and is dropped on receipt
  (`crates/cairn-proto/src/franked.rs`). The commitment goes in the envelope as hex. The
  opening goes **only** inside the encrypted body (§8.1). Handshakes carry no commitment.
- **Tag.** On acceptance, the instance computes:

  ```
  tag = HMAC-SHA256(key = instance franking key,
        "cairn/franking/tag/v1" ‖ commitment ‖ room ‖ sender ‖ sender_device ‖ server_seq (u64 BE)
        ‖ (0x00 | 0x01 ‖ previous franked commitment in this room))
  ```

  The ids are the 16 raw bytes each. The tag is returned to the sender and to every
  fetcher. Because the previous commitment is chained in, consecutive franked messages
  form a run that can be verified as a sequence.
- **Receiver check.** A receiver **MUST** recompute the commitment from the decrypted body
  (framed as above for an edit) and the opening, and MUST drop a message whose commitment
  does not match: it could not be reported, and an unreportable message is exactly what an
  abuser would send.
- **Report.** `POST /v1/reports` (unauthenticated) takes `{messages: [{plaintext, opening,
  context: {commitment, room, sender, sender_device, server_seq, prev_commitment}, tag}]}`.
  `plaintext` is the franked bytes `f` as a JSON array of byte values. `opening`,
  `commitment`, `prev_commitment` (or `null`) and `tag` are hex.
  The response is `{verified, reason?, message_count}`, always with HTTP 200, because a
  verdict of "this does not hold up" is a result, not an error. A report verifies when
  every commitment opens to its plaintext, every tag is valid, and the run is in one room,
  contiguous through `prev_commitment`, and strictly increasing in `server_seq`.

Franking gives up deniability on purpose ([`01-threat-model.md`](01-threat-model.md) §3.6).

## 10. Attachments

- A client seals the file with XChaCha20-Poly1305 under a fresh random 32-byte key. The
  blob is `nonce (24 bytes) ‖ ciphertext‖tag`.
- It uploads the blob with `POST /v1/rooms/{room}/blobs` (action `upload_blob`, resource
  the room), using the raw bytes as the body. The response is `{blob}`. The instance caps
  a blob at 25 MiB, and caps uploads at 100 MiB per account per hour.
- `GET /v1/blobs/{blob}` (action `download_blob`, resource the blob) returns the bytes to
  current members of the room the blob was uploaded to.
- The key, the blob id, the sender's filename, the size and an optional media type travel
  in the inner body's `attachment` field. The filename and media type are the sender's
  claims, and a receiver MUST NOT treat the name as a path.

## 11. HTTP surface

Every request below, apart from the exceptions in §4, is signed. The quoted string is the
signed action, and the resource is in brackets.

| Method and path | Action [resource] | § |
|---|---|---|
| `GET /health` | none | — |
| `POST /v1/accounts` | none | 3.2 |
| `POST /v1/devices` | none, carries its own authorization | 3.3 |
| `POST /v1/rooms` | `create_room` | 6.1 |
| `GET /v1/rooms/{room}` | `describe` [room] (private rooms) | 6.1 |
| `POST /v1/rooms/{room}/messages` | none, envelope-signed | 5.4 |
| `GET /v1/rooms/{room}/messages` | `read` [room] | 5.4 |
| `POST /v1/rooms/{room}/members` | `add_member` [room] | 6.2 |
| `GET /v1/rooms/{room}/members` | `list_room_members` [room] | 6.2 |
| `DELETE /v1/rooms/{room}/members/{user}` | `remove_member` [room] | 6.2 |
| `PUT /v1/rooms/{room}/members/{user}` | `set_role` [room] | 6.2 |
| `POST /v1/rooms/{room}/join` | `join` [room] | 6.2 |
| `POST /v1/rooms/{room}/invites` | `create_room_invite` [room] | 6.2 |
| `POST /v1/invites/redeem` | `redeem_room_invite` | 6.2 |
| `POST /v1/rooms/{room}/ttl` | `set_room_ttl` [room] | 6.3 |
| `POST /v1/devices/{device}/key-packages` | `publish_key_packages` [device] | 7.2 |
| `POST /v1/users/{user}/key-packages` | `claim_key_packages` [user] | 7.2 |
| `POST /v1/rooms/{room}/blobs` | `upload_blob` [room] | 10 |
| `GET /v1/blobs/{blob}` | `download_blob` [blob] | 10 |
| `POST /v1/reports` | none | 9 |
| `POST /v1/usernames` `{username}` | `claim_username` | — |
| `GET /v1/usernames/{name}` | `lookup_username`, returns `{user}` | — |
| `POST /v1/rooms/{room}/turn` | `turn_credentials` [room] | 12-realtime-media |
| `POST`, `GET /v1/rooms/{room}/voice`; `DELETE …/voice/{session}` | `voice_join`, `voice_roster`, `voice_leave` [room] | ADR-012 |
| `GET /v1/gifs`; `GET /v1/gifs/tunnel/{target}` | see `14-gifs.md` | 14-gifs |
| `/v1/spaces…`, `/v1/space-invites/redeem` | see `spaces_http.rs` | ADR-011 |

Errors return `{error: "<message>"}` with these statuses:

| Status | Meaning |
|---|---|
| 400 | malformed |
| 401 | authentication failed, or an invite was refused |
| 403 | authenticated but not entitled |
| 404 | no such resource, or the feature is off |
| 409 | conflict: already claimed, room full, no key packages, duplicate envelope |
| 413 | blob too large |
| 429 | rate limited |
| 500 | storage failure. The write may not have happened. Settle it by reading (§7.3), not by assuming. |

## 12. What the instance sees

The instance sees every envelope field except the ciphertext's contents. That includes:

- sender, device, room, time and size
- every request's action and resource
- membership and roles
- franking commitments
- blob sizes, and who uploaded them to which room

In T3 it sees the content as well. This is the exposure that
[`01-threat-model.md`](01-threat-model.md) §3 concedes, and nothing in this protocol hides it.

## 13. Not yet specified, or known to be weak

- **The MLS wire choices are `mls-rs` defaults** (§7.1), written down and guarded by a
  test, but not configured explicitly. Interop against a second RFC 9420 implementation
  (M5) is what would show whether writing them down was enough.
- **A commit that lands after the client gave up on it** (§7.3). "Not in the log, so it
  never landed" assumes the instance has finished every request whose connection has died.
  The window is one `accept` call. Closing it needs a way to ask "did envelope X land?",
  which §5.3's per-room id record could now answer.
- **Request replay inside 60 seconds** (§4). This needs a nonce before anything
  state-changing faces a hostile network.
- **No paging** on fetch (§5.4), and no binary encoding. JSON and hex are a development
  convenience.
- **Federation**: none. One instance is one island ([ADR-003](adr/003-islands-first.md)).
- **Version negotiation**: none. `version` is signed and stored, but no instance refuses a
  version other than 0 yet.
- **The ciphertext is not bound to the envelope signer** (§8.3).
