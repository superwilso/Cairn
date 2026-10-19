# Self-hosting a Cairn instance

**Status: pre-alpha.** Read the section at the bottom before you put anyone's real
conversations on this. It is not a disclaimer for form's sake — the gaps listed there are
specific and some of them will bite a small friendly deployment, not just a large hostile
one.

This guide gets you to the point where a friend on another machine can register, join a
room, and exchange end-to-end encrypted messages with you.

---

## 1. What you need

- A machine with a public IP and Docker.
- A domain name pointed at it. **Not optional** — see §3.
- Ports 80 and 443 reachable.

## 2. Run it

```bash
git clone https://github.com/superwilso/Cairn && cd Cairn

cat > .env <<'EOF'
CAIRN_DOMAIN=cairn.example.com
CAIRN_INVITES=paste-a-long-random-string,and-another-one
EOF

docker compose up -d --build
```

Generate the invite tokens with something that is actually random:

```bash
openssl rand -hex 24
```

They are single-use, and they are the only thing standing between the open internet and
an account on your instance. A guessable token is an open instance. The server refuses to
start with one shorter than 16 characters — a floor, not an entropy check, so use the
command above rather than typing something long.

Check it came up:

```bash
docker compose logs cairn | grep listening
curl -s https://cairn.example.com/health
```

### Registration limits, and telling the instance about your proxy

Each address may attempt registration 20 times an hour, successful or not. Failures count
because under invite-only registration a failure *is* the attack: before this limit, one
address could guess about 2,000 invites a second. IPv6 addresses are grouped by `/64`, since
one machine can otherwise pick a fresh address from its `/64` for every attempt.

The instance can only limit addresses it can see. Behind Caddy, **every** connection comes
from Caddy, so the instance must be told to believe the `X-Forwarded-For` header Caddy
adds — and told *only* about Caddy, because anyone can send that header themselves.
`docker-compose.yml` does this for you: Caddy has a fixed address on a private network and
`CAIRN_TRUSTED_PROXIES` names it. If you change the network, change both.

Getting it wrong fails in the safe direction. If the instance trusts no proxy, everyone
shares Caddy's one budget — registrations get refused early — and the log says
`ignoring X-Forwarded-For from an untrusted peer`. It never fails by letting a client pick
its own address.

Two setups from §6 cannot give the instance real addresses, and it is better to know than to
discover: behind a **Tor onion service** every client arrives from the local Tor daemon, and
behind a **stream-level passthrough VPS** every client arrives from the tunnel. In both, all
registrations share one budget. Invite-only registration still holds, which is the part that
matters.

What this does not do: bound someone with many addresses. A botnet, or anyone holding a
large IPv6 allocation, gets many budgets. That is why invite-only is the default — against a
distributed guesser, a long random token is the defence, and the limit is not.

### GIF search (optional, off by default)

A fresh instance has **no GIF search**, and the picker says so. Cairn ships no API key: a
shared key would be rate-limited into uselessness by the first few instances. To turn it on,
get a key from one or both providers and set it on the `cairn` service:

```bash
CAIRN_KLIPY_API_KEY=...   # https://partner.klipy.com — but read the terms note below first
CAIRN_GIPHY_API_KEY=...   # https://developers.giphy.com
```

Either, both or neither. With both, members get a tab for each. A key is letters, digits,
`-` and `_`; anything else stops the instance at startup rather than producing broken
requests. Removing a key and restarting turns that provider off.

**How it works, and what it costs you.** Members' clients search through *your* instance
([`14-gifs.md`](14-gifs.md)): the instance opens a tunnel to the provider's fixed hosts on
port 443 and relays bytes, and the client runs its own TLS to the provider inside it. You see
that a member searched, which provider host, when, and how many bytes — never the words. The
provider sees the words and your instance's address — never the member's. A sent GIF is
fetched the same way and then travels as an ordinary encrypted attachment, so recipients
contact no provider at all. Every search and preview crosses your connection, bounded per
account at 600 tunnels and 200 MiB an hour; each sent GIF also counts against the upload
quota like a photo.

**Two things to understand before enabling it:**

- **The key is shared with every member.** The client builds the provider request inside
  its own TLS session, so it must hold the key — Signal ships its GIPHY key in its app for the
  same reason. Any account on your instance can read it and use it elsewhere, spending your
  quota or getting it revoked. Strangers cannot: the endpoint that hands it out requires a
  signed-in account.
- **A small instance is a small crowd.** The provider cannot see who searched, but on an
  instance with three active people it can guess. The relay stops a profile being built
  against a member's own address; it does not make them anonymous to the provider.

**KLIPY's terms, read October 2026.** KLIPY's standard
[integration requirements](https://docs.klipy.com/integration-requirements) say API requests
and media must come from the end-user's device *without* routing through partner proxies,
that media must not be re-hosted, and that results must not be filtered. Cairn's design does
all three on purpose — the relay is what keeps a member's address from KLIPY, re-hosting is
what keeps recipients from contacting it, and Cairn removes the adverts KLIPY inserts
(non-negotiable #4). Each of those requirements carries an exception for "prior written
approval" from developers@klipy.com. **Get that approval before setting
`CAIRN_KLIPY_API_KEY`**; without it, enabling KLIPY on your instance likely breaches its terms.
KLIPY also requires the search box to read "Search KLIPY", which the client does. GIPHY
requires "Powered by GIPHY", which the client shows; read GIPHY's own API terms for your key's
tier — beta keys are limited to about 100 requests an hour.

Behind Caddy nothing extra should be needed: the tunnel is an HTTP/1.1 `Upgrade` on an ordinary
path, which Caddy's `reverse_proxy` passes through for any protocol, as it does WebSockets
(the relay is tested over real sockets; it has not yet been run behind a live Caddy). If your firewall
restricts outbound traffic, the instance needs `api.klipy.com`, `static.klipy.com`,
`static1.klipy.com`, `static2.klipy.com` and/or `api.giphy.com`, `i.giphy.com`,
`media.giphy.com`, `media0`–`media4.giphy.com`, all on 443. That list is fixed in the source
(`crates/cairn-server/src/gif_relay.rs`) and is not configurable, because a configurable list
is how a relay ends up reaching `localhost`.

### A TURN relay for calls (optional, off by default)

Calls carry media **directly between participants** ([`12-realtime-media.md`](12-realtime-media.md)
§0); the instance never sees it. That costs you nothing, and it has two consequences members
will notice: a call between two people behind some home routers (symmetric NAT, carrier-grade
NAT) does not connect at all, and **every participant learns every other participant's IP
address**. A TURN relay fixes both, and the price is yours: relayed media crosses your
connection — a 1:1 video call is roughly 2–3 Mbps each way while it lasts.

Cairn does not include a relay. Run [coturn](https://github.com/coturn/coturn) beside the
instance with its REST-auth scheme (`use-auth-secret`), and give both the same secret:

```bash
CAIRN_TURN_URLS=stun:turn.example.org:3478,turn:turn.example.org:3478?transport=udp,turns:turn.example.org:5349
CAIRN_TURN_SECRET=...      # at least 16 bytes; `openssl rand -hex 32`. coturn's static-auth-secret
CAIRN_TURN_TTL_SECS=14400  # optional; how long each credential lasts (60–86400, default 4 hours)
```

and in `turnserver.conf`:

```
use-auth-secret
static-auth-secret=<the same secret>
realm=turn.example.org
# Never relay into your own network: a relay is otherwise a door into it.
no-multicast-peers
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
# How many relay allocations one credential, and the whole relay, may hold at once.
user-quota=12
total-quota=1200
```

**What the instance does.** A member who joins a call asks the instance for credentials for
*that room*; the instance answers only an authenticated member of it, with
`HMAC-SHA1(secret, "<expiry>:<account id>")` — the scheme coturn checks without contacting
the instance. Anyone else, including a request with no signature, gets a refusal that does not
say whether a relay exists. Credentials are fresh on every call and expire after the TTL, which
trades two things: a shorter TTL bounds how long a leaked credential lets a stranger spend your
bandwidth, a longer one keeps a long call from losing its relay when coturn re-checks the
credential. The account id in the username means your coturn logs say which account relayed
when.

**What it does not do.** Membership is a gate against strangers, not against your own members:
any account can create a room and ask. Abuse by a member is bounded by coturn's quotas, not
Cairn. And the relay operator — you — sees the IP address of everyone relayed through it, plus
the size and timing of their media. It cannot read the media: DTLS-SRTP runs end to end between
the participants, through the relay.

If the URLs include a `stun:` entry, clients use it **instead of** the public STUN default,
so a call never contacts a third party. If they list only `turn:`/`turns:`, clients keep the
public default for discovering direct paths. Setting one of `CAIRN_TURN_URLS` and
`CAIRN_TURN_SECRET` without the other stops the instance at startup.

Members can then switch on **Settings → Voice & video → Always use the relay**, which hides
their IP address from the other people in a call. The setting says what it costs: the relay —
you — sees that address instead, and on an instance with no relay it means calls cannot
connect.

### 2a. Voice channels: the SFU (optional, off by default)

Drop-in voice channels need a media server, and Cairn's is built in: set

```
CAIRN_SFU_BIND=0.0.0.0:3480            # a UDP port; open it in your firewall
CAIRN_SFU_ADVERTISE=203.0.113.7:3480   # the public address clients send to (needed with 0.0.0.0)
```

and every room gets a voice channel. Without them there are none, and calls are the mesh only.
[ADR-012](adr/012-sfu-voice-channels.md) is the design.

**What it costs you.** All of a channel's audio crosses your connection: each speaker's
stream goes in once and out to every other participant, so egress grows as N×(N−1) Opus
streams — around 40 kbps each, so a full channel of 16 is roughly 10 Mbps out at worst, and
an ordinary handful of people far less. No video goes through it.

**What it lets you see**, and your users are told the same: who is in which channel, from
which IP address, and when; and the size and timing of each person's packets, which shows who
is speaking. In an end-to-end encrypted room you do **not** get the audio — frames are sealed
on the device before they reach you — unless a participant's client cannot seal, in which case
the call is badged transport-only for everyone and then you do.

**What it does not do yet.** It is not behind TURN, so a client whose network blocks the UDP
port cannot join a voice channel. Caddy does not proxy it; it is UDP straight to the instance.

## 3. Why TLS is not optional here

The server terminates no TLS of its own, and `docker-compose.yml` deliberately gives it no
published port — only Caddy is exposed.

MLS protects message **bodies** end to end, so an attacker on the network cannot read what
people say even over plain HTTP. That is a narrower guarantee than it sounds:

- Every user id, device id, and room id is visible, and ids are on every request.
- Who talks to whom, when, and how often is visible.
- An **active** attacker can modify everything around the ciphertext — including a
  registration request or a room membership change.

`docs/01-threat-model.md` §2 assigns A1 and A2 to the transport. Without TLS, they are
simply not defended. The client says so: connect it to an `http://` origin and the prompt
reads `plaintext-transport`, because a client that showed a clean encryption badge over a
plaintext connection would be claiming a protection that does not exist.

## 4. Connecting

You and your friend each run:

```bash
cargo run -p cairn-cli -- chat \
  --name alice \
  --server https://cairn.example.com \
  --invite <one of the tokens>
```

The invite is needed **on first run only**. The client records that the account was
claimed and never registers again — which matters, because the server checks the invite
before it notices an account already exists, so a second registration attempt would be
rejected even by its rightful owner.

Then, to talk:

1. Your friend runs `/username theirname` to claim a handle, then `/keys 5` to publish key
   packages. **Without published key packages nobody can add them to a room.**
2. You run `/dm @theirname`. That resolves the handle, creates the room, and adds them in one
   step. Raw `usr_...` ids still work if you prefer.
3. They run `/open rom_...` with the room id you were shown.
4. Both of you run `/safety` and compare the numbers **out of band** — on a call, or in
   person. If they match, no key substitution happened between the two of you. If they
   differ, stop.
5. `/verify <n>`, with the member's number from `/safety`, records that you compared them.
   It persists, and it confirms the number `/safety` printed: if their key changed in
   between, it refuses and asks you to compare again.

In the desktop client the same comparison is a click: select the person in the member list,
read the digits to each other, and press **Mark as verified**.

**Usernames now exist**, so step 1 can be `@alice` rather than a uuid — claim one once,
and it is yours. They resolve by **exact match only**: there is no search or directory, so
knowing a handle confirms an account exists but nobody can walk your instance for a list of
who is on it. Lookups are rate limited per account, because exact-match resolution stops
listing but not guessing.

**Invite links exist now.** A moderator runs `/invite [uses] [hours]` in the open room —
default one use, 24 hours — and the joiner runs `/join <token>`. The token is shown once;
the server keeps only a hash, so it cannot be recovered or read out of a backup. There is no
unlimited link, deliberately: an uncapped one is a public invite in all but name, and a
public invite to a T1 or T2 room would mean it should have been T3.

**Every MLS leaf now names the account that holds it.** The credential used to be a display
name the client chose for itself, which probing showed let one member present another's
label: every client displayed the impostor as that person, and because MLS refuses duplicate
identities, **the real person could then never join that room at all**. Credentials now carry
the account and device ids the instance already authenticates, checked both when a key
package is published and when one is claimed.

Two consequences for an operator. A client too old to name its account **cannot publish key
packages** to an upgraded instance and cannot be added to a room — everyone upgrades
together. And `/members` now prints account ids matching what `/roster` shows, so the
encrypted group and the server's member list can be compared by eye.

**Redeeming joins the room; it does not give you the keys.** The group's keys are held by
its members, not the instance, so nobody can hand them out on the strength of a token. Until
an existing member admits you to the encrypted group, the room is visible and unreadable. The
client says so rather than implying the door is fully open.

**Admitting is now one word.** When a member opens a room, the client compares the instance's
member list against the encrypted group's roster and names anyone who has joined but cannot
read yet. `/admit` lets all of them in. Nobody pastes a uuid and nobody coordinates out of
band — which is what M2's exit condition asked for.

It is deliberately **not automatic**, and the reason is worth keeping: the list of who is
waiting comes from the *instance*. Admitting on its word alone would let a malicious one name
an account of its choosing and have a moderator's client hand it the group keys, silently.
The server cannot add a leaf itself — it never sees group state — and automating this would
give it that power back through the front door. So the friction removed is the uuid, not the
decision.

**Superseded note.** Room ids and user ids are passed by hand. That is the main
piece of unfinished work between here and something you would hand to a non-technical
person (`docs/10-roadmap.md`, M3).

## 5. Back up the franking key

The data volume holds two things:

- `franking.key` — **the one that is not replaceable.** Losing it invalidates every abuse
  report the instance ever issued: a report filed last week cannot be verified once the key
  changes. It is minted on first start and then never rewritten.
- `cairn.redb` — accounts, rooms, messages, invites, **and attachments**. Attachment
  ciphertext lives in here, so this file grows with what people send, not just with how many
  of them there are. The per-attachment ceiling is `MAX_BLOB_BYTES` (25 MiB) — a deliberate
  floor-level default, since every byte is storage and egress you pay for.

```bash
mkdir -p backups && chmod 777 backups     # the image runs as an unprivileged user
docker compose stop cairn
docker compose run --rm -v "$PWD/backups:/backups" cairn backup "/backups/$(date +%F)"
docker compose start cairn
```

The image's entrypoint *is* `cairn-server`, so the subcommand is the first argument. That
writes both files plus a `backup.json` manifest, then **reopens what it just wrote and checks
it** before reporting success. Confirm an older backup at any time, without restoring it:

```bash
docker compose run --rm -v "$PWD/backups:/backups" cairn verify /backups/2026-08-10
docker compose run --rm -v "$PWD/backups:/backups" cairn restore /backups/2026-08-10 /data
```

`restore` writes only into an empty directory: it refuses if the destination already holds an
instance, since whoever is running it is usually having a bad enough day already.

### Why not just `cp`

The previous version of this section said to stop the instance and copy the two files, which
is correct and rests entirely on you remembering the first step. Probing what happens when
you do not:

| Instance | Result of `cp` on a live `cairn.redb` |
|---|---|
| Busy | Unopenable: `Failed to repair database. All roots are corrupted` |
| Idle | **Opens cleanly, every row present, looks like a perfectly good backup** |

So `cp` is not merely unreliable — it succeeds under exactly the conditions in which you
*test* your backup procedure, and fails under exactly the conditions in which you *need* it,
with the failure surfacing at restore time. `cairn-server backup` opens the database instead
of copying the file, so against a running instance it refuses and says so.

### The two files are one artifact

**Back up both, and keep them together.** A restore that brings back `cairn.redb` without
`franking.key` used to start cleanly and mint a replacement, which looked like a working
instance while every report filed before the restore had silently stopped verifying.

Both halves of that are now refused at startup:

- **Key missing**, database populated → refuses, and tells you to restore the key.
- **Key present but from a different instance** → refuses. This one used to start perfectly
  cleanly; the database now records a hash of the key it belongs to, so a separated pair is
  caught rather than served.

One limit, stated because it is real: an instance that was *already* running on a mismatched
pair before this change has no record of which key was the right one, so the first start
after upgrading adopts whatever key it finds. The check protects pairs that meet each other
from here on.

If you are upgrading an instance that predates the database, it will hold a `state.json`
instead. That is imported automatically on first start and **left in place**, so a rollback
to the previous release still finds its data. Nothing to do.

## 6. Running it at home, without publishing your home IP

A Raspberry Pi in a spare room is a legitimate deployment, and it is the reason paid
capacity on a flagship instance is acceptable (`13-customisation.md` §2): the alternative to
paying is real. But **every user of your instance connects to it**, and by default that means
every user learns your home IP address.

For three friends who already know where you live, that may be fine. For anything wider it
is a doxxing risk you cannot take back, and it is worth deciding *before* you hand anyone an
invite. Three options, in increasing order of what you give up.

### Do not publish it at all — WireGuard or Tailscale

Do not expose the instance to the internet. Put every device on a private overlay network
and let the instance listen only there.

Nothing to hide, because nothing is public: no port forwarding, no DNS record, no
certificate. **This is the best option for a friends test**, and the one to start with. What
you give up is that everyone needs the overlay client installed and configured, so it does
not scale past people who will tolerate that.

### A rented front door — VPS plus a tunnel back

Rent the cheapest VPS available, point your domain at *its* address, and tunnel from the Pi
to it over WireGuard. Users see the VPS. Your home IP appears in nothing public.

**Terminate TLS on the Pi, not on the VPS.** This is the part that matters and the part most
guides get wrong. A normal reverse proxy decrypts and re-encrypts, so the VPS sees every
request in the clear — all metadata, and in a T3 room the actual message content. Configure
the VPS as a **stream-level passthrough** instead (SNI routing, no TLS termination), and it
carries bytes it cannot read. It still sees who connects, when, and how much, which is the
metadata `01-threat-model.md` §3.1 already concedes — but it stops there.

What you give up: a few dollars a month, and the VPS provider becomes a party who can
observe traffic patterns.

### Hide it completely — a Tor onion service

An onion service has no IP address to leak, needs no port forwarding, no DNS, and no
certificate authority — the address authenticates the service by construction. For a
messaging instance the latency is tolerable.

What you give up: users need Tor, discovery is harder, and **calls are effectively out** —
real-time media over Tor is not viable.

### Two things a tunnel does not fix

- **A commercial tunnel that terminates TLS sees everything the VPS option was configured
  not to see.** Cloudflare Tunnel and similar are genuinely easy and genuinely hide your IP,
  but they decrypt your traffic to do it. That is a third party your users did not choose,
  with the same view of metadata your own instance has and, on T3 rooms, of content. If you
  use one, say so — running a privacy product through a provider you have not disclosed is
  exactly the kind of unstated protection gap this project refuses elsewhere.
- **Hiding the server's address does nothing for peer-to-peer calls.** ICE hands each peer
  the other's IP directly, so a call would leak the address you went to trouble to hide —
  and not only yours. [`12-realtime-media.md`](12-realtime-media.md) §10 makes relaying the
  default for this reason; if you are hiding your home IP, treat relaying as **mandatory**,
  not a default to turn off for bandwidth.

Also worth knowing before you start: many residential ISPs prohibit running servers, most
hand out dynamic addresses (so you need dynamic DNS), and an increasing number use CGNAT,
which makes inbound connections impossible without one of the options above regardless of
what you want.

## 7. Updating

```bash
git pull && docker compose up -d --build
```

The data volume is preserved. The database records a schema version, and a build **refuses
to open a database written by a newer build** rather than reading records under rules that
have since changed — so a bad downgrade is an outage, not silent corruption. Migrations
forward are automatic. Read the release notes anyway before updating an instance holding
conversations you care about.

---

## What is not ready

Honest list. Each of these is real and none is hypothetical.

**Will affect even a small friendly deployment:**

- **Rate limiting is partial.** Key package claims are now capped per account — 3 per
  target and 30 in total per hour — because probing confirmed the drain was real: one
  authenticated account emptied a victim's entire published supply in a tight loop, after
  which nobody could add that victim to a room until they came back online and published
  more, and the victim saw nothing.

  **What the cap does not do:** it bounds the rate, not the total. Several accounts can
  still drain a victim between them, one account can drain slowly across windows, and the
  counter lives in memory, so restarting the server clears it. Keep your published supply
  topped up (`/keys 10`) rather than treating this as solved.

  Message sending and attachment uploads are now capped per account over the same window,
  which bounds how fast one account can fill your disk — probing found one account storing
  300 MiB without a single refusal. Registration is capped per address (§2), which closes
  the loop: before it, accounts were free to mint, and each new one arrived with a fresh
  send and upload budget. **What none of these bound is an attacker with many addresses**,
  and every counter lives in memory, so a restart clears them all.
- **Message history is stored in the clear.** A restart now replays a room rather than
  losing it, which it could not do from the network — MLS discards each message key after
  use, so the server holds ciphertext your device can no longer open. The copy is written
  `0600` beside the client state that already sits there unencrypted. **Decided (owner)**,
  and superseded by the platform keystores when the native clients land. Concretely: a
  device that is taken is a conversation that is read. A room's disappearing-message timer
  governs the local copy too, so an expired message is deleted from disk rather than merely
  hidden.
- **Polling, not push.** The client fetches when you press enter.
- **Calls you ring are a peer-to-peer mesh of at most six.** Voice, video and screen sharing
  work in the desktop client, with media going directly between participants, so they cost
  your instance nothing — unless you run the optional TURN relay (§2), whose traffic is yours.
  **Voice channels** go through the SFU if you configure one (§2a): audio only, 16 people.
  The designed media server ([`12-realtime-media.md`](12-realtime-media.md) §2–§4) is
  unbuilt; worth reading before you plan an instance around it, because its egress scales
  with the square of the participant count — five people on 720p video is roughly 30 Mbps
  out, sustained.
- **Client state lives in the user's data directory** — `~/.local/share/cairn/<name>` on
  Linux (honouring `XDG_DATA_HOME`), `~/Library/Application Support/cairn/<name>` on macOS,
  `%APPDATA%\cairn\<name>` on Windows. Override with `CAIRN_HOME`.

  It used to default to a **temporary directory**, which on most Linux systems is cleared on
  reboot and is often `tmpfs` — RAM, never touching a disk. That meant a reboot destroyed
  the device key, the MLS group state, the contacts and the whole message history: the
  account and every conversation, gone. "History survives a restart" had been verified by
  restarting *processes*, never the machine. If you ran an earlier build, the client now
  prints where the old state is; move it across or delete it.
- **Client state is written unencrypted**, `0600` on Unix. **Decided (owner): platform
  keystores** — Keychain, Android Keystore, DPAPI, libsecret — behind an FFI seam, landing
  with the native clients. A passphrase-derived key was considered and rejected as a
  stopgap: it prompts on every launch and protects nothing while the client runs. Until
  keystores exist, **no linked social accounts**, because a session cookie is a credential
  and this is where it would sit. Anyone with read access to the
  account's home directory has the group keys. This is consistent with
  `docs/01-threat-model.md` §3.4, which does not claim to defend a compromised device — but
  it is weaker than a platform keystore, which is what a finished client would use.

  **On Windows there is no `0600`.** Every `restrict` in the tree is `#[cfg(unix)]` with a
  no-op fallback, because setting an ACL explicitly means calling Win32 through `unsafe`,
  which every crate here forbids. What protects the files instead is that they now sit under
  `%APPDATA%`, inside the user's profile, whose ACL grants that user, SYSTEM and
  Administrators and nobody else — inherited by everything beneath it. That is roughly
  equivalent, and it is inheritance doing the work rather than anything this code does.

- **Disappearing messages are purged lazily**, when someone next reads the room. An
  abandoned room keeps its messages until it is opened again, so the timer is an upper bound
  on what a *reader* sees rather than a guarantee about what is on disk at any instant. A
  background sweep would close that; it does not exist yet.

**Structural, and the reason this is pre-alpha:**

- **No external cryptographic review.** Scheduled for M5 and explicitly non-optional in
  `SECURITY.md`. Nobody outside the project has attacked this.
- **No key transparency.** Comparing safety numbers is the *only* defence against a
  malicious instance operator substituting keys. It works — but it is manual, per-peer, and
  protects exactly the conversations where someone bothered. §4 step 4 is not a formality.
- **Credentials are unauthenticated labels.** Two devices can present identical identity
  bytes; the server asserts the binding. Again: this is what the safety number check
  exists for.
- **No federation.** Instances do not interoperate (ADR-003), so everyone you talk to must
  be on your instance.
- **Registration is invite-only by default and should stay that way.** With open
  registration anyone can claim any *unused* user id — including one your friend was about
  to be assigned.

If you run this for a group of friends, tell them what it is. The one thing this project
will not do is claim a protection it does not have.
