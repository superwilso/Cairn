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
an account on your instance. A guessable token is an open instance.

Check it came up:

```bash
docker compose logs cairn | grep listening
curl -s https://cairn.example.com/health
```

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
   person. If they match, no key substitution happened. If they differ, stop.
5. `/verify 0` records that you compared them. It persists.

**Usernames now exist**, so step 1 can be `@alice` rather than a uuid — claim one once,
and it is yours. They resolve by **exact match only**: there is no search or directory, so
knowing a handle confirms an account exists but nobody can walk your instance for a list of
who is on it. Lookups are rate limited per account, because exact-match resolution stops
listing but not guessing.

**There is no invite link yet.** Room ids and user ids are passed by hand. That is the main
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
docker compose stop cairn
docker compose run --rm -v "$PWD:/backup" cairn \
  sh -c 'cp /data/franking.key /data/cairn.redb /backup/'
docker compose start cairn
```

Stopped first: the database is crash-consistent, but a plain `cp` of a live one is not a
snapshot, and the two files must be restored as a matched pair.

**Back up both, and keep them together.** A restore that brings back `cairn.redb` without
`franking.key` used to start cleanly and mint a replacement key, which looked like a working
instance while every report filed before the restore had silently stopped verifying. The
server now refuses to start in that state and tells you to restore the key — but that only
converts silent damage into a visible outage. The backup is still your responsibility.

If you are upgrading an instance that predates this change, it will hold a `state.json`
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
  topped up (`/keys 10`) rather than treating this as solved. **Registration and message
  sending are still unthrottled.**
- **No message history on the client.** Messages arrive by polling and scroll past. A
  restart does not replay them — it cannot, because MLS discards each message key after
  use.
- **Polling, not push.** The client fetches when you press enter.
- **No voice, video, or screen sharing.** Designed, unbuilt, and behind the native clients
  ([`12-realtime-media.md`](12-realtime-media.md)). Worth reading before you plan an
  instance around it: a media server's egress scales with the square of the participant
  count — five people on 720p video is roughly 30 Mbps out, sustained — so calls are the
  point where a self-hosted instance stops being bandwidth-negligible.
- **Client state is written unencrypted**, `0600` on Unix. **Decided (owner): platform
  keystores** — Keychain, Android Keystore, DPAPI, libsecret — behind an FFI seam, landing
  with the native clients. A passphrase-derived key was considered and rejected as a
  stopgap: it prompts on every launch and protects nothing while the client runs. Until
  keystores exist, **no linked social accounts**, because a session cookie is a credential
  and this is where it would sit. Anyone with read access to the
  account's home directory has the group keys. This is consistent with
  `docs/01-threat-model.md` §3.4, which does not claim to defend a compromised device — but
  it is weaker than a platform keystore, which is what a finished client would use.

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
