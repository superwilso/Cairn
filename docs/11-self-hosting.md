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

1. Your friend runs `/keys 5` to publish key packages, and `/whoami` to get their user id.
   **Without published key packages nobody can add them to a room.**
2. You run `/dm usr_...` with their id. That creates the room and adds them in one step.
3. They run `/open rom_...` with the room id you were shown.
4. Both of you run `/safety` and compare the numbers **out of band** — on a call, or in
   person. If they match, no key substitution happened. If they differ, stop.
5. `/verify 0` records that you compared them. It persists.

**There is no invite link yet.** Room ids and user ids are passed by hand. That is the main
piece of unfinished work between here and something you would hand to a non-technical
person (`docs/10-roadmap.md`, M3).

## 5. Back up the franking key

The data volume holds two files:

- `franking.key` — **the one that is not replaceable.** Losing it invalidates every abuse
  report the instance ever issued: a report filed last week cannot be verified once the key
  changes. It is regenerated silently on first start, so a lost key looks like a working
  instance.
- `state.json` — accounts, rooms, messages, invites.

```bash
docker compose stop cairn
docker compose run --rm -v "$PWD:/backup" cairn \
  sh -c 'cp /data/franking.key /data/state.json /backup/'
docker compose start cairn
```

Stopped first because the server rewrites `state.json` wholesale on every message, so a
copy taken while it is running can catch a rename in progress. Restore by putting both
files back into the volume before starting.

## 6. Updating

```bash
git pull && docker compose up -d --build
```

The data volume is preserved. There is no schema migration story yet, so read the release
notes before updating an instance holding conversations you care about.

---

## What is not ready

Honest list. Each of these is real and none is hypothetical.

**Will affect even a small friendly deployment:**

- **No rate limiting.** An authenticated account can drain another account's key packages,
  after which nobody can add that person to a room until they publish more. There is
  nothing throttling registration or sending either.
- **Storage rewrites all state on every message.** It is O(messages) per message, so cost
  grows quadratically with the conversation. Fine for a handful of people for a while;
  not fine indefinitely, and it is why link previews carry no images yet.
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
