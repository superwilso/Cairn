# Cairn desktop

The client from [ADR-008](../../docs/adr/008-client-architecture.md): one web UI, wrapped in
Tauri. Windows is the first target.

## Shape

```
ui/index.html       structure, and the inline SVG icon set
ui/style.css        the whole design, hand-written, no framework
ui/app.js           the DOM — rooms, timeline, members, safety numbers, call controls
ui/call.js          WebRTC: peer connections, devices, screen share
src-tauri/          the shell — Tauri commands, each a one-line delegation to Rust
```

Everything the UI can do goes through `cairn_client_core::session::Session`. **The FFI line
falls between Rust and JavaScript**: `src-tauri` is below it, `ui/` is above it, and the UI
only ever receives plain data. It never constructs an envelope, decides a tier, or touches a
key — the rule [ADR-006](../../docs/adr/006-platform-architecture.md) drew for five native
clients and [ADR-008](../../docs/adr/008-client-architecture.md) kept when it replaced them
with one.

If a command in `src-tauri/src/main.rs` grows past forwarding a call, that is logic leaking
upward and it belongs in `client-core`.

## No frontend dependencies

Deliberate. This is a security product with a small supply chain as a stated value, and a
chat window does not need a framework and 300 transitive packages to render a list. There is
no `package.json`, no bundler, and nothing to audit but the three files in `ui/`.

## Running it

```bash
# Linux dev box — needs the platform webview
sudo apt install libwebkit2gtk-4.1-dev librsvg2-dev

cargo run -p cairn-desktop
```

Point it at an instance (`http://127.0.0.1:8080` by default; run one with
`cargo run -p cairn-server`).

**The invite code field on the sign-in card is a *registration* invite, not a room one.**
The server's registration policy defaults to `InviteOnly` and `docs/11-self-hosting.md`
recommends keeping it that way, so an operator hands one out per person:

```bash
CAIRN_REGISTRATION_POLICY=invite_only CAIRN_INVITES=first-friend-q8w2e7r4,second-friend-z5x1c9v3 \
  cargo run -p cairn-server
```

It is ignored once a profile has registered — the instance checks the invite *before* it
notices the account already exists, so a returning user presenting a spent token would
otherwise be locked out of their own account.

## Building for Windows

**Must happen on Windows.** Tauri packages against the platform's own webview — WebView2 on
Windows, WebKitGTK on Linux — and produces an installer with NSIS or WiX. Cross-compiling
that from Linux is not practical, so this repository builds it on the `windows-latest`
runner or on a Windows machine:

```powershell
cargo tauri build          # produces .msi and .exe installers
```

Windows ships WebView2 on Windows 11 and on most Windows 10 installs; Tauri's installer can
bootstrap it where it is missing.

**What that means for verification:** the Linux build here proves the Rust compiles, links
and runs against a real instance. It does **not** prove the Windows packaging works — that
needs a run on Windows, and nothing in this repository has done one yet.

## Group chats

The reason this landed when it did. Before it, no client could create a group at all: the
CLI hardcoded `is_direct: true, member_ceiling: 2`, so every room was a two-person DM.

- **New group** makes a room that is not direct and not publicly discoverable, which
  `derive_tier` seals as **T2 — still end-to-end encrypted**. A group is not weaker than a
  DM. Only *discoverability* drops a room to T3.
- **Invite / Join** carries someone into the room without anybody pasting a user id.
- **Admit** is the step that matters and is deliberately a button rather than automatic.
  Redeeming an invite joins the room; it does not hand over the group keys, because the keys
  belong to the members and not to the instance. Someone already in the group has to let a
  joiner in — and the list of who is waiting comes from the *instance*, so admitting on its
  word alone would let a malicious one name an account and have this client hand it the
  keys silently.

The member panel shows the distinction rather than flattening it: someone in the room but
not in the encrypted group is marked, because they cannot read a word of it. The reverse is
marked too: someone who holds a leaf in the encrypted group but whom the instance's member
list leaves out appears as **unlisted** rather than not at all. The list is the instance's to
write, and a reader of the room must not vanish because it omitted them.

## Safety numbers

Click anyone in the encrypted group to see the safety number for each of their devices —
twelve groups of five digits, the same number they see on their side. Compare it in person
or on a call the instance does not carry; if every digit matches, press **Mark as verified**.
The member list then shows a tick, and only when *every* device of that account has been
compared.

What the panel does and does not claim:

- **A match covers two people.** It proves the keys between you and that person were not
  swapped. It says nothing about anyone else in the group, each of whom has their own number.
- **The number is computed in Rust from the encrypted group's own roster**
  (`cairn_client_core::verify`), never from a key the instance published. A number built from
  the instance's directory matches on both ends of an interception — `docs/01-threat-model.md`
  §4 records the version of this that did exactly that.
- **The button confirms the number you were shown, not whatever is there when you click.**
  The page hands the displayed string back and Rust refuses it if the key changed while the
  panel was open.
- **A key that changes after you verified it stays flagged** — *key changed* in the member
  list and a red warning in the panel — until you compare the new number. A reinstall and an
  interception look identical here, which is exactly why it is not cleared automatically.
- Unverified is the default, and the honest one.

Verification state lives in the profile's `contacts.json`, shared with `cairn-cli chat` when
both use the same profile.

## Calls

Voice, video and screen sharing, as a **mesh**: every participant holds a direct peer
connection to every other, and media never touches the instance. There is no SFU to deploy
and nothing for an operator to pay for. The cost is why an SFU exists — everyone uploads
their stream once per other participant — so a call is capped at `MAX_MESH_PARTICIPANTS`
(6) and says so out loud rather than letting everyone blame their broadband.

The cap is enforced per *peer connection*, in the frontend, because that is the only place
the number is real. An earlier version checked the room's size in Rust instead, which meant a
group chat of eight could not hold a call between two of them — and the error blamed the
room. See
[`docs/12-realtime-media.md`](../../docs/12-realtime-media.md) for where this goes next.

**Signalling rides inside the encrypted message body.** An SDP offer names your codecs, your
ICE candidates and your IP addresses; carrying it beside the ciphertext would hand all of
that to an instance that only needs to relay a blob. `crates/cairn-server/tests/group_chat_session.rs`
has a test that reads what the instance actually stored and asserts the SDP is not in it.

Two things the UI states rather than hides, because both are real:

- **No TURN relay is configured**, so calls fall back to STUN alone and will fail to connect
  across some home networks. The client says so when a connection fails instead of leaving
  someone to blame their broadband.
- **A mesh call shows every participant every other participant's IP address.** That is what
  peer-to-peer media means. A relay is the only thing that changes it, and a relay costs an
  operator bandwidth.

### Known gap: microphone permission on Linux

`wry` registers a WebView2 permission handler for the clipboard only, so on Windows a call
raises WebView2's own microphone/camera prompt and works. On Linux, WebKitGTK's
`permission-request` signal is unhandled and its default is **deny** — so `getUserMedia`
fails and calls cannot start. Chat is unaffected.

The fix is a `permission-request` handler reached through `with_webview`, which means a
Linux-only `webkit2gtk` dependency on this crate. Not taken yet because Windows is the
target; recorded here so it is a decision rather than a mystery.

## Attachments

Photos and files go through the paperclip, a drop onto the conversation, or a paste. The
bytes cross the IPC boundary as a raw body — not a JSON array, which would make a 25 MiB
photo about 100 MB of text — and Rust seals, uploads and sends them; `ui/attachments.js`
never sees a key. A sender's claimed type decides nothing on its own: Rust maps it to
`image` (PNG, JPEG, GIF, WebP — never SVG), `audio`, or `file`, and only the first two are
ever turned into something the webview renders. A file is only offered as **Save**, which
Rust writes into Downloads under a sanitised name without overwriting anything.

Two settings in `tauri.conf.json` exist for this and are easy to undo by accident:

- `connect-src ipc: http://ipc.localhost` — Tauri's own local IPC endpoints, not remote
  origins. Without them the webview cannot reach the `ipc:` protocol, Tauri silently falls
  back to `postMessage`, and every binary payload is re-encoded as JSON numbers.
- `dragDropEnabled: false` — hands file drops to the page. With it on, Tauri consumes them.

Honest limits: one request per file, up to 25 MiB, no resume. The attachment key is stored
beside the local transcript (same file, same `0600`) so yesterday's photo still opens; the
instance does not yet delete blobs, so a disappearing timer removes this device's key but
not the server's ciphertext.

## What it does not do yet

Link cards and disappearing-message controls exist in `client-core` and are not yet
surfaced in this UI. Safety numbers are compared by reading digits aloud; there is no QR
code to scan yet.

## The icon

Drawn by [`scripts/make-icon.py`](../../scripts/make-icon.py) — a rasteriser, PNG encoder and
ICO writer on zlib and struct alone, because the development container has neither Pillow nor
ImageMagick. Run it after changing the mark.

It exists because of two things found by probing. The `icon.png` that was here was a
placeholder: 512x512 pixels of a single colour, which reads as an icon in a file listing and
ships as a flat blue square. And `tauri-build` **hard-errors** on Windows without
`icons/icon.ico` — so the release build would have failed on the runner rather than here.
