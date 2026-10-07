# Cairn desktop

The client from [ADR-008](../../docs/adr/008-client-architecture.md): one web UI, wrapped in
Tauri. Windows is the first target.

## Shape

```
ui/index.html       structure, and the inline SVG icon set
ui/style.css        the whole design, hand-written, no framework
ui/app.js           the DOM — rooms, timeline, members, call controls
ui/call.js          WebRTC: peer connections, devices, screen share
ui/timer.js         the disappearing-message control and its notices
ui/messages.js      drawing a message; replying and reacting to it
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
no `package.json`, no bundler, and nothing to audit but the files in `ui/`.

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
CAIRN_REGISTRATION_POLICY=invite_only CAIRN_INVITES=first-friend,second-friend \
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
not in the encrypted group is marked, because they cannot read a word of it.

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

## Disappearing messages

The clock in the room header is the room's timer: off, 5 minutes, 1 hour, 1 day or 1 week.
Any member may set it (`docs/10-roadmap.md`), and `ui/timer.js` only displays and forwards —
`Session::set_room_timer` sets it, and `Session::poll` re-reads it every ten seconds, because
another member may change it from any client and the instance does not push. A change is
announced in the timeline, unattributed: the instance does not say who made it, and a name
taken from a message would be that sender's claim.

While the room is open, polling also sweeps the transcript on disk and tells the UI which
messages to take off the screen. Before this, an expired message was only deleted locally
the next time the room was opened.

**A new timer reaches back.** The instance measures every stored message against the
current setting, so turning a timer on deletes messages already older than it — not only
future ones. The dropdown says so before a value is picked.

## Replies and reactions

Hover a message for **react** and **reply**; double-click it to send a heart; on a touch
screen, swipe it right to reply. Clicking your own reaction takes it back. One reaction per
person per message — a new one replaces the old.

Both travel inside the encrypted body and name their target by its franking commitment,
which every member already holds, so the instance learns nothing it did not already know.
What they deliberately do **not** carry:

- **A reply carries no quoted text.** Each recipient's client looks the original up in its
  own transcript (`cairn_client_core::thread`). A sender cannot misquote anyone, and a quote
  cannot outlive a disappearing message: when the original expires, the quote reads
  "Original message unavailable" — on screen at once, and on disk.
- **A reaction names no reactor.** It is attributed to the envelope's sender, so there is
  nothing to forge. Text is refused as a reaction, by the sender's client and again by every
  recipient's.

**A reaction cannot be reported.** Franking commits to a message's body, and a reaction's
body is empty. A report can prove what a reply said, not which message it answered.



Attachments, link cards and safety-number comparison all exist in `client-core` and are not
yet surfaced in this UI.

## The icon

Drawn by [`scripts/make-icon.py`](../../scripts/make-icon.py) — a rasteriser, PNG encoder and
ICO writer on zlib and struct alone, because the development container has neither Pillow nor
ImageMagick. Run it after changing the mark.

It exists because of two things found by probing. The `icon.png` that was here was a
placeholder: 512x512 pixels of a single colour, which reads as an icon in a file listing and
ships as a flat blue square. And `tauri-build` **hard-errors** on Windows without
`icons/icon.ico` — so the release build would have failed on the runner rather than here.
