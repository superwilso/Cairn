# Cairn desktop

The client from [ADR-008](../../docs/adr/008-client-architecture.md): one web UI, wrapped in
Tauri. Windows is the first target.

## Shape

```
ui/                 the interface — plain HTML, CSS and JS, no build step and no npm tree
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

## What it does not do yet

Voice and video. WebRTC is the reason ADR-008 chose this architecture, and it is the next
piece — nothing here touches media yet.

Attachments, link cards, safety-number comparison and disappearing-message controls all
exist in `client-core` and are not yet surfaced in this UI.
