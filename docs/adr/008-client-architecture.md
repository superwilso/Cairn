# ADR-008: One web client, wrapped in Tauri

**Status:** Accepted. **Supersedes [ADR-006](006-platform-architecture.md).**

## Context

ADR-006 committed to five separate native UIs — WinUI 3, SwiftUI, GTK4, AppKit, Jetpack
Compose — over one shared Rust core, and rejected Electron, Tauri, Flutter and React Native
because *"native" is the requirement that shapes everything*.

That requirement has been reconsidered, and the honest accounting is:

- **Five native UIs is the largest single cost in this project**, larger than the server,
  larger than the crypto. Nothing had been built against it, so nothing is sunk.
- **It is what stands between here and voice and video.** A media client needs device
  capture, echo cancellation, jitter buffering, codec negotiation and an SFU connection.
  Written natively, that is five times over, per platform, in five languages.
- **The browser already has all of it.** WebRTC is a maintained, hardened, universally
  deployed media stack. `12-realtime-media.md` calls calls "the largest component the
  project has considered"; WebRTC removes most of that component.

ADR-006 itself called Tauri "the closer call" among the options it rejected — "it would
have been much cheaper — but it delivers a webview, not a native UI."

## Decision

**One web client. Tauri for desktop. The Rust core stays.**

- **UI:** one web codebase, served in a browser and wrapped by Tauri on Windows, macOS and
  Linux. A Tauri bundle is around 10 MB against Electron's ~150 MB, because it uses the
  platform's existing WebView rather than shipping a browser.
- **Media:** WebRTC, in the WebView. Capture, echo cancellation, jitter buffers, codec
  negotiation and simulcast come from the platform rather than from us.
- **Core:** `cairn-proto`, `cairn-crypto` and `cairn-client-core` keep their jobs. Tauri
  invokes the Rust core natively; the browser build reaches it through WebAssembly.
- **Mobile:** deferred. Tauri's mobile support exists but is young; a responsive web client
  covers phones adequately until it is worth revisiting.

## What this costs, plainly

**It is not a native app and will not feel like one.** That was ADR-006's whole thesis and
it is now given up deliberately, not overlooked. Cairn will feel like Discord and Slack feel,
because it will be built the way they are built.

**In a browser, the server serves the code.** An instance that ships malicious JavaScript can
read anything the client can, so browser-delivered end-to-end encryption is a weaker claim
than the same code in a signed binary. This does not break the tier model — it bounds it, and
`01-threat-model.md` must say so rather than leaving a reader to assume otherwise. The Tauri
build is materially stronger here, since the code is shipped and signed rather than fetched
per session, and that difference should be visible to a user choosing between them.

**One UI everywhere means it fits nowhere perfectly.** Accepted.

## What it buys

Cross-platform on day one. Voice, video and screen share within reach instead of behind five
native media integrations. One place to fix a bug. And a contributor can work on the client
with web skills rather than five native toolkits — which matters for a project that intends
to be open source.

## Alternatives reconsidered

**Keeping ADR-006.** Rejected: the native feel is not worth five media stacks and a
multi-year client timeline for a project with no users yet.

**Electron.** Rejected: ~150 MB per install for the same result Tauri gives at ~10 MB.

**Web only, no Tauri.** Rejected: no signed binary, no tray, weaker notifications, and the
browser-serves-the-code problem with nothing better alongside it.
