# ADR-006: Shared Rust core, native UI per platform

**Status:** Accepted
**Date:** 2026-08-04

## Context

The goal is native applications on **Windows, macOS, Linux, iOS, and Android**, with
servers hostable on **Windows, Linux, and macOS** (and possibly repurposed old phones
later). Windows desktop and a Linux server come first; UI work follows the protocol.

"Native" is the requirement that shapes everything. It rules out the Electron approach
that most open-source chat apps take, and it creates a problem: five clients means five
chances to implement the protocol slightly differently, and in a security product that
means five different sets of vulnerabilities.

## Decision

**One shared Rust core; a thin native UI per platform; no protocol logic above the FFI
line.**

```
┌──────────┬──────────┬──────────┬──────────┬──────────┐
│ Windows  │  macOS   │  Linux   │   iOS    │ Android  │
│ WinUI 3  │ SwiftUI  │   GTK4   │ SwiftUI  │ Compose  │
└─────┬────┴─────┬────┴─────┬────┴─────┬────┴─────┬────┘
      └──────────┴─────┬────┴──────────┴──────────┘
                       │  FFI (uniffi / C ABI)
      ┌────────────────▼─────────────────┐
      │  cairn-client-core   (Rust)      │
      │  cairn-crypto  ·  cairn-proto    │
      └──────────────────────────────────┘
```

**The line is absolute: everything that touches the protocol, cryptography, storage, or
tier enforcement lives below the FFI boundary.** The UI layer draws, handles input, and
calls the core. A platform UI must never construct an envelope, decide a tier, or touch a
key. `cairn-client-core` must never gain a UI dependency.

### Bindings

Use **UniFFI** to generate Kotlin and Swift bindings, and a plain C ABI for the desktop
targets that need it. `mls-rs` being synchronous by default
([ADR-005](005-protocol-core.md)) is what makes this tractable — no async runtime has to
be pumped across the boundary.

### Platform choices

| Platform | UI toolkit | Rationale |
|---|---|---|
| Windows | WinUI 3 / WinAppSDK | Genuinely native; the first client target |
| macOS | SwiftUI | Native; shares most view code with iOS |
| Linux | GTK4 + libadwaita | Best native fit; strongest match for the likely early adopters |
| iOS | SwiftUI | Only realistic native option |
| Android | Jetpack Compose | Current native standard |

### Server

Pure Rust, no platform-specific dependencies, so Linux/Windows/macOS come from one source
tree. Linux is the primary supported and tested target; the others are best-effort and
CI-verified. Old phones as servers is a plausible later target given Rust's ARM support,
but is explicitly not a v1 goal and should not constrain any decision now.

## Consequences

### Positive

- The protocol is implemented once. A cryptographic fix lands everywhere at once.
- Each app feels genuinely native, which is the differentiator against every
  Electron-based competitor.
- Rust cross-compiles to all five targets already.
- The core is testable without any UI, which is why the current test suite covers the
  security-critical paths with no UI in existence.

### Negative

- **Five UIs is a large, permanent cost** — the single biggest ongoing expense in the
  project, and the most likely thing to be under-resourced.
- FFI is a real surface. Bindings are where memory-safety guarantees get lost; they need
  the same review discipline as the crypto.
- Platform-specific behaviour (push notifications, background execution, key storage) does
  not abstract cleanly and will leak into the core's API.
- Requires contributors fluent in Rust *and* the platform toolkits.

### Sequencing

1. Shared core — **in progress**, this scaffold
2. Headless CLI client — **done**, `cairn-cli`
3. Windows desktop client (UI deferred at the user's request)
4. Linux desktop, then Android, then macOS/iOS

## Alternatives rejected

**Electron or Tauri everywhere.** Rejected: not native, which is the explicit requirement.
Tauri was the closer call — it would have been much cheaper — but it delivers a webview,
not a native UI.

**Flutter / React Native.** Rejected: one non-native UI everywhere, and it would still need
the Rust core for crypto, so it saves less than it appears to.

**Independent native implementations per platform.** Rejected outright: five
implementations of MLS and franking is five sets of security bugs.
