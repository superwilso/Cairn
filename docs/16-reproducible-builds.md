# 16 — Reproducible builds: where things stand

**Status:** investigation, October 2026. Nothing here is a release process yet, and Cairn
does not claim reproducible builds anywhere. This records what was measured, what was not,
and what a release would need before the claim could be made.

## Why it matters here

The threat model lists an instance serving backdoored client code as something a server
operator can do (`01-threat-model.md` §4), and the answer there is native clients that are
reproducibly built. A reproducible build is what turns "the binary was built from this
source" from a promise into something anyone can check: rebuild, compare hashes. For the
server it matters less to users — they cannot see what an instance runs either way — but it
is what lets a self-hoster confirm that the image they pulled is the source they read.

## What was measured

The release profile (`Cargo.toml`: `opt-level = 3`, thin LTO, `codegen-units = 1`,
`strip = true`), `--locked`, Rust 1.97 stable on x86_64 Linux, building `cairn-server` and
`cairn-cli`:

| Two builds that differ in | Result |
|---|---|
| Nothing but the checkout's location (`…/a` vs `…/bb/deeper/b`) | **byte-identical**, both binaries |
| The cargo home (`/root/.cargo` vs another directory) | **differ** |
| The cargo home, with `--remap-path-prefix=<cargo home>=/cargo` | **byte-identical** |

So the Rust side is close to reproducible already, and for a specific reason each way:

- **Workspace paths do not leak.** Cargo passes workspace members to rustc by relative path,
  so where the repository is checked out does not reach the binary. Nothing in the
  server or CLI embeds a build time or a git hash, and no crate below the desktop app has a
  build script that would.
- **Dependency paths do.** Panic locations and similar strings carry the absolute path of
  each dependency's source under `$CARGO_HOME/registry/src/…` — a stripped server binary
  still held 372 of them. Two builders with different home directories get different
  bytes. Remapping the prefix removes every one (0 left) and the hashes then match.
  Cargo's `trim-paths` profile option would do this declaratively, but it is still
  unstable in 1.97, so `--remap-path-prefix` through `RUSTFLAGS` is the stable way.

## What was not measured

- **The Docker image.** No Docker daemon was available for this pass. The build stage
  runs at fixed paths (`/src`, the image's own `/usr/local/cargo`), so by the result above
  two builds from the same base image should give the same binary. But `rust:1.88-bookworm`
  is a tag, not a digest. A rebuilt tag can bring a different linker or C compiler, which
  would change the output, and the runtime stage's `apt-get install` gives different image
  layers on every build even when the binary is identical. So the *binary* inside could be
  reproducible while the *image* is not.
- **The desktop client.** `cairn-desktop` needs WebKitGTK to build, which this environment
  does not have, and its installers (NSIS, MSI, deb, AppImage) add packaging timestamps and
  signatures of their own. This is where reproducibility matters most, per the threat
  model, and it has not been looked at.
- **Other architectures and operating systems.** Only x86_64 Linux. Windows and macOS
  toolchains embed their own metadata (PE timestamps, code signatures), and each needs its
  own investigation.
- **Toolchain drift.** Every comparison used one rustc. Different compiler versions give
  different binaries, which is expected and is why a release must name its toolchain.

## What a reproducible release would need

In rough order of cost:

1. **Pin the toolchain per release**, by exact version — the Dockerfile already pins
   1.88, but the release workflow uses `stable`.
2. **Remap the cargo home** in release builds: `RUSTFLAGS="--remap-path-prefix=$CARGO_HOME=/cargo"`,
   until `trim-paths` stabilises.
3. **Pin base images by digest** in the Dockerfile, and accept that the image as a whole
   is not reproducible because of `apt-get`. Publish the server *binary's* hash, which is
   the part a verifier can rebuild.
4. **Publish hashes with each release**, and a documented command that rebuilds and
   compares. This step turns the property into something people can check rather than
   something they are told.
5. **Investigate the desktop bundles** separately: `SOURCE_DATE_EPOCH` for the Linux
   packages, and what Tauri's Windows bundler embeds. This needs a machine with the webview
   packages and probably a Windows runner.
6. **A CI job that builds twice and compares**, so a dependency that starts embedding a
   timestamp breaks the build, not the claim. The two-path check above takes two release
   builds, which is too slow for every push. It fits the release workflow or a weekly
   schedule.

Until (1)–(4) exist for a given artefact, nothing should say Cairn's builds are
reproducible. The feature-parity table's "🎯 v2" target is still the honest description.
