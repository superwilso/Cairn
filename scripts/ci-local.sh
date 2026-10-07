#!/usr/bin/env bash
# Everything .github/workflows/ci.yml runs, on this machine, before it costs anything.
#
# Why this exists: a red CI run costs a round trip — push, wait for three platforms, read
# the log, push again — and a failure caught here costs nothing. It was first written when
# the repository was private and every macOS minute was billed 10x; that is no longer true,
# but the round trip still is.
#
# It must stay a faithful copy of the workflow. The two are easy to let drift, and a local
# check that is *weaker* than CI is worse than none — it produces confidence CI then
# contradicts. Specifically mirrored, and each one was missing from ad-hoc local runs:
#
#   - RUSTFLAGS: -D warnings          (set globally in the workflow, applies to every job)
#   - cargo test --all-targets        (not the same set as plain `cargo test`)
#   - cargo run -p cairn-cli          (the vertical slice; a job of its own in CI)
#   - cargo check under 1.85          (the MSRV floor)
#   - cargo audit
#
# **One thing this can never check: the runner's system packages.** `cairn-desktop` links
# GTK and WebKitGTK on Linux, and a development machine has those installed by definition —
# it could not have built the client otherwise. A GitHub runner does not, and every Ubuntu
# job failed in twelve seconds on `glib-2.0 was not found` while this script and the Windows
# job both passed. The workflow now installs them; the check below is the closest a local
# run can get, which is to notice if that step ever disappears.
#
# Usage:
#   scripts/ci-local.sh           everything that can run here
#   scripts/ci-local.sh quick     fmt + clippy + tests only, for a tight loop
set -uo pipefail

export CARGO_TERM_COLOR=always
export RUSTFLAGS="-D warnings"

MODE="${1:-full}"
FAILED=()
PASSED=()

run() {
    local name="$1"; shift
    printf '\n\033[1m── %s ─────────────────────────────────\033[0m\n' "$name"
    if "$@"; then
        PASSED+=("$name")
    else
        FAILED+=("$name")
        printf '\033[31mFAILED: %s\033[0m\n' "$name"
    fi
}

# ---- what a local run structurally cannot verify --------------------------
# Two failures have now reached `main` green from here and red on CI, both from the same
# shape of gap: this machine is more privileged and better equipped than the runner.
#
#   1. Missing system packages. `cairn-desktop` links WebKitGTK; a machine that can build it
#      has the headers by definition, and the runner does not.
#   2. Running as root. `statedir::prepare` chmod'ed the state directory's *parent*, which
#      for a test is `/tmp` — root can chmod it, an ordinary user cannot, and thirteen tests
#      died on EPERM.
#
# Neither is fixable by running more checks here. What is fixable is noticing.
if [ "$(id -u 2>/dev/null)" = "0" ]; then
    printf '\n\033[33mNOTE: running as root. CI does not.\n'
    printf 'Anything gated on file ownership or permissions — chmod on a shared directory,\n'
    printf 'writing outside the workspace — will succeed here and can still fail there.\033[0m\n'
fi

# Not a substitute for the real thing, just a tripwire: if the workflow stops installing the
# Linux webview packages, a local run will still pass and CI will still fail. This at least
# makes the omission visible here rather than after a push.
if ! grep -q 'libwebkit2gtk-4.1-dev' .github/workflows/ci.yml; then
    printf '\n\033[33mWARNING: ci.yml no longer installs libwebkit2gtk-4.1-dev.\n'
    printf 'cairn-desktop will fail to build on the Ubuntu runners, and this machine\n'
    printf 'cannot reproduce that because it already has the package.\033[0m\n'
fi

# ---- lint job -------------------------------------------------------------
run "fmt --check"          cargo fmt --all --check
run "clippy --all-targets" cargo clippy --workspace --all-targets

# ---- test job (this platform only; see cross-check below) -----------------
run "test --all-targets"   cargo test --workspace --all-targets
run "vertical slice"       cargo run -p cairn-cli

# ---- desktop job ----------------------------------------------------------
# The call mesh is JavaScript, and `cargo test` cannot see a line of it. Who offers, whether
# an early ICE candidate survives, whether turning a camera on renegotiates -- all decided in
# ui/call.js, and every failure there looks like a network fault rather than a bug.
if command -v node >/dev/null 2>&1; then
    run "desktop mesh tests" node --test clients/desktop/tests/mesh.test.js

    # And the same code against two real browsers, which is the only thing that catches an
    # SDP-level fault: a transceiver the answering side pre-created and the offer would not
    # reuse made every call connect cleanly and carry video one way only. Skips itself, with
    # a note, when Playwright's Chromium is not present.
    if [ "$MODE" != "quick" ]; then
        run "desktop call in a browser" \
            env PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers \
                NODE_PATH="${NODE_PATH:-/opt/node22/lib/node_modules}" \
                node --test clients/desktop/tests/call.browser.test.js
    fi
else
    printf '\n\033[33mSKIPPED desktop tests: node is not installed\033[0m\n'
fi

# Every icon the bundle config names must exist. `tauri-build` hard-errors on Windows
# without icons/icon.ico -- so a missing file does not fail here, it fails 20 minutes into a
# Windows runner.
run "bundle icons present" python3 - <<'PYCHECK'
import json, sys
from pathlib import Path
root = Path("clients/desktop/src-tauri")
config = json.loads((root / "tauri.conf.json").read_text())
missing = [i for i in config["bundle"]["icon"] if not (root / i).is_file()]
if missing:
    sys.exit("missing bundle icons: " + ", ".join(missing))
print("all", len(config["bundle"]["icon"]), "bundle icons present")
PYCHECK

if [ "$MODE" != "quick" ]; then
    # ---- msrv job ---------------------------------------------------------
    # The floor is a hard requirement: the crypto tree needs edition2024, stabilised in
    # exactly 1.85. A dependency bump that quietly raises it is the failure this catches.
    if rustup toolchain list 2>/dev/null | grep -q '^1\.85'; then
        # Excludes the desktop app deliberately: Tauri's tree needs rustc 1.88. The floor
        # exists so the protocol and crypto *libraries* stay consumable at a known minimum;
        # a desktop binary is not something anyone builds against. Same exclusion in CI.
        run "msrv 1.85 check" cargo +1.85.0 check --workspace --exclude cairn-desktop
    else
        printf '\n\033[33mSKIPPED msrv: rustup toolchain install 1.85.0\033[0m\n'
    fi

    # ---- audit job --------------------------------------------------------
    # A vulnerable dependency in a security product is a release blocker.
    if command -v cargo-audit >/dev/null 2>&1; then
        run "cargo audit" cargo audit
    else
        printf '\n\033[33mSKIPPED audit: cargo install cargo-audit --locked\033[0m\n'
    fi

    # ---- the part CI does that this machine cannot ------------------------
    # Windows and macOS get a *compile* check, never a test run, and only of the crates that
    # will cross-compile at all.
    #
    # Two honest limits, because a local check that overstates itself is worse than none:
    #
    #   1. --no-default-features is required. With default features the tree pulls `ring`
    #      through rustls, whose build script needs a platform C toolchain (lib.exe on
    #      Windows, the Apple SDK on macOS) that a Linux box does not have. That failure is
    #      about this machine, not the code, and reporting it as a failure would train
    #      everyone to ignore this script.
    #   2. It therefore does NOT cover anything behind the `http` feature, and it compiles
    #      rather than runs. A Windows-only *test* failure has bitten this branch before and
    #      this would not have caught it -- only the real matrix on main would.
    #
    # What it does catch is the likeliest breakage: a cfg(unix)/cfg(windows) branch that
    # does not compile on the other side.
    CROSS_CRATES=(-p cairn-proto -p cairn-crypto -p cairn-client-core -p cairn-server)
    for target in x86_64-pc-windows-msvc aarch64-apple-darwin; do
        if rustup target list --installed 2>/dev/null | grep -q "^${target}$"; then
            run "cross-compile ${target}" \
                cargo check "${CROSS_CRATES[@]}" --target "$target" --no-default-features
        else
            printf '\n\033[33mSKIPPED %s: rustup target add %s\033[0m\n' "$target" "$target"
        fi
    done
fi

printf '\n\033[1m════ summary ════\033[0m\n'
for p in "${PASSED[@]:-}"; do [ -n "$p" ] && printf '  \033[32mok  \033[0m %s\n' "$p"; done
for f in "${FAILED[@]:-}"; do [ -n "$f" ] && printf '  \033[31mFAIL\033[0m %s\n' "$f"; done

if [ "${#FAILED[@]}" -gt 0 ]; then
    printf '\n\033[31m%d check(s) failed — do not push.\033[0m\n' "${#FAILED[@]}"
    exit 1
fi
printf '\n\033[32mAll local checks passed.\033[0m\n'
