#!/usr/bin/env bash
# Everything .github/workflows/ci.yml runs, on this machine, before it costs anything.
#
# Why this exists: CI on a private repo bills macOS minutes at 10x and Windows at 2x, so a
# full matrix run is expensive out of proportion to how often it catches something. Catching
# a failure here costs nothing.
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

# ---- lint job -------------------------------------------------------------
run "fmt --check"          cargo fmt --all --check
run "clippy --all-targets" cargo clippy --workspace --all-targets

# ---- test job (this platform only; see cross-check below) -----------------
run "test --all-targets"   cargo test --workspace --all-targets
run "vertical slice"       cargo run -p cairn-cli

if [ "$MODE" != "quick" ]; then
    # ---- msrv job ---------------------------------------------------------
    # The floor is a hard requirement: the crypto tree needs edition2024, stabilised in
    # exactly 1.85. A dependency bump that quietly raises it is the failure this catches.
    if rustup toolchain list 2>/dev/null | grep -q '^1\.85'; then
        run "msrv 1.85 check" cargo +1.85.0 check --workspace
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
