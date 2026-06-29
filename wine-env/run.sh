#!/usr/bin/env bash
# Run a Windows exe under the isolated repo-local Wine prefix with env wired.
#
#   wine-env/run.sh <exe> [args...]
#
# Assumes the prefix already exists (run wine-env/setup.sh once, or `cargo xtask
# wine-smoke` which calls it for you). Mirrors the env in decant-wine-harness so the
# script path and the Rust test path behave identically.
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <exe> [args...]" >&2
    exit 64
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WINEPREFIX="${SCRIPT_DIR}/prefix"
export WINEDEBUG=-all

# mscoree/mshtml disabled to silence the gecko/mono prompts.
#
# Phase 3 interposer hook: prepend the Decant DLL override here so Wine loads our
# carafe (decant_interpose) in place of the real builtin for the few exports we
# redirect, e.g.
#   export WINEDLLOVERRIDES="decant_interpose=n,b;mscoree=;mshtml="
# and point the interposer at the daemon endpoint:
#   export DECANT_ENDPOINT="unix:///run/decant.sock"
# Neither is needed in Phase 0 (no daemon, no VM), so we keep the quiet defaults.
export WINEDLLOVERRIDES="mscoree=;mshtml="

exe="$1"
shift
exec wine "${exe}" "$@"
