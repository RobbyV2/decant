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
# interposer hook (vector chosen by ADR-0006): the carafe is delivered by
# launcher-driven remote-thread injection, NOT a DLL override. `AppInit_DLLs` is a
# no-op stub on Wine, and an override-proxy must re-export the whole shadowed DLL; the
# launcher (testbins/decant-launcher) instead CreateProcess(SUSPENDED)s the tool and
# CreateRemoteThread+LoadLibrary's decant_interpose.dll, whose DllMain IAT-patches the
# unmodified tool. To run the tool through the launcher with the daemon endpoint wired:
#   export DECANT_AUTOHOOK=1                       # carafe self-installs on attach
#   export DECANT_ENDPOINT="tcp://127.0.0.1:7878"  # daemon
#   exec wine decant-launcher.exe "${exe}" "$@"
# With no daemon and no VM that is not needed, so we keep the quiet defaults
# and run the exe directly.
export WINEDLLOVERRIDES="mscoree=;mshtml="

exe="$1"
shift
exec wine "${exe}" "$@"
