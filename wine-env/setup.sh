#!/usr/bin/env bash
# Initialize the isolated, repo-local Wine prefix Decant runs Windows binaries in.
#
# Everything lives under wine-env/prefix so the host's ~/.wine is never touched and
# the prefix is disposable (delete the directory to start clean). The prompts Wine
# normally raises on first boot (download gecko/mono) are suppressed via
# WINEDLLOVERRIDES so this runs non-interactively with no X display.
#
# Idempotent: if the prefix is already booted (system.reg exists) we do nothing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WINEPREFIX="${SCRIPT_DIR}/prefix"

# Quiet + headless: no debug spam, no gecko/mono installer dialogs.
export WINEDEBUG=-all
export WINEDLLOVERRIDES="mscoree=;mshtml="
# No X server in CI: keep Wine from trying to talk to one.
export DISPLAY=""

if [[ -f "${WINEPREFIX}/system.reg" ]]; then
    echo "[wine-env] prefix already initialized at ${WINEPREFIX}"
    exit 0
fi

echo "[wine-env] booting fresh prefix at ${WINEPREFIX} (first run can take ~30-60s)"
mkdir -p "${WINEPREFIX}"

# wineboot initializes the prefix; --init forces the full first-boot setup. We wait
# on the wineserver so the prefix is fully written before we return.
wineboot --init
wineserver --wait

echo "[wine-env] prefix ready"
