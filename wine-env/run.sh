#!/usr/bin/env bash
# Run any Windows exe under the isolated repo-local Wine prefix with the Decant
# interposer injected and pointed at a daemon.
#
#   wine-env/run.sh <exe> [args...]
#
# Co-locates decant-launcher.exe and decant_interpose.dll next to the target exe,
# then runs `wine decant-launcher.exe <exe> args` from that directory. The launcher
# starts the target suspended and injects the carafe, which self-installs its hooks
# (DECANT_AUTOHOOK=1) and connects to DECANT_ENDPOINT.
#
# Honors an existing DECANT_ENDPOINT; otherwise defaults to 127.0.0.1:7878. Assumes
# the prefix already exists (run wine-env/setup.sh once).
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <exe> [args...]" >&2
    exit 64
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_DIR="${REPO_ROOT}/target/x86_64-pc-windows-gnu/debug"

export WINEPREFIX="${SCRIPT_DIR}/prefix"
export WINEDEBUG=-all
export WINEDLLOVERRIDES="mscoree=;mshtml="
export DECANT_AUTOHOOK=1
export DECANT_ENDPOINT="${DECANT_ENDPOINT:-127.0.0.1:7878}"

exe_abs="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
shift
exe_dir="$(dirname "${exe_abs}")"
exe_name="$(basename "${exe_abs}")"

for f in decant-launcher.exe decant_interpose.dll; do
    if [[ "${exe_dir}/${f}" -ef "${BIN_DIR}/${f}" ]]; then
        continue
    fi
    cp -f "${BIN_DIR}/${f}" "${exe_dir}/${f}"
done

cd "${exe_dir}"
exec wine decant-launcher.exe "${exe_name}" "$@"
