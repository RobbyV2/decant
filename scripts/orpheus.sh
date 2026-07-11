#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WIN_TARGET="x86_64-pc-windows-gnu"
cd "$ROOT"

usage() {
  cat <<'EOF'
Usage:
  scripts/orpheus.sh build [linux|windows]
  scripts/orpheus.sh install [--platform linux|windows] [--dir ORPHEUS_DLL_DIR]
  scripts/orpheus.sh connect

install defaults:
  linux    ~/.orpheus/dlls
  windows  $DECANT_WINEPREFIX/drive_c/users/$USER/AppData/Roaming/Orpheus/dlls

connect environment:
  DECANT_ENDPOINT  Decant daemon address (default 127.0.0.1:7878)
  ORPHEUS_MCP_URL  Orpheus HTTP server (default http://127.0.0.1:8765)
  ORPHEUS_API_KEY  Bearer token when Orpheus authentication is enabled
EOF
}

build_plugin() {
  local platform="$1"
  case "$platform" in
    linux)
      cargo build --release -p decant-leechcore-device
      ;;
    windows)
      cargo build --release -p decant-leechcore-device --target "$WIN_TARGET"
      ;;
    *) echo "unsupported platform: $platform" >&2; return 2 ;;
  esac
}

install_plugin() {
  local platform="linux" destination=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --platform) platform="$2"; shift 2 ;;
      --dir) destination="$2"; shift 2 ;;
      -h|--help) usage; return 0 ;;
      *) echo "unknown install option: $1" >&2; return 2 ;;
    esac
  done

  build_plugin "$platform"
  local source target
  case "$platform" in
    linux)
      source="$ROOT/target/release/libleechcore_device_decant.so"
      target="leechcore_device_decant.so"
      destination="${destination:-${DECANT_ORPHEUS_DLL_DIR:-$HOME/.orpheus/dlls}}"
      ;;
    windows)
      source="$ROOT/target/$WIN_TARGET/release/leechcore_device_decant.dll"
      target="leechcore_device_decant.dll"
      destination="${destination:-${DECANT_ORPHEUS_DLL_DIR:-${DECANT_WINEPREFIX:-$ROOT/wine-env/prefix}/drive_c/users/$USER/AppData/Roaming/Orpheus/dlls}}"
      ;;
  esac
  mkdir -p "$destination"
  install -m 0755 "$source" "$destination/$target"
  echo "installed $destination/$target"
  echo "Orpheus device: decant://${DECANT_ENDPOINT:-127.0.0.1:7878}"
}

connect_orpheus() {
  command -v curl >/dev/null || { echo "missing command: curl" >&2; return 2; }
  local url="${ORPHEUS_MCP_URL:-http://127.0.0.1:8765}"
  local endpoint="${DECANT_ENDPOINT:-127.0.0.1:7878}"
  local auth=()
  if [[ -n "${ORPHEUS_API_KEY:-}" ]]; then
    auth=(-H "Authorization: Bearer $ORPHEUS_API_KEY")
  fi
  curl --fail-with-body --silent --show-error \
    "${auth[@]}" \
    -H 'Content-Type: application/json' \
    -d "{\"device_type\":\"decant://$endpoint\"}" \
    "$url/tools/connect_dma"
  printf '\n'
  echo "Orpheus is connecting through Decant; check $url/tools/dma_status for status."
}

cmd="${1:-help}"
[[ $# -eq 0 ]] || shift
case "$cmd" in
  build) build_plugin "${1:-linux}" ;;
  install) install_plugin "$@" ;;
  connect) connect_orpheus ;;
  help|-h|--help) usage ;;
  *) echo "unknown command: $cmd" >&2; usage >&2; exit 2 ;;
esac
