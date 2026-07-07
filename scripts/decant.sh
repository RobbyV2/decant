#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="${DECANT_STAGE:-$ROOT/target/decant-run}"
ENDPOINT="${DECANT_ENDPOINT:-127.0.0.1:7878}"
WIN_TARGET="x86_64-pc-windows-gnu"

usage() {
  cat <<'EOF'
decant.sh

Usage:
  scripts/decant.sh build
  scripts/decant.sh daemon [--connector kvm|qemu] [--vm NAME] [--args ARG]
  scripts/decant.sh wine-run [--method METHOD|--config TOML] TARGET.exe [args...]
  scripts/decant.sh guest-inject [options]
  scripts/decant.sh cli decant-cli-args...

Test and fixture harnesses live in scripts/decant-test.sh.

Examples:
  scripts/decant.sh wine-run --method standard "$HOME/.wine/drive_c/Program Files/Cheat Engine/Cheat Engine.exe"
  scripts/decant.sh wine-run --method manual-map ./target/x86_64-pc-windows-gnu/debug/sample-tool.exe --inject-test
  MEMFLOW_PLUGIN_PATH=/opt/memflow scripts/decant.sh daemon --connector qemu --vm win10
  MEMFLOW_PLUGIN_PATH=/opt/memflow scripts/decant.sh daemon --connector kvm --vm win10
  scripts/decant.sh guest-inject --pid 7800 --payload ./payload.dll --stage-base 0x1400013b0 --result-base 0x140022000
  scripts/decant.sh guest-inject --pid 7800 --payload ./payload.dll --final-protections section --loader-metadata best-effort --call-stack registered-unwind --permission-transitions write-through-final --thread-starts require-module-backed --image-backing sec-image

Environment:
  MEMFLOW_PLUGIN_PATH   directory containing libmemflow_{qemu,kvm,win32}.so
  DECANT_ENDPOINT       daemon endpoint, default 127.0.0.1:7878
  DECANT_CONNECTOR      memflow connector, default kvm
  DECANT_CONNECTOR_ARGS memflow connector default arg
  DECANT_VM_NAME        qemu -name guest value, default win10
  DECANT_OS_ARGS        optional memflow-win32 hints
  DECANT_WINEPREFIX     Wine prefix for wine-run, default wine-env/prefix
EOF
}

need() {
  command -v "$1" >/dev/null || {
    echo "missing command: $1" >&2
    exit 2
  }
}

toml_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

build_host() {
  cargo build --release -p decant-daemon -p decant-cli --features memflow
}

build_wine() {
  mkdir -p "$STAGE"
  cargo build --target "$WIN_TARGET" \
    -p decant-interpose \
    -p decant-launcher \
    -p sample-tool \
    -p decant-plugin-standard \
    -p decant-external-standard
  for name in decant_interpose.dll decant-launcher.exe sample-tool.exe decant_plugin_standard.dll decant-external-standard.exe; do
    cp "$ROOT/target/$WIN_TARGET/debug/$name" "$STAGE/$name"
  done
}

build_all() {
  build_host
  build_wine
}

qemu_pid_for_guest() {
  local vm="$1"
  local pid
  for pid in $(pgrep -f "guest=$vm"); do
    case "$(cat "/proc/$pid/comm" 2>/dev/null)" in
      qemu-system*) printf '%s\n' "$pid"; return 0 ;;
    esac
  done
}

memflow_args() {
  local connector="$1" vm="$2" args="$3"
  if [[ -n "$args" ]]; then
    printf '%s\n' "$args"
    return
  fi
  case "$connector" in
    kvm) qemu_pid_for_guest "$vm" ;;
    qemu) printf '%s\n' "$vm" ;;
    *) printf '%s\n' "$args" ;;
  esac
}

check_memflow_plugins() {
  local connector="$1"
  local plugin_dir="${MEMFLOW_PLUGIN_PATH:-}"
  if [[ -z "$plugin_dir" ]]; then
    echo "set MEMFLOW_PLUGIN_PATH to the memflow plugin directory" >&2
    exit 2
  fi
  for plugin in "libmemflow_${connector}.so" libmemflow_win32.so; do
    if [[ ! -f "$plugin_dir/$plugin" ]]; then
      echo "missing plugin: $plugin_dir/$plugin" >&2
      exit 2
    fi
  done
}

daemon_cmd() {
  local connector="${DECANT_CONNECTOR:-kvm}"
  local vm="${DECANT_VM_NAME:-win10}"
  local args="${DECANT_CONNECTOR_ARGS:-}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --connector) connector="$2"; shift 2 ;;
      --vm) vm="$2"; shift 2 ;;
      --args) args="$2"; shift 2 ;;
      --endpoint) ENDPOINT="$2"; shift 2 ;;
      -h|--help) usage; return 0 ;;
      *) echo "unknown daemon option: $1" >&2; exit 2 ;;
    esac
  done
  build_host
  check_memflow_plugins "$connector"
  args="$(memflow_args "$connector" "$vm" "$args")"
  if [[ -z "$args" ]]; then
    echo "could not resolve connector args for connector=$connector vm=$vm" >&2
    exit 2
  fi
  echo "decant-daemon endpoint=$ENDPOINT connector=$connector args=$args"
  if [[ "$connector" == "kvm" || "${DECANT_DAEMON_SUDO:-}" == "1" ]]; then
    exec sudo env \
      MEMFLOW_PLUGIN_PATH="$MEMFLOW_PLUGIN_PATH" \
      DECANT_CONNECTOR_ARGS="$args" \
      DECANT_OS_ARGS="${DECANT_OS_ARGS:-}" \
      RUST_LOG="${RUST_LOG:-decant_daemon=info,decant_memflow=info,memflow=warn}" \
      "$ROOT/target/release/decant-daemon" --backend memflow --connector "$connector" --bind "$ENDPOINT"
  fi
  exec env \
    MEMFLOW_PLUGIN_PATH="$MEMFLOW_PLUGIN_PATH" \
    DECANT_CONNECTOR_ARGS="$args" \
    DECANT_OS_ARGS="${DECANT_OS_ARGS:-}" \
    RUST_LOG="${RUST_LOG:-decant_daemon=info,decant_memflow=info,memflow=warn}" \
    "$ROOT/target/release/decant-daemon" --backend memflow --connector "$connector" --bind "$ENDPOINT"
}

wine_path() {
  local path="$1"
  case "$path" in
    [A-Za-z]:*|*\\*) printf '%s\n' "$path" ;;
    *) winepath -w "$path" ;;
  esac
}

wine_run() {
  local method="standard" config="" prefix="${DECANT_WINEPREFIX:-$ROOT/wine-env/prefix}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --method) method="$2"; shift 2 ;;
      --config) config="$2"; shift 2 ;;
      --prefix) prefix="$2"; shift 2 ;;
      --) shift; break ;;
      -h|--help) usage; return 0 ;;
      *) break ;;
    esac
  done
  if [[ $# -lt 1 ]]; then
    echo "wine-run requires TARGET.exe" >&2
    exit 2
  fi
  need wine
  need winepath
  build_wine
  local target="$1"
  shift
  local target_win dll_win config_win workdir
  target_win="$(wine_path "$target")"
  dll_win="$(wine_path "$STAGE/decant_interpose.dll")"
  if [[ -z "$config" && "$method" != "standard" ]]; then
    config="$STAGE/wine-injection.toml"
    printf '[injection]\nmethod = "%s"\n' "$method" >"$config"
  fi
  if [[ -n "$config" ]]; then
    config_win="$(wine_path "$config")"
  else
    config_win=""
  fi
  if [[ -e "$target" ]]; then
    workdir="$(cd "$(dirname "$target")" && pwd)"
  else
    workdir="$STAGE"
  fi
  (
    cd "$workdir"
    local env_args=(
      WINEPREFIX="$prefix" \
      WINEDEBUG="${WINEDEBUG:--all}" \
      WINEDLLOVERRIDES="${WINEDLLOVERRIDES:-mscoree=;mshtml=}" \
      DECANT_AUTOHOOK="${DECANT_AUTOHOOK:-1}" \
      DECANT_DLL="$dll_win"
    )
    if [[ -n "$config_win" ]]; then
      env_args+=(DECANT_CONFIG="$config_win")
    fi
    env "${env_args[@]}" wine "$STAGE/decant-launcher.exe" "$target_win" "$@"
  )
}

guest_config() {
  local config="$1" target_line="$2" payload="$3" stage="" result="" hook_module="$4" hook_function="$5" timeout="$6" dependency_policy="$9" loader_metadata="${10}" final_protections="${11}" call_stack="${12}" permission_transitions="${13}" thread_starts="${14}" image_backing="${15}" base_address="${16}" header_wipe="${17}" loader_entries="${18}" stack_shaping="${19}" cleanup="${20}" execution_method="${21}" vad_spoof="${22}"
  stage="$7"
  result="$8"
  cat >"$config" <<TOML
[injection]
domain = "guest"
method = "manual-map"
timeout_ms = $timeout

[guest]
$target_line
payload_path = "$(toml_escape "$payload")"
allocation = "virtual-alloc"
dependency_policy = "$dependency_policy"
tls = "callbacks-only"
final_protections = "$final_protections"
loader_metadata = "$loader_metadata"
call_stack = "$call_stack"
permission_transitions = "$permission_transitions"
thread_starts = "$thread_starts"
image_backing = "$image_backing"
base_address = "$base_address"
header_wipe = "$header_wipe"
loader_entries = "$loader_entries"
stack_shaping = "$stack_shaping"
cleanup = "$cleanup"
vad_spoof = "$vad_spoof"
hook_module = "$(toml_escape "$hook_module")"
hook_function = "$(toml_escape "$hook_function")"
$stage$result

[guest.execution]
method = "$execution_method"
timeout_ms = $timeout
TOML
}

guest_inject() {
  local pid="" process="" payload="" config="" timeout="10000" hook_module="kernel32.dll" hook_function="Sleep"
  local stage="" result="" dependency_policy="require-loaded" loader_metadata="reject-unsupported" final_protections="section"
  local call_stack="native" permission_transitions="standard"
  local thread_starts="existing-thread"
  local image_backing="private"
  local base_address="preferred" header_wipe="none" loader_entries="absent" stack_shaping="native" cleanup="resident"
  local execution_method="iat-hook"
  local vad_spoof="off"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pid) pid="$2"; shift 2 ;;
      --process) process="$2"; shift 2 ;;
      --payload) payload="$2"; shift 2 ;;
      --config) config="$2"; shift 2 ;;
      --timeout-ms) timeout="$2"; shift 2 ;;
      --stage-base) stage="stage_base = $2"$'\n'; shift 2 ;;
      --stage-pattern) stage="stage_pattern = \"$(toml_escape "$2")\""$'\n'; shift 2 ;;
      --result-base) result="result_base = $2"$'\n'; shift 2 ;;
      --result-pattern) result="result_pattern = \"$(toml_escape "$2")\""$'\n'; shift 2 ;;
      --hook-module) hook_module="$2"; shift 2 ;;
      --hook-function) hook_function="$2"; shift 2 ;;
      --dependency-policy) dependency_policy="$2"; shift 2 ;;
      --loader-metadata) loader_metadata="$2"; shift 2 ;;
      --final-protections) final_protections="$2"; shift 2 ;;
      --call-stack) call_stack="$2"; shift 2 ;;
      --permission-transitions) permission_transitions="$2"; shift 2 ;;
      --thread-starts) thread_starts="$2"; shift 2 ;;
      --image-backing) image_backing="$2"; shift 2 ;;
      --base-address) base_address="$2"; shift 2 ;;
      --header-wipe) header_wipe="$2"; shift 2 ;;
      --loader-entries) loader_entries="$2"; shift 2 ;;
      --stack-shaping) stack_shaping="$2"; shift 2 ;;
      --cleanup) cleanup="$2"; shift 2 ;;
      --execution-method) execution_method="$2"; shift 2 ;;
      --vad-spoof) vad_spoof="$2"; shift 2 ;;
      -h|--help) usage; return 0 ;;
      *) echo "unknown guest-inject option: $1" >&2; exit 2 ;;
    esac
  done
  if [[ "${DECANT_SKIP_BUILD:-}" != "1" ]]; then
    build_host
  fi
  mkdir -p "$STAGE"
  if [[ -z "$config" ]]; then
    if [[ -z "$payload" ]]; then
      echo "guest-inject requires --payload or --config" >&2
      exit 2
    fi
    local target_line
    case "${pid:+pid}:${process:+process}" in
      pid:) target_line="pid = $pid" ;;
      :process) target_line="process = \"$(toml_escape "$process")\"" ;;
      *) echo "guest-inject requires exactly one of --pid or --process" >&2; exit 2 ;;
    esac
    config="$STAGE/guest-inject.toml"
    guest_config "$config" "$target_line" "$payload" "$hook_module" "$hook_function" "$timeout" "$stage" "$result" "$dependency_policy" "$loader_metadata" "$final_protections" "$call_stack" "$permission_transitions" "$thread_starts" "$image_backing" "$base_address" "$header_wipe" "$loader_entries" "$stack_shaping" "$cleanup" "$execution_method" "$vad_spoof"
  fi
  "$ROOT/target/release/decant-cli" --endpoint "$ENDPOINT" --json guest-inject "$config"
}

cmd="${1:-help}"
if [[ $# -gt 0 ]]; then
  shift
fi

case "$cmd" in
  help|-h|--help) usage ;;
  build) build_all ;;
  daemon) daemon_cmd "$@" ;;
  wine-run) wine_run "$@" ;;
  guest-inject) guest_inject "$@" ;;
  cli) build_host; "$ROOT/target/release/decant-cli" --endpoint "$ENDPOINT" "$@" ;;
  *) echo "unknown command: $cmd" >&2; usage >&2; exit 2 ;;
esac
