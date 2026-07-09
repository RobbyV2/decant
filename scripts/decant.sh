#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="${DECANT_STAGE:-$ROOT/target/decant-run}"
LIVE_DIR="${DECANT_LIVE_DIR:-$HOME/Downloads/decant-live}"
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
  scripts/decant.sh guest-unmap --config TOML
  scripts/decant.sh cli decant-cli-args...

Test and fixture harnesses live in scripts/decant-test.sh.

Examples:
  scripts/decant.sh wine-run --method standard "$HOME/.wine/drive_c/Program Files/Cheat Engine/Cheat Engine.exe"
  scripts/decant.sh wine-run --method manual-map ./target/x86_64-pc-windows-gnu/debug/sample-tool.exe --inject-test
  MEMFLOW_PLUGIN_PATH=/opt/memflow scripts/decant.sh daemon --connector qemu --vm win10
  MEMFLOW_PLUGIN_PATH=/opt/memflow scripts/decant.sh daemon --connector kvm --vm win10
  scripts/decant.sh guest-inject --pid 7800 --payload ./payload.dll --stage-base 0x1400013b0 --result-base 0x140022000
  scripts/decant.sh guest-inject --pid 7800 --payload ./payload.dll --final-protections section --loader-metadata best-effort --call-stack registered-unwind --permission-transitions write-through-final --thread-starts require-module-backed --image-backing sec-image
  scripts/decant.sh guest-unmap --config ./target/decant-run/guest-inject.toml

Environment:
  MEMFLOW_PLUGIN_PATH   directory containing libmemflow_{qemu,kvm,win32}.so
  DECANT_ENDPOINT       daemon endpoint, default 127.0.0.1:7878
  DECANT_CONNECTOR      memflow connector, default kvm
  DECANT_CONNECTOR_ARGS memflow connector default arg
  DECANT_VM_NAME        qemu -name guest value, default win10
  DECANT_OS_ARGS        optional memflow-win32 hints
  DECANT_WINEPREFIX     Wine prefix for wine-run, default wine-env/prefix
  DECANT_LIVE_DIR       runnable host binaries, default ~/Downloads/decant-live
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

toml_byte_array() {
  local compact="${1#0x}"
  compact="${compact//[[:space:],]/}"
  if [[ ! "$compact" =~ ^([[:xdigit:]]{2})+$ ]]; then
    echo "--dll-main-reserved-hex must contain complete hexadecimal bytes" >&2
    return 2
  fi
  local out="[" byte
  local i
  for ((i = 0; i < ${#compact}; i += 2)); do
    byte=$((16#${compact:i:2}))
    [[ "$i" == 0 ]] || out+=", "
    out+="$byte"
  done
  printf '%s]' "$out"
}

build_host() {
  cargo build --release -p decant-daemon -p decant-cli --features memflow
  mkdir -p "$LIVE_DIR"
  install -m 0755 "$ROOT/target/release/decant-daemon" "$LIVE_DIR/decant-daemon"
  install -m 0755 "$ROOT/target/release/decant-cli" "$LIVE_DIR/decant-cli"
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
      "$LIVE_DIR/decant-daemon" --backend memflow --connector "$connector" --bind "$ENDPOINT"
  fi
  exec env \
    MEMFLOW_PLUGIN_PATH="$MEMFLOW_PLUGIN_PATH" \
    DECANT_CONNECTOR_ARGS="$args" \
    DECANT_OS_ARGS="${DECANT_OS_ARGS:-}" \
    RUST_LOG="${RUST_LOG:-decant_daemon=info,decant_memflow=info,memflow=warn}" \
    "$LIVE_DIR/decant-daemon" --backend memflow --connector "$connector" --bind "$ENDPOINT"
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
  local config="$1" target_line="$2" payload="$3" stage="" result="" hook_module="$4" hook_function="$5" timeout="$6" dependency_policy="$9" loader_metadata="${10}" final_protections="${11}" call_stack="${12}" permission_transitions="${13}" thread_starts="${14}" image_backing="${15}" base_address="${16}" header_wipe="${17}" loader_entries="${18}" stack_shaping="${19}" cleanup="${20}" execution_method="${21}" vad_spoof="${22}" target_module="${23}" delay_loads="${24}" sxs="${25}" force_remap="${26}" high_memory="${27}" is_dependency="${28}" manual_module_registry="${29}" reserved_hex="${30}" map_callback_path="${31}" clr_assembly="${32}" clr_class="${33}" clr_method="${34}" clr_net_version="${35}"
  stage="$7"
  result="$8"
  local target_module_line="" reserved_line="" callback_line="" clr_block=""
  if [[ -n "$target_module" ]]; then
    target_module_line="target_module = \"$(toml_escape "$target_module")\""$'\n'
  fi
  if [[ -n "$reserved_hex" ]]; then
    local reserved_bytes
    reserved_bytes="$(toml_byte_array "$reserved_hex")" || return
    reserved_line="dll_main_reserved_arg = $reserved_bytes"$'\n'
  fi
  if [[ -n "$map_callback_path" ]]; then
    callback_line="map_callback_path = \"$(toml_escape "$map_callback_path")\""$'\n'
  fi
  if [[ -n "$clr_assembly" ]]; then
    clr_block="
[guest.clr]
assembly_path = \"$(toml_escape "$clr_assembly")\"
class_name = \"$(toml_escape "$clr_class")\"
method_name = \"$(toml_escape "$clr_method")\"
"
    if [[ -n "$clr_net_version" ]]; then
      clr_block+="net_version = \"$(toml_escape "$clr_net_version")\""$'\n'
    fi
  fi
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
delay_loads = "$delay_loads"
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
$target_module_line
sxs = "$sxs"
force_remap = $force_remap
high_memory = $high_memory
is_dependency = $is_dependency
manual_module_registry = "$manual_module_registry"
hook_module = "$(toml_escape "$hook_module")"
hook_function = "$(toml_escape "$hook_function")"
$stage$result$reserved_line$callback_line

[guest.execution]
method = "$execution_method"
timeout_ms = $timeout
$clr_block
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
  local target_module="" delay_loads="resolve" sxs="skip"
  local force_remap="false" high_memory="false" is_dependency="false" manual_module_registry="off"
  local reserved_hex="" map_callback_path=""
  local clr_assembly="" clr_class="" clr_method="" clr_net_version=""
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
      --delay-loads) delay_loads="$2"; shift 2 ;;
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
      --target-module) target_module="$2"; shift 2 ;;
      --sxs) sxs="$2"; shift 2 ;;
      --force-remap) force_remap="true"; shift ;;
      --high-memory) high_memory="true"; shift ;;
      --is-dependency) is_dependency="true"; shift ;;
      --manual-module-registry) manual_module_registry="$2"; shift 2 ;;
      --dll-main-reserved-hex) reserved_hex="$2"; shift 2 ;;
      --map-callback-path) map_callback_path="$2"; shift 2 ;;
      --clr-assembly) clr_assembly="$2"; shift 2 ;;
      --clr-class) clr_class="$2"; shift 2 ;;
      --clr-method) clr_method="$2"; shift 2 ;;
      --clr-net-version) clr_net_version="$2"; shift 2 ;;
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
    if [[ -n "$clr_assembly$clr_class$clr_method$clr_net_version" ]] && [[ -z "$clr_assembly" || -z "$clr_class" || -z "$clr_method" ]]; then
      echo "--clr-assembly, --clr-class, and --clr-method must be provided together" >&2
      exit 2
    fi
    config="$STAGE/guest-inject.toml"
    guest_config "$config" "$target_line" "$payload" "$hook_module" "$hook_function" "$timeout" "$stage" "$result" "$dependency_policy" "$loader_metadata" "$final_protections" "$call_stack" "$permission_transitions" "$thread_starts" "$image_backing" "$base_address" "$header_wipe" "$loader_entries" "$stack_shaping" "$cleanup" "$execution_method" "$vad_spoof" "$target_module" "$delay_loads" "$sxs" "$force_remap" "$high_memory" "$is_dependency" "$manual_module_registry" "$reserved_hex" "$map_callback_path" "$clr_assembly" "$clr_class" "$clr_method" "$clr_net_version"
  fi
  "$LIVE_DIR/decant-cli" --endpoint "$ENDPOINT" --json guest-inject "$config"
}

guest_unmap() {
  local config=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config) config="$2"; shift 2 ;;
      -h|--help) usage; return 0 ;;
      *) echo "unknown guest-unmap option: $1" >&2; exit 2 ;;
    esac
  done
  if [[ -z "$config" ]]; then
    echo "guest-unmap requires --config with the original target, stage, result, and hook settings" >&2
    exit 2
  fi
  if [[ "${DECANT_SKIP_BUILD:-}" != "1" ]]; then
    build_host
  fi
  "$LIVE_DIR/decant-cli" --endpoint "$ENDPOINT" --json guest-unmap "$config"
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
  guest-unmap) guest_unmap "$@" ;;
  cli) build_host; "$LIVE_DIR/decant-cli" --endpoint "$ENDPOINT" "$@" ;;
  *) echo "unknown command: $cmd" >&2; usage >&2; exit 2 ;;
esac
