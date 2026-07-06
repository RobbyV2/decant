#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="${DECANT_STAGE:-$ROOT/target/decant-run}"
ENDPOINT="${DECANT_ENDPOINT:-127.0.0.1:7878}"
WIN_TARGET="x86_64-pc-windows-gnu"
FIXTURE_PROCESS="guest-inject-target.exe"
FIXTURE_MAGIC="44 45 43 41 4e 54 3a 3a 47 49 4e 4a 30 30 30 35"
PROBE_MAGIC="44 45 43 41 4e 54 3a 3a 47 55 45 53 54 49 4e 4a"
STUB_MAGIC="44 45 43 41 4e 54 3a 3a 53 54 55 42 30 30 30 34"
RESULT_MAGIC="44 45 43 41 4e 54 3a 3a 52 45 53 55 4c 54 30 34"
MARKER_LE="07 51 0d 60 a7 ec 1d d1"

usage() {
  cat <<'EOF'
decant.sh

Usage:
  scripts/decant.sh build
  scripts/decant.sh inject-test
  scripts/decant.sh daemon [--connector kvm|qemu] [--vm NAME] [--args ARG]
  scripts/decant.sh wine-run [--method METHOD|--config TOML] TARGET.exe [args...]
  scripts/decant.sh guest-inject [options]
  scripts/decant.sh guest-fixture [--connector kvm|qemu] [--vm NAME] [--args ARG] [--payload DLL]... [--final-protections rwx|section] [--loader-metadata reject-unsupported|best-effort|allow-unsupported] [--call-stack native|registered-unwind] [--permission-transitions standard|write-through-final] [--thread-starts existing-thread|require-module-backed] [--image-backing private|sec-image]
  scripts/decant.sh cli decant-cli-args...

Examples:
  scripts/decant.sh wine-run --method standard "$HOME/.wine/drive_c/Program Files/Cheat Engine/Cheat Engine.exe"
  scripts/decant.sh wine-run --method manual-map ./target/x86_64-pc-windows-gnu/debug/sample-tool.exe --inject-test
  MEMFLOW_PLUGIN_PATH=/opt/memflow scripts/decant.sh daemon --connector qemu --vm win10
  MEMFLOW_PLUGIN_PATH=/opt/memflow scripts/decant.sh daemon --connector kvm --vm win10
  scripts/decant.sh guest-inject --pid 7800 --payload ./payload.dll --stage-base 0x1400013b0 --result-base 0x140022000
  scripts/decant.sh guest-inject --pid 7800 --payload ./payload.dll --final-protections section --loader-metadata best-effort --call-stack registered-unwind --permission-transitions write-through-final --thread-starts require-module-backed --image-backing sec-image
  MEMFLOW_PLUGIN_PATH=/opt/memflow scripts/decant.sh guest-fixture --connector kvm --vm win10
  MEMFLOW_PLUGIN_PATH=/opt/memflow scripts/decant.sh guest-fixture --connector kvm --vm win10 --final-protections section
  MEMFLOW_PLUGIN_PATH=/opt/memflow scripts/decant.sh guest-fixture --connector kvm --vm win10 --payload guest_inject_tls.dll

Environment:
  MEMFLOW_PLUGIN_PATH   directory containing libmemflow_{qemu,kvm,win32}.so
  DECANT_ENDPOINT       daemon endpoint, default 127.0.0.1:7878
  DECANT_CONNECTOR      memflow connector, default kvm
  DECANT_CONNECTOR_ARGS memflow connector default arg
  DECANT_VM_NAME        qemu -name guest value, default win10
  DECANT_OS_ARGS        optional memflow-win32 hints
  DECANT_WINEPREFIX     Wine prefix for wine-run, default wine-env/prefix
  DECANT_GUEST_FINAL_PROTECTIONS section|rwx for guest-fixture
  DECANT_GUEST_LOADER_METADATA reject-unsupported|best-effort|allow-unsupported
  DECANT_GUEST_CALL_STACK native|registered-unwind for guest-fixture
  DECANT_GUEST_PERMISSION_TRANSITIONS standard|write-through-final for guest-fixture
  DECANT_GUEST_THREAD_STARTS existing-thread|require-module-backed for guest-fixture
  DECANT_GUEST_IMAGE_BACKING private|sec-image for guest-fixture
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

hex_bytes() {
  local pid="$1" addr="$2" len="$3"
  "$ROOT/target/release/decant-cli" --endpoint "$ENDPOINT" read "$pid" "$addr" "$len" |
    awk '{
      for (i = 2; i <= NF; i++) {
        if ($i == "|" || $i ~ /^\|/) break;
        if ($i ~ /^[0-9a-fA-F][0-9a-fA-F]$/) {
          printf "%s%s", (out ? " " : ""), tolower($i);
          out = 1;
        }
      }
      if (out) { print ""; exit }
    }'
}

le_hex_literal() {
  local bytes="$1"
  local parts=()
  read -r -a parts <<<"$bytes"
  printf '0x'
  local i
  for ((i = ${#parts[@]} - 1; i >= 0; i--)); do
    printf '%s' "${parts[$i]}"
  done
}

read_u64_le() {
  local pid="$1" addr="$2"
  local bytes
  bytes="$(hex_bytes "$pid" "$addr" 8 || true)"
  if [[ -z "$bytes" ]]; then
    echo "could not read u64 at $addr in pid $pid" >&2
    exit 5
  fi
  printf '%d\n' "$(( $(le_hex_literal "$bytes") ))"
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
  cargo run -p xtask -- guest-inject-fixture
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

start_daemon_background() {
  local connector="$1" vm="$2" args="$3" log="$4"
  if "$ROOT/target/release/decant-cli" --endpoint "$ENDPOINT" diagnostics >/dev/null 2>&1; then
    if [[ "${DECANT_REUSE_DAEMON:-}" == "1" ]]; then
      DAEMON_PID=""
      return
    fi
    echo "decant-daemon is already listening at $ENDPOINT" >&2
    echo "stop it before guest-fixture, or set DECANT_REUSE_DAEMON=1 to reuse it intentionally" >&2
    exit 7
  fi
  check_memflow_plugins "$connector"
  args="$(memflow_args "$connector" "$vm" "$args")"
  if [[ -z "$args" ]]; then
    echo "could not resolve connector args for connector=$connector vm=$vm" >&2
    exit 2
  fi
  if [[ "$connector" == "kvm" || "${DECANT_DAEMON_SUDO:-}" == "1" ]]; then
    if [[ ! -t 0 ]] && ! sudo -n true >/dev/null 2>&1; then
      echo "sudo is required for connector=$connector; run sudo -v in a terminal, then rerun" >&2
      exit 7
    fi
    sudo env \
      MEMFLOW_PLUGIN_PATH="$MEMFLOW_PLUGIN_PATH" \
      DECANT_CONNECTOR_ARGS="$args" \
      DECANT_OS_ARGS="${DECANT_OS_ARGS:-}" \
      RUST_LOG="${RUST_LOG:-decant_inject::guest=debug,decant_daemon=info,decant_memflow=info,memflow=warn}" \
      "$ROOT/target/release/decant-daemon" --backend memflow --connector "$connector" --bind "$ENDPOINT" >"$log" 2>&1 &
  else
    env \
      MEMFLOW_PLUGIN_PATH="$MEMFLOW_PLUGIN_PATH" \
      DECANT_CONNECTOR_ARGS="$args" \
      DECANT_OS_ARGS="${DECANT_OS_ARGS:-}" \
      RUST_LOG="${RUST_LOG:-decant_inject::guest=debug,decant_daemon=info,decant_memflow=info,memflow=warn}" \
      "$ROOT/target/release/decant-daemon" --backend memflow --connector "$connector" --bind "$ENDPOINT" >"$log" 2>&1 &
  fi
  DAEMON_PID=$!
  for _ in $(seq 1 80); do
    if "$ROOT/target/release/decant-cli" --endpoint "$ENDPOINT" diagnostics >/dev/null 2>&1; then
      return
    fi
    sleep 0.25
  done
  echo "decant-daemon did not become ready at $ENDPOINT" >&2
  sed -n '1,220p' "$log" >&2 || true
  exit 7
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
  local config="$1" target_line="$2" payload="$3" stage="" result="" hook_module="$4" hook_function="$5" timeout="$6" dependency_policy="$9" loader_metadata="${10}" final_protections="${11}" call_stack="${12}" permission_transitions="${13}" thread_starts="${14}" image_backing="${15}"
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
hook_module = "$(toml_escape "$hook_module")"
hook_function = "$(toml_escape "$hook_function")"
$stage$result

[guest.execution]
method = "iat-hook"
timeout_ms = $timeout
TOML
}

guest_inject() {
  local pid="" process="" payload="" config="" timeout="10000" hook_module="kernel32.dll" hook_function="Sleep"
  local stage="" result="" dependency_policy="require-loaded" loader_metadata="reject-unsupported" final_protections="section"
  local call_stack="native" permission_transitions="standard"
  local thread_starts="existing-thread"
  local image_backing="private"
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
    guest_config "$config" "$target_line" "$payload" "$hook_module" "$hook_function" "$timeout" "$stage" "$result" "$dependency_policy" "$loader_metadata" "$final_protections" "$call_stack" "$permission_transitions" "$thread_starts" "$image_backing"
  fi
  "$ROOT/target/release/decant-cli" --endpoint "$ENDPOINT" --json guest-inject "$config"
}

wait_for_tick_window() {
  local pid="$1" tick_addr="$2" before after
  before="$(read_u64_le "$pid" "$tick_addr")"
  for _ in $(seq 1 80); do
    sleep 0.05
    after="$(read_u64_le "$pid" "$tick_addr")"
    if [[ "$after" -ne "$before" ]]; then
      sleep "${DECANT_GUEST_FIXTURE_ARM_DELAY:-0.10}"
      return 0
    fi
  done
  echo "guest fixture: target tick did not advance at $tick_addr" >&2
  exit 5
}

fixture_target() {
  local name="$1" pid marker found_pid="" found_marker=""
  while read -r pid _; do
    marker="$("$ROOT/target/release/decant-cli" --endpoint "$ENDPOINT" scan "$pid" "$FIXTURE_MAGIC" | awk '/^0x/{print $1; exit}')"
    if [[ -n "$marker" ]]; then
      if [[ -n "$found_pid" ]]; then
        echo "multiple $name processes contain the fixture marker; set DECANT_GUEST_PID" >&2
        exit 4
      fi
      found_pid="$pid"
      found_marker="$marker"
    fi
  done < <("$ROOT/target/release/decant-cli" --endpoint "$ENDPOINT" processes | awk -v n="$name" '$2 == n {print $1, $2}')
  if [[ -z "$found_pid" ]]; then
    echo "$name is not running with fixture marker DECANT::GINJ0005" >&2
    echo "copy $STAGE/guest-inject-target.exe into the VM, start it, then rerun this command" >&2
    exit 4
  fi
  printf '%s %s\n' "$found_pid" "$found_marker"
}

guest_fixture() {
  local connector="${DECANT_CONNECTOR:-kvm}" vm="${DECANT_VM_NAME:-win10}" args="${DECANT_CONNECTOR_ARGS:-}"
  local final_protections="${DECANT_GUEST_FINAL_PROTECTIONS:-section}"
  local loader_metadata="${DECANT_GUEST_LOADER_METADATA:-reject-unsupported}"
  local call_stack="${DECANT_GUEST_CALL_STACK:-native}"
  local permission_transitions="${DECANT_GUEST_PERMISSION_TRANSITIONS:-standard}"
  local thread_starts="${DECANT_GUEST_THREAD_STARTS:-existing-thread}"
  local image_backing="${DECANT_GUEST_IMAGE_BACKING:-private}"
  local selected_payloads=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --connector) connector="$2"; shift 2 ;;
      --vm) vm="$2"; shift 2 ;;
      --args) args="$2"; shift 2 ;;
      --endpoint) ENDPOINT="$2"; shift 2 ;;
      --payload) selected_payloads+=("$2"); shift 2 ;;
      --final-protections) final_protections="$2"; shift 2 ;;
      --loader-metadata) loader_metadata="$2"; shift 2 ;;
      --call-stack) call_stack="$2"; shift 2 ;;
      --permission-transitions) permission_transitions="$2"; shift 2 ;;
      --thread-starts) thread_starts="$2"; shift 2 ;;
      --image-backing) image_backing="$2"; shift 2 ;;
      -h|--help) usage; return 0 ;;
      *) echo "unknown guest-fixture option: $1" >&2; exit 2 ;;
    esac
  done
  need awk
  need pgrep
  build_host
  cargo run -p xtask -- guest-inject-fixture
  mkdir -p "$STAGE"
  cp "$ROOT/target/guest-inject-fixture/guest-inject-target.exe" "$STAGE/"
  cp "$ROOT/target/guest-inject-fixture"/guest_inject_*.dll "$STAGE/"
  local log="$STAGE/decant-daemon.log" daemon_pid=""
  DAEMON_PID=""
  start_daemon_background "$connector" "$vm" "$args" "$log"
  daemon_pid="$DAEMON_PID"
  trap 'case "${daemon_pid:-}" in "") ;; *) sudo kill "$daemon_pid" >/dev/null 2>&1 || true ;; esac' EXIT

  local pid fixture stub result bytes marker probe tick_addr count_addr count_before count_after
  if [[ -n "${DECANT_GUEST_PID:-}" ]]; then
    pid="$DECANT_GUEST_PID"
    fixture="$("$ROOT/target/release/decant-cli" --endpoint "$ENDPOINT" scan "$pid" "$FIXTURE_MAGIC" | awk '/^0x/{print $1; exit}')"
  else
    read -r pid fixture < <(fixture_target "$FIXTURE_PROCESS")
  fi
  stub="$("$ROOT/target/release/decant-cli" --endpoint "$ENDPOINT" scan "$pid" "$STUB_MAGIC" | awk '/^0x/{print $1; exit}')"
  result="$("$ROOT/target/release/decant-cli" --endpoint "$ENDPOINT" scan "$pid" "$RESULT_MAGIC" | awk '/^0x/{print $1; exit}')"
  if [[ -z "$fixture" || -z "$stub" || -z "$result" ]]; then
    echo "fixture markers were not all found in pid $pid" >&2
    exit 4
  fi
  bytes="$(hex_bytes "$pid" "$stub" 16 || true)"
  if [[ "$bytes" != "$STUB_MAGIC" ]]; then
    echo "stub marker readback mismatch at $stub: ${bytes:-<unreadable>}" >&2
    exit 4
  fi
  bytes="$(hex_bytes "$pid" "$result" 16 || true)"
  if [[ "$bytes" != "$RESULT_MAGIC" ]]; then
    echo "result marker readback mismatch at $result: ${bytes:-<unreadable>}" >&2
    exit 4
  fi
  echo "selected target: pid=$pid fixture=$fixture stub=$stub result=$result"
  probe="$(printf '0x%x' "$((fixture + 16))")"
  tick_addr="$(printf '0x%x' "$((probe + 16))")"
  marker="$(printf '0x%x' "$((probe + 24))")"
  count_addr="$(printf '0x%x' "$((probe + 32))")"
  count_before="$(read_u64_le "$pid" "$count_addr")"
  local payload payload_name expected_count
  local payloads=()
  if [[ ${#selected_payloads[@]} -gt 0 ]]; then
    payloads=("${selected_payloads[@]}")
  elif [[ -n "${DECANT_GUEST_FIXTURE_PAYLOADS:-}" ]]; then
    read -r -a payloads <<<"$DECANT_GUEST_FIXTURE_PAYLOADS"
  else
    payloads=(
      guest_inject_probe.dll
      guest_inject_imports.dll
      guest_inject_tls.dll
      guest_inject_rust.dll
    )
  fi
  for payload in "${payloads[@]}"; do
    case "$payload" in
      /*) ;;
      *) payload="$STAGE/$payload" ;;
    esac
    payload_name="$(basename "$payload")"
    if [[ ! -f "$payload" ]]; then
      echo "guest fixture payload not found: $payload" >&2
      exit 2
    fi
    local extra_args=(
      --loader-metadata "$loader_metadata"
      --call-stack "$call_stack"
      --permission-transitions "$permission_transitions"
      --thread-starts "$thread_starts"
      --image-backing "$image_backing"
    )
    if [[ "$payload_name" == "guest_inject_rust.dll" ]]; then
      local rust_loader_metadata="$loader_metadata"
      if [[ "$rust_loader_metadata" == "reject-unsupported" ]]; then
        rust_loader_metadata="best-effort"
      fi
      extra_args=(
        --dependency-policy load-with-guest-loader
        --loader-metadata "$rust_loader_metadata"
        --call-stack "$call_stack"
        --permission-transitions "$permission_transitions"
        --thread-starts "$thread_starts"
        --image-backing "$image_backing"
      )
    fi
    expected_count=$((count_before + 1))
    echo "guest fixture: injecting $payload_name"
    wait_for_tick_window "$pid" "$tick_addr"
    if ! DECANT_SKIP_BUILD=1 guest_inject \
      --pid "$pid" \
      --payload "$payload" \
      --stage-base "$stub" \
      --result-base "$result" \
      --final-protections "$final_protections" \
      "${extra_args[@]}"
    then
      echo "guest fixture: injection failed for $payload_name" >&2
      "$ROOT/target/release/decant-cli" --endpoint "$ENDPOINT" processes >&2 || true
      tail -n 260 "$log" >&2 || true
      exit 5
    fi
    for _ in $(seq 1 50); do
      bytes="$(hex_bytes "$pid" "$marker" 8 || true)"
      count_after="$(read_u64_le "$pid" "$count_addr")"
      if [[ "$bytes" == "$MARKER_LE" && "$count_after" -ge "$expected_count" ]]; then
        echo "guest fixture: PASS $payload_name pid=$pid count=$count_after"
        count_before="$count_after"
        break
      fi
      sleep 0.2
    done
    if [[ "$count_before" -lt "$expected_count" ]]; then
      echo "guest fixture: $payload_name did not advance dll_count at $count_addr" >&2
      tail -n 220 "$log" >&2 || true
      exit 5
    fi
  done
  echo "guest fixture: PASS pid=$pid probe=$probe marker=$marker count=$count_before"
}

cmd="${1:-help}"
if [[ $# -gt 0 ]]; then
  shift
fi

case "$cmd" in
  help|-h|--help) usage ;;
  build) build_all ;;
  inject-test) cargo run -p xtask -- inject-test ;;
  daemon) daemon_cmd "$@" ;;
  wine-run) wine_run "$@" ;;
  guest-inject) guest_inject "$@" ;;
  guest-fixture) guest_fixture "$@" ;;
  cli) build_host; "$ROOT/target/release/decant-cli" --endpoint "$ENDPOINT" "$@" ;;
  *) echo "unknown command: $cmd" >&2; usage >&2; exit 2 ;;
esac
