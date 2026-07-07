#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DECANT_SH="$ROOT/scripts/decant.sh"
STAGE="${DECANT_STAGE:-$ROOT/target/decant-run}"
ENDPOINT="${DECANT_ENDPOINT:-127.0.0.1:7878}"

FIXTURE_PROCESS="guest-inject-target.exe"
FIXTURE_MAGIC="44 45 43 41 4e 54 3a 3a 47 49 4e 4a 30 30 30 35"
STUB_MAGIC="44 45 43 41 4e 54 3a 3a 53 54 55 42 30 30 30 34"
RESULT_MAGIC="44 45 43 41 4e 54 3a 3a 52 45 53 55 4c 54 30 34"
MARKER_LE="07 51 0d 60 a7 ec 1d d1"
DAEMON_PID=""

usage() {
  cat <<'EOF'
decant-test.sh

Usage:
  scripts/decant-test.sh inject-test
  scripts/decant-test.sh guest-fixture [--connector kvm|qemu] [--vm NAME] [--args ARG] [--payload DLL]...

Examples:
  MEMFLOW_PLUGIN_PATH=/opt/memflow scripts/decant-test.sh guest-fixture --connector kvm --vm win10
  MEMFLOW_PLUGIN_PATH=/opt/memflow scripts/decant-test.sh guest-fixture --connector kvm --vm win10 --payload guest_inject_tls.dll
  MEMFLOW_PLUGIN_PATH=/opt/memflow scripts/decant-test.sh guest-fixture --connector kvm --vm win10 --image-backing private --base-address randomized --header-wipe after-load --loader-entries synthesized --stack-shaping spoofed --cleanup tracked

Environment:
  MEMFLOW_PLUGIN_PATH   directory containing libmemflow_{qemu,kvm,win32}.so
  DECANT_ENDPOINT       daemon endpoint, default 127.0.0.1:7878
  DECANT_CONNECTOR      memflow connector, default kvm
  DECANT_CONNECTOR_ARGS memflow connector default arg
  DECANT_VM_NAME        qemu -name guest value, default win10
  DECANT_GUEST_FINAL_PROTECTIONS section|rwx
  DECANT_GUEST_LOADER_METADATA reject-unsupported|best-effort|allow-unsupported
  DECANT_GUEST_CALL_STACK native|registered-unwind
  DECANT_GUEST_PERMISSION_TRANSITIONS standard|write-through-final
  DECANT_GUEST_THREAD_STARTS existing-thread|require-module-backed
  DECANT_GUEST_IMAGE_BACKING private|sec-image
  DECANT_GUEST_BASE_ADDRESS preferred|randomized
  DECANT_GUEST_HEADER_WIPE none|after-load
  DECANT_GUEST_LOADER_ENTRIES absent|synthesized
  DECANT_GUEST_STACK_SHAPING native|spoofed
  DECANT_GUEST_CLEANUP resident|tracked
  DECANT_GUEST_VAD_SPOOF off|vad-image-map
EOF
}

need() {
  command -v "$1" >/dev/null || {
    echo "missing command: $1" >&2
    exit 2
  }
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

cleanup_daemon() {
  if [[ -n "${DAEMON_PID:-}" ]]; then
    kill "$DAEMON_PID" >/dev/null 2>&1 || sudo kill "$DAEMON_PID" >/dev/null 2>&1 || true
  fi
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
  fi
  DECANT_ENDPOINT="$ENDPOINT" \
    MEMFLOW_PLUGIN_PATH="$MEMFLOW_PLUGIN_PATH" \
    DECANT_OS_ARGS="${DECANT_OS_ARGS:-}" \
    RUST_LOG="${RUST_LOG:-decant_inject::guest=debug,decant_daemon=info,decant_memflow=info,memflow=warn}" \
    "$DECANT_SH" daemon --connector "$connector" --vm "$vm" --args "$args" --endpoint "$ENDPOINT" >"$log" 2>&1 &
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

fixture_tick_advances() {
  local pid="$1" fixture="$2" tick_addr before after bytes
  tick_addr="$(printf '0x%x' "$((fixture + 32))")"
  bytes="$(hex_bytes "$pid" "$tick_addr" 8 || true)"
  if [[ -z "$bytes" ]]; then
    return 1
  fi
  before="$(( $(le_hex_literal "$bytes") ))"
  for _ in $(seq 1 30); do
    sleep 0.1
    bytes="$(hex_bytes "$pid" "$tick_addr" 8 || true)"
    if [[ -z "$bytes" ]]; then
      return 1
    fi
    after="$(( $(le_hex_literal "$bytes") ))"
    if [[ "$after" -ne "$before" ]]; then
      return 0
    fi
  done
  return 1
}

fixture_target() {
  local name="$1" pid marker found_pid="" found_marker="" stale_count=0
  while read -r pid _; do
    marker="$("$ROOT/target/release/decant-cli" --endpoint "$ENDPOINT" scan "$pid" "$FIXTURE_MAGIC" | awk '/^0x/{print $1; exit}')"
    if [[ -n "$marker" ]]; then
      if ! fixture_tick_advances "$pid" "$marker"; then
        stale_count=$((stale_count + 1))
        echo "skipping stale $name pid=$pid: fixture tick did not advance" >&2
        continue
      fi
      if [[ -n "$found_pid" ]]; then
        echo "multiple $name processes contain the fixture marker; set DECANT_GUEST_PID" >&2
        exit 4
      fi
      found_pid="$pid"
      found_marker="$marker"
    fi
  done < <("$ROOT/target/release/decant-cli" --endpoint "$ENDPOINT" processes | awk -v n="$name" '$2 == n {print $1, $2}')
  if [[ -z "$found_pid" ]]; then
    if [[ "$stale_count" -gt 0 ]]; then
      echo "$name has $stale_count stale fixture process(es), but none are live" >&2
      echo "stop the stale guest-inject-target.exe process in the VM, start a fresh one, then rerun" >&2
    else
      echo "$name is not running with fixture marker DECANT::GINJ0005" >&2
    fi
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
  local base_address="${DECANT_GUEST_BASE_ADDRESS:-preferred}"
  local header_wipe="${DECANT_GUEST_HEADER_WIPE:-none}"
  local loader_entries="${DECANT_GUEST_LOADER_ENTRIES:-absent}"
  local stack_shaping="${DECANT_GUEST_STACK_SHAPING:-native}"
  local cleanup="${DECANT_GUEST_CLEANUP:-resident}"
  local execution_method="${DECANT_GUEST_EXECUTION_METHOD:-iat-hook}"
  local vad_spoof="${DECANT_GUEST_VAD_SPOOF:-off}"
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
      --base-address) base_address="$2"; shift 2 ;;
      --header-wipe) header_wipe="$2"; shift 2 ;;
      --loader-entries) loader_entries="$2"; shift 2 ;;
      --stack-shaping) stack_shaping="$2"; shift 2 ;;
      --cleanup) cleanup="$2"; shift 2 ;;
      --execution-method) execution_method="$2"; shift 2 ;;
      --vad-spoof) vad_spoof="$2"; shift 2 ;;
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
  local log="$STAGE/decant-daemon.log"
  start_daemon_background "$connector" "$vm" "$args" "$log"
  trap cleanup_daemon EXIT

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
      --base-address "$base_address"
      --header-wipe "$header_wipe"
      --loader-entries "$loader_entries"
      --stack-shaping "$stack_shaping"
      --cleanup "$cleanup"
      --execution-method "$execution_method"
      --vad-spoof "$vad_spoof"
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
        --base-address "$base_address"
        --header-wipe "$header_wipe"
        --loader-entries "$loader_entries"
        --stack-shaping "$stack_shaping"
        --cleanup "$cleanup"
        --execution-method "$execution_method"
        --vad-spoof "$vad_spoof"
      )
    fi
    expected_count=$((count_before + 1))
    echo "guest fixture: injecting $payload_name"
    wait_for_tick_window "$pid" "$tick_addr"
    if ! DECANT_SKIP_BUILD=1 "$DECANT_SH" guest-inject \
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
  local post_pass_ticks="${DECANT_GUEST_FIXTURE_POST_PASS_TICKS:-2}"
  for _ in $(seq 1 "$post_pass_ticks"); do
    wait_for_tick_window "$pid" "$tick_addr"
  done
  echo "guest fixture: PASS pid=$pid probe=$probe marker=$marker count=$count_before"
}

cmd="${1:-help}"
if [[ $# -gt 0 ]]; then
  shift
fi

case "$cmd" in
  help|-h|--help) usage ;;
  inject-test) cargo run -p xtask -- inject-test ;;
  guest-fixture) guest_fixture "$@" ;;
  *) echo "unknown test command: $cmd" >&2; usage >&2; exit 2 ;;
esac
