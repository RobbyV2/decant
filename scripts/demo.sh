#!/usr/bin/env bash
# End-to-end Decant demo against the mock backend (no VM required).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

pid=1234
magic_addr=0x140010100
slot_addr=0x140010400
chain_head=0x140010200

echo "Building host binaries"
cargo build -p decant-daemon -p decant-cli

echo "Building Windows testbins"
cargo build --target x86_64-pc-windows-gnu \
    -p decant-interpose -p mock-cheat -p decant-launcher

daemon="$root/target/debug/decant-daemon"
cli="$root/target/debug/decant-cli"

echo "Starting decant-daemon (mock backend)"
daemon_out="$(mktemp)"
"$daemon" --backend mock --bind 127.0.0.1:0 >"$daemon_out" 2>/dev/null &
daemon_pid=$!

cleanup() {
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
    rm -f "$daemon_out"
}
trap cleanup EXIT

endpoint=""
for _ in $(seq 1 50); do
    endpoint="$(sed -n 's/.*listening on \([^ ]*\).*/\1/p' "$daemon_out" || true)"
    [ -n "$endpoint" ] && break
    sleep 0.1
done
[ -n "$endpoint" ] || { echo "daemon did not report a listening endpoint"; exit 1; }
export DECANT_ENDPOINT="$endpoint"
echo "Daemon up on $endpoint"

echo "Processes"
"$cli" processes

echo "Read demo signature at $magic_addr"
"$cli" read "$pid" "$magic_addr" 16

echo "Write to the slot at $slot_addr"
"$cli" write "$pid" "$slot_addr" "deadbeef01020304"
echo "Read the slot back"
"$cli" read "$pid" "$slot_addr" 8

echo "Scan for the signature"
"$cli" scan "$pid" "44 45 43 41 4E 54"

echo "Resolve the pointer chain from $chain_head"
"$cli" resolve "$pid" "$chain_head" 0x10

echo "Diagnostics"
"$cli" diagnostics

echo "Running mock-cheat under Wine through the launcher"
cargo run -p xtask -- e2e

echo "demo: PASS"
