# Decant project utilities. Run `just` to list.

win_target := "x86_64-pc-windows-gnu"
win_crates := "-p decant-interpose -p sample-tool -p decant-launcher -p guest-target -p dll-smoke -p hello-dll"

default:
    @just --list

build:
    cargo build

test:
    cargo test

# format every crate, host and windows-target
fmt:
    cargo fmt --all

# verify formatting without writing (CI uses this)
fmt-check:
    cargo fmt --all --check

clippy:
    cargo clippy --all-targets

# cross-compile every windows crate
build-win:
    cargo build --target {{win_target}} {{win_crates}}

# load a rust dll under wine and call its export
wine-smoke:
    cargo run -p xtask -- wine-smoke

# interposer against a mock daemon under wine
e2e:
    cargo run -p xtask -- e2e

# injection vector check without a daemon
inject-test:
    cargo run -p xtask -- inject-test

# offline end-to-end demo
demo:
    bash scripts/demo.sh

# the whole offline suite
check: build test build-win wine-smoke inject-test e2e

# daemon on the mock backend
daemon port="7878":
    cargo run -p decant-daemon -- --backend mock --bind 127.0.0.1:{{port}}

# build the daemon and cli with the memflow feature
build-memflow:
    cargo build --release -p decant-daemon -p decant-cli --features memflow

# daemon on a qemu/kvm guest via the kvm connector, as root.
# set MEMFLOW_PLUGIN_PATH to the dir holding libmemflow_kvm.so and libmemflow_win32.so.
daemon-vm vm port="7878":
    #!/usr/bin/env bash
    set -euo pipefail
    : "${MEMFLOW_PLUGIN_PATH:?set MEMFLOW_PLUGIN_PATH to the memflow plugin dir}"
    qpid=""
    for p in $(pgrep -f "guest={{vm}}"); do
      case "$(cat /proc/$p/comm 2>/dev/null)" in qemu-system*) qpid=$p; break;; esac
    done
    [ -n "$qpid" ] || { echo "no qemu process for guest={{vm}}"; exit 1; }
    sudo env MEMFLOW_PLUGIN_PATH="$MEMFLOW_PLUGIN_PATH" DECANT_CONNECTOR_ARGS="$qpid" \
      ./target/release/decant-daemon --backend memflow --connector kvm --bind 127.0.0.1:{{port}}

# drive the cli, e.g. `just cli processes`
cli *args:
    cargo run -q -p decant-cli -- {{args}}

# initialize the isolated wine prefix
wine-setup:
    bash wine-env/setup.sh

# delete the wine prefix
clean-prefix:
    rm -rf wine-env/prefix
