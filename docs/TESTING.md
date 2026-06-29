# Decant Testing

Decant's design goal is that ~90% of the system is testable **without a VM and
without memflow**. This is achieved by funnelling all memory access through the
`MemoryBackend` trait (see `docs/ARCHITECTURE.md` sections 2 and 4) and providing a
scriptable mock guest behind it. This document describes the two test modes (mock
and VM), how to run each, the property-test approach, the write-verification
strategy, and adversarial review prompts.

---

## 1. Mock vs VM

| | **Mock mode (offline)** | **VM mode** |
|---|---|---|
| Backend | `MockBackend` over a `MockGuest` | `MemflowBackend` over a QEMU/KVM connector |
| Needs a VM? | No | Yes (running Windows guest) |
| Needs memflow? | No | Yes |
| Determinism | Fully deterministic | Depends on guest state |
| Coverage | Protocol, framing, dispatch, core scanner/resolver, CLI, carafe marshaling | The memflow translation layer + real end-to-end |
| When it runs | Every `cargo test`, CI, default | Opt-in, gated, `--ignored` |

The mock backend is the basis of the offline suite: `MockBackend` implements every
trait method deterministically, and writes round-trip (write-then-read returns the
new bytes), so everything above the backend seam is provable offline. `MemflowBackend` is the
*only* component that genuinely requires a VM, and it is swapped in behind the
identical trait, so the suites above it do not change between modes.

---

## 2. Running the offline suite

```bash
# 1. Host unit/integration tests (no VM, no mingw needed).
cargo test                 # runs default-members only (host crates)

# 2. Orchestrated test run (host tests + cross-compiled Windows testbins).
cargo xtask test           # builds win-gnu testbins, runs host tests

# 3. Toolchain smoke test under Wine: build hello-dll + dll-smoke for
#    x86_64-pc-windows-gnu, run dll-smoke.exe under Wine, assert it loads the
#    DLL and calls the exported `add` (proves the cross-compile + Wine path).
cargo xtask wine-smoke
```

Notes:
- `cargo test` touches only `default-members` (host crates) by ADR-0003, so it
  works for contributors without a mingw toolchain.
- The Windows testbins are built explicitly via `--target x86_64-pc-windows-gnu`;
  `xtask` wraps this so contributors do not memorize the target triple.
- `wine-smoke` is the end-to-end proof of the build/run path that the carafe will
  later use: cross-compile a PE32+ DLL, load it from a PE32+ exe, execute under
  Wine, observe the result. It uses `decant-wine-harness::run_under_wine`, which
  launches an exe under an isolated `WINEPREFIX` and captures stdout/exit so the
  check is `cargo test`-drivable.

Everything in this section runs with **no VM present**.

---

## 3. Running the VM suite

VM tests are `#[ignore]`d by default and gated on environment variables so they
never run by accident in CI or on a VM-less machine.

```bash
# Requires: a running Windows guest VM + a memflow connector available.
export DECANT_LIVE=1                       # master switch for VM tests
export DECANT_CONNECTOR=qemu               # connector name (e.g. qemu/kvm)
# ...plus any connector-specific env the verified memflow API needs (ADR-0005).

cargo test -- --ignored                    # run the ignored (VM) tests
```

Contract for a live test:
- Skip (or `panic!` with a clear message) unless `DECANT_LIVE=1` is set, so a bare
  `cargo test -- --ignored` on a dev box does not hang waiting for a VM.
- Read the connector and target selection from env (`DECANT_CONNECTOR`, plus the
  process/module to inspect), never hard-code a machine-specific path.
- Assert against the *same* observable behavior the mock suite asserts, so the only
  variable under test is the memflow translation layer.

The exact connector-construction env and method names are **pending ADR-0005**
(verified empirically against the VM); this section is the slot they plug into.

---

## 4. Property tests

The framing and the backend invariants are good fits for property testing:

- **Framing round-trip.** For arbitrary `Request`/`Response` values, `read_msg ∘
  write_msg == identity`. (The current unit tests assert this over a hand-picked
  spread of every variant via `Cursor`; the property version generalizes the
  payloads.)
- **Frame boundary integrity.** For a vector of arbitrary messages serialized
  back-to-back into one buffer, reading them back yields the same sequence with no
  bleed (the "two messages back to back" unit test, generalized to N).
- **Hostile length prefix.** Any `len > MAX_MSG_LEN` errors rather than allocating;
  any truncated tail yields `UnexpectedEof`.
- **Mock memory algebra.** For arbitrary non-overlapping `(addr, bytes)` writes
  inside a region, a subsequent `read` of any sub-range returns exactly the bytes
  last written there (see section 5).

---

## 5. Host-side write-verification strategy

Writes are the dangerous primitive, so they are verified by **read-back**, not by
trusting the return value:

1. A `write(pid, addr, data)` returns the count written.
2. The test immediately issues `read(pid, addr, data.len())` and asserts the bytes
   equal `data`.
3. Where applicable, neighbouring bytes are read too and asserted *unchanged*, so a
   write is proven to have hit exactly its range and not one byte more.

In **mock mode** this is exact and deterministic. `MockBackend`'s write mutates
the region's byte map and the read returns from the same map, so the round-trip is
a true equality check (the `MockGuest` builder's `bytes_at`/`u32_at`/`u64_at`
seeds give known starting values to diff against).

In **VM mode** the same read-back pattern applies through `MemflowBackend`,
giving an end-to-end proof that a host-issued write actually landed in guest
physical RAM and is visible on the next read. The `Diagnostics` counters (`reads`,
`writes`, `unsupported_ops`) are asserted to move as expected, and any unsupported
operation (alloc/thread/inject) must return
`ProtoError::Unsupported` rather than a synthetic success. A test asserts this
explicitly so an unsupported operation can never silently turn into corruption.

---

## 6. Adversarial review ideas

Adversarial prompts to run as tests or manual review:

- **Toolchain and scaffolding.** Does a bare `cargo build`/`cargo test`
  *ever* try to compile a win-gnu crate for Linux? Confirm `default-members`
  excludes them and CI on a box *without* mingw stays green. Confirm the framing
  reader cannot be made to over-allocate by a crafted length prefix.
- **memflow and daemon.** Feed the daemon a `pid`/module that does not
  exist, a zero-length read, a read straddling a region boundary, and a write to a
  read-only region. Each must produce the *correct* structured `ProtoError`, not
  a panic or a partial result. Verify a guessed-vs-verified memflow API mismatch
  surfaces as a build/feature error, not a silent wrong read.
- **Core scanner and resolver.** Construct a `MockGuest` where the AOB
  pattern appears at a region boundary, appears zero times, and appears twice;
  build a pointer chain with a deliberately bad link. The scanner/resolver must
  not read out of bounds or loop, and must report misses cleanly.
- **Carafe injection.** Point a real tool at the carafe and have it call
  an *execution* API (`VirtualAllocEx`, `CreateRemoteThread`). Confirm it is
  rejected clearly as unsupported (and increments `unsupported_ops`) rather than
  returning a bogus handle. Then have the tool issue a **raw syscall** that bypasses
  the export layer (see `docs/VERSIONING.md`, the documented limitation) and confirm
  Decant's docs/diagnostics make that bypass visible rather than pretending coverage.

## VM runbook (run on the VM host)

The offline suite proves the daemon + CLI against `--backend mock` with no VM.
This procedure proves the same path against a real Windows 10 guest via memflow.

The arg/plugin-path details matter (see ADR-0005 "Validation against the VM").

Prerequisites (one-time): the memflow connector + win32 `.so` plugins must exist
(`memflowup install memflow-kvm memflow-win32`, or prebuilt) and, for KVM, the
`memflow` kernel module loaded. The plugin's core version **need not equal** the core
`decant-memflow` links; only the integer `MEMFLOW_PLUGIN_VERSION` ABI must match
(0.2.4 core loads 0.2.1 plugins fine). Build the daemon:

```sh
cargo build -p decant-daemon --features memflow      # add --release for the real run
```

Run the procedure (Windows VM booted under QEMU/KVM). KVM reads `/dev/memflow`
(`root:root`), so the daemon runs as **root**:

```sh
# MEMFLOW_PLUGIN_PATH = dir holding libmemflow_kvm.so + libmemflow_win32.so.
# DECANT_CONNECTOR_ARGS = the qemu process PID passed BARE, memflow's default/unnamed
#   arg. A `pid=...` NAMED arg fails with Error(Connector, ArgValidation).
QPID=$(pgrep -f 'guest=<vm-name>')        # the qemu-system process for your VM
sudo env \
  MEMFLOW_PLUGIN_PATH=/path/to/plugins \
  DECANT_CONNECTOR_ARGS="$QPID" \
  ./target/debug/decant-daemon --backend memflow --connector kvm --bind 127.0.0.1:7878
# Capability detection: a missing plugin / wrong arg / unreachable VM exits HERE with a
# clear message, before binding, never a silent half-up server. On success it prints:
#   decant-daemon listening on 127.0.0.1:7878 (backend: memflow:kvm)

# From another shell, as your normal user:
decant-cli processes                       # real guest processes (System, explorer.exe…)
decant-cli modules <pid>                    # explorer.exe -> Explorer.EXE, ntdll.dll, …
decant-cli read  <pid> <module-base> 2     # must be `4d 5a` (MZ), self-checking read
decant-cli memory-map <pid>                # find an rw- region; pick stable zero padding
decant-cli write <pid> <addr> deadbeef     # write…
decant-cli read  <pid> <addr> 4            # …read back: de ad be ef
decant-cli diagnostics                     # connector: memflow:kvm, reads/writes counters
```

This passes when `processes` lists real processes and the read-back shows the written
bytes. **Pick a stable/unused write target** (zero-filled padding, or `guest-target`'s
slot): writing *actively-used* heap is racy, observed when a churning heap slot
was reclaimed by the guest mid-test (an atomicity caveat). `read_raw`/`write_raw`
surface paged-out memory as a clean `ReadFailed`/`WriteFailed`, never truncated data.
