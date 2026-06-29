<p align="center">
  <img src="assets/decant_lockup_dark.png" alt="Decant" width="420">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-2021-orange" alt="Rust">
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue" alt="License">
  <img src="https://img.shields.io/badge/target-x86__64-lightgrey" alt="x86_64">
  <img src="https://img.shields.io/badge/Phases%200–2-live--validated-success" alt="Phases 0-2 live-validated">
</p>

Run an **unmodified** Windows memory-editing tool (Cheat Engine–style) under Wine on Linux, with its memory reads/writes transparently redirected to a **separate running Windows VM** via [memflow](https://github.com/memflow/memflow).

The tool believes it is inspecting a local Windows process. The bytes actually come from the guest VM, read out-of-band by the hypervisor. Decant is **passive introspection** — it reads and writes *existing* guest memory from the outside, and deliberately **cannot execute guest code**.

```console
$ decant-cli read 2980 0x00007ff756d00000 16
0x00007ff756d00000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00   MZ..............
#                   └─ real bytes from the VM's explorer.exe, served to a Wine-hosted tool
```

---

## How it works

```
  ┌──────────────────────────────────────────────┐
  │  Windows guest VM  (QEMU/KVM)                 │
  │    target.exe — real, unmodified, oblivious   │
  └──────────────────▲───────────────────────────┘
                     │  physical RAM read out-of-band (memflow)
  ┌──────────────────┴───────────────────────────┐
  │  Linux host                                   │
  │                                               │
  │   decant-daemon  "the cellar"                 │
  │     owns the MemoryBackend, dispatches reqs   │
  │                  ▲                            │
  │                  │  TCP 127.0.0.1             │
  │                  │  length-prefixed bincode   │
  │                  │  (decant-protocol "funnel")│
  │   Wine process   │                            │
  │     [ unmodified tool ]                       │
  │     + decant-interpose.dll  "the carafe" ─────┘
  │       intercepts Win32/NT memory exports
  └──────────────────────────────────────────────┘
```

**The narrow waist.** Every Win32/NT memory + introspection API a tool can call
(`ReadProcessMemory`, `NtReadVirtualMemory`, `VirtualQueryEx`, `CreateToolhelp32Snapshot`,
`EnumProcessModules`, `GetProcAddress`, …) collapses onto **nine primitives** — the
[`MemoryBackend`](crates/decant-backend/src/lib.rs) trait:

```rust
fn list_processes(&self) -> Result<Vec<ProcessInfo>>;
fn process_by_pid(&self, pid: Pid) -> Result<ProcessInfo>;
fn module_list(&self, pid: Pid) -> Result<Vec<ModuleInfo>>;
fn module_exports(&self, pid: Pid, module: &str) -> Result<Vec<(String, u64)>>;
fn read(&self, pid: Pid, addr: u64, len: usize) -> Result<Vec<u8>>;
fn write(&self, pid: Pid, addr: u64, data: &[u8]) -> Result<usize>;
fn memory_map(&self, pid: Pid) -> Result<Vec<MemRegion>>;
// + process_by_name, module_by_name
```

Translate these once and every Win32 API above them comes along for free. Two backends sit behind the trait:

| Backend | VM? | When |
|---|---|---|
| `MockBackend` (the "tasting") | none | **default** — scriptable fake guest, fully offline |
| `MemflowBackend` | live VM | `--features memflow` — reads real guest physical RAM |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Quickstart (offline, no VM)

```bash
cargo build          # builds host crates (default-members) only
cargo test           # 70+ tests, all run against the mock backend — no VM, no mingw
```

For the Wine / cross-compile path:

```bash
rustup target add x86_64-pc-windows-gnu     # + system mingw-w64 + wine
cargo xtask wine-smoke
# cross-compiles a Rust cdylib (hello-dll), loads it from a PE32+ exe under an
# isolated repo-local WINEPREFIX, calls the exported `add` → prints 5
```

`xtask` subcommands: `setup` · `build-native` · `build-dll` · `test` · `test-live` · `wine-smoke` · `spike` · `phase3` · `demo`.

---

## CLI

Point `decant-cli` at a running daemon (mock or live — the commands are identical).

```console
$ decant-cli processes
   4  System
2980  explorer.exe
3120  target.exe
 ...

$ decant-cli modules 2980
ntdll.dll        0x00007ffb8e2c0000  0x1f0000
KERNEL32.DLL     0x00007ffb8d910000  0x0c1000
 ...

$ decant-cli read 2980 0x00007ff756d00000 16
0x00007ff756d00000  4d 5a 90 00 03 00 00 00 ...   MZ..............

$ decant-cli write 3120 0x00007ff700401000 deadbeef
wrote 4 bytes
$ decant-cli read 3120 0x00007ff700401000 4
0x00007ff700401000  de ad be ef                    ....

$ decant-cli scan 3120 "DE CA ?? EF"          # AOB: hex bytes, ?? / ? wildcards
0x00007ff7004012a0
0x00007ff700401dd8

$ decant-cli resolve 3120 0x140010200 0x10    # pointer chain: base + offsets
0x0000000000140010290  ->  u64=0x539 (1337)

$ decant-cli diagnostics
connector: memflow:kvm   reads: 42  writes: 3  exec_wall_hits: 0
```

Full set: `processes` · `modules <pid>` · `exports <pid> <module>` · `read <pid> <addr> <len>` · `write <pid> <addr> <hexbytes>` · `memory-map <pid>` · `scan <pid> "<AOB>"` · `resolve <pid> <base> <off>...` · `diagnostics`.

---

## Running the daemon

**Offline / mock** (no VM, default — develop the whole stack against a fake guest):

```bash
decant-daemon --backend mock --bind 127.0.0.1:7878
```

**Live VM** (memflow over QEMU/KVM — runs as root, see [docs/TESTING.md](docs/TESTING.md) / ADR-0005):

```bash
cargo build -p decant-daemon --features memflow

QPID=$(pgrep -f 'guest=<vm-name>')          # the qemu-system process for your VM
sudo env \
  MEMFLOW_PLUGIN_PATH=/path/to/plugins \
  DECANT_CONNECTOR_ARGS="$QPID" \
  ./target/debug/decant-daemon --backend memflow --connector kvm --bind 127.0.0.1:7878
# → decant-daemon listening on 127.0.0.1:7878 (backend: memflow:kvm)
```

> **Gotchas (live-validated 2026-06-29 against a Win10 guest):**
> - The qemu PID is memflow's **bare default arg**. A `pid=` *named* arg fails with `Error(Connector, ArgValidation)`.
> - Plugin ABI is the integer `MEMFLOW_PLUGIN_VERSION`, not the crate version — a 0.2.4 core happily loads 0.2.1 plugins.
> - KVM needs **root** (`/dev/memflow` is `root:root`). Capability detection fails *before* binding, never a half-up server.
> - Write to **stable** memory (zero padding), not churning heap — actively-used slots get reclaimed mid-test.

---

## The execution wall

memflow can read/write existing memory and enumerate/resolve — it **cannot run guest code**. Decant surfaces this honestly (`ProtoError::ExecutionWall { op }`, counted by `Diagnostics::exec_wall_hits`) and **never fakes it**.

| Supported | Past the wall (loud failure, never faked) |
|---|---|
| Read / write existing memory | `VirtualAllocEx` / new guest allocations |
| AOB scan | `CreateRemoteThread` / remote threads |
| Pointer-chain resolution | DLL injection into the *target* |
| Module / export resolution | `SetWindowsHookEx` |
| In-place byte patching | Calling a guest function |
| `VirtualProtectEx` → no-op success | |
| `VirtualQueryEx` → best-effort | |

Two truths stated plainly:
- **Hooks are event-driven; Decant is poll-only.** It cannot deliver a `SetWindowsHookEx`-style callback.
- **No atomicity across the VM boundary** — no atomic read-modify-write, and paged-out guest pages read as *not-present* (a clean `ReadFailed`, never truncated bytes).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) §3.

---

## Version-agnosticism

The carafe binds to **only** the public Win32/NT export ABI + the PE format (IAT patching) — **never** Wine internals (`__wine_unix_call`, the wineserver protocol, syscall-dispatch thunks). That surface is the most stable thing Wine offers, so the DLL drops onto any Wine version unchanged, no recompile tied to Wine's layout.

- **Delivery** = launcher-driven remote-thread injection (`decant-launcher`): suspended-create → `LoadLibrary` via `CreateRemoteThread` → `DllMain` self-installs the IAT hooks. The target stays unmodified.
- **Known hole:** a tool issuing a **raw `syscall` instruction** (never calling the named `Nt*` export) bypasses all export-level interception. Closing it would require Wine-internal syscall-dispatch hooking — Decant keeps portability instead. (It still cannot escape the execution wall.)

See [docs/VERSIONING.md](docs/VERSIONING.md) and ADR-0006 in [docs/DECISIONS.md](docs/DECISIONS.md).

---

## Crate layout

Mixed-target Cargo workspace. Host crates are `default-members`; the Windows crates build only with `--target x86_64-pc-windows-gnu` (ADR-0003). x86_64 everywhere (ADR-0004).

| Path | Target | Role |
|---|---|---|
| `crates/decant-protocol` | host + win-gnu | Wire contract + shared domain types; `write_msg`/`read_msg` framing |
| `crates/decant-backend` | host | `MemoryBackend` trait + `MockBackend` / `MockGuest` |
| `crates/decant-memflow` | host | `MemflowBackend` (live VM, feature-gated) |
| `crates/decant-core` | host | AOB scanner + pointer-chain resolver |
| `crates/decant-daemon` | host | "the cellar" — TCP server + dispatch |
| `crates/decant-cli` | host | user CLI |
| `crates/decant-wine-harness` | host | launches exes under Wine for `cargo test` |
| `crates/decant-interpose` | win-gnu (cdylib) | "the carafe" — interposer DLL (IAT patching) |
| `testbins/guest-target` | win-gnu | sample target for live tests |
| `testbins/mock-cheat` | win-gnu | stand-in cheat tool for harness tests |
| `testbins/decant-launcher` | win-gnu | suspended-create + remote-thread DLL injector |
| `testbins/dll-smoke` | win-gnu | loads `hello-dll`, proves the toolchain under Wine |
| `testbins/hello-dll` | win-gnu (cdylib) | minimal PE32+ DLL exporting `add` |
| `xtask` | host | build/test orchestration |

---

## Status

| Phase | Scope | State |
|---|---|---|
| 0 | Toolchain / scaffolding | ✅ |
| 1 | Daemon · CLI · memflow backend | ✅ **live-validated** (real Win10 guest) |
| 2 | AOB scanner + pointer-chain resolver | ✅ **live-validated** |
| 3 | Interposer DLL (IAT patch + injection) | 🚧 in progress (vector Wine-validated, ADR-0006) |
| 4 | Execution-wall polish + demo | ⏳ pending |

**70+ tests, fully offline-testable with no VM.**

---

## Testing

Two modes behind one trait — see [docs/TESTING.md](docs/TESTING.md).

```bash
cargo test               # mock mode: protocol, dispatch, scanner/resolver, CLI — no VM
cargo xtask wine-smoke   # cross-compile + Wine load proof
cargo test -- --ignored  # live mode: gated on DECANT_LIVE=1 + a running guest
```

Writes are verified by **read-back**, not by trusting the return value. Anything past the execution wall must return `ProtoError::ExecutionWall`, asserted explicitly so the wall can never silently become corruption.

Design rationale and the full ADR log live in [docs/DECISIONS.md](docs/DECISIONS.md).

---

## License

Dual-licensed under **MIT OR Apache-2.0**, at your option.
