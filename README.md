<p align="center">
  <img src="assets/decant_lockup_dark.png" alt="Decant" width="420">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/edition-2024-orange" alt="Rust">
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue" alt="License">
  <img src="https://img.shields.io/badge/target-x86__64-lightgrey" alt="x86_64">
</p>

Run an **unmodified** Windows memory-editing tool (Cheat Engine style) under Wine on Linux, with its memory reads and writes redirected to a **separate running Windows VM** via [memflow](https://github.com/memflow/memflow).

The tool sees a local Windows process. The bytes come from the guest VM, read out-of-band by the hypervisor. Decant is passive introspection: it reads and writes *existing* guest memory from the outside, and does not execute guest code.

```console
$ decant-cli read 2980 0x00007ff756d00000 16
0x00007ff756d00000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00   MZ..............
#                   real bytes from the VM's explorer.exe, served to a Wine-hosted tool
```

## How it works

```
  ┌──────────────────────────────────────────────┐
  │  Windows guest VM  (QEMU/KVM)                │
  │    target.exe, real and unmodified           │
  └──────────────────▲───────────────────────────┘
                     │  physical RAM read out-of-band (memflow)
  ┌──────────────────┴───────────────────────────┐
  │  Linux host                                  │
  │                                              │
  │   decant-daemon (the cellar)                 │
  │     owns the MemoryBackend, dispatches reqs  │
  │                  ▲                           │
  │                  │  TCP 127.0.0.1            │
  │                  │  length-prefixed bincode  │
  │                  │  (decant-protocol)        │
  │   Wine process   │                           │
  │     [ unmodified tool ]                      │
  │     + decant-interpose.dll (the carafe)      │
  │       intercepts Win32/NT memory exports     │
  └──────────────────────────────────────────────┘
```

Every Win32/NT memory and introspection API a tool can call (`ReadProcessMemory`,
`NtReadVirtualMemory`, `VirtualQueryEx`, `CreateToolhelp32Snapshot`, `EnumProcessModules`,
`GetProcAddress`, and the rest) reduces to nine primitives, the
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

Translating these once covers every Win32 API above them.

## Backends

- `MockBackend`: scriptable mock guest, runs offline.
- `MemflowBackend` (`--features memflow`): reads real guest physical RAM.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Library

Use Decant as a crate. Embed a backend in your own program, or connect to a daemon.

```rust
use decant::prelude::*;

// In-process backend, the way memflow is used (MemflowBackend needs --features memflow):
let backend = MemflowBackend::connect("kvm")?;
let proc = backend.process_by_name("notepad.exe")?;
let hits = scan(&backend, proc.pid, &Pattern::parse("DE CA ?? EF")?)?;
let addr = resolve(&backend, proc.pid, 0x140010200, &[0x10])?;
let bytes = backend.read(proc.pid, addr, 4)?;

// Or talk to a running daemon over the network:
let mut client = Client::new("127.0.0.1:7878");
let procs = client.processes()?;
client.write(Pid(1234), 0x140010400, &[0xAA; 4])?;
```

## Quickstart (offline, no VM)

```bash
cargo build          # host crates (default-members) only
cargo test           # 79 tests against the mock backend; no VM, no mingw
```

For the Wine and cross-compile path:

```bash
rustup target add x86_64-pc-windows-gnu     # plus system mingw-w64 and wine
cargo xtask wine-smoke
# cross-compiles a Rust cdylib (hello-dll), loads it from a PE32+ exe under an
# isolated repo-local WINEPREFIX, calls the exported `add`, prints 5
```

`xtask` subcommands: `setup`, `build-native`, `build-dll`, `test`, `test-live`, `wine-smoke`, `inject-test`, `e2e`, `demo`.

## CLI

Point `decant-cli` at a running daemon. The commands are the same for mock and VM backends.

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

$ decant-cli scan 3120 "DE CA ?? EF"          # AOB: hex bytes, ?? or ? wildcards
0x00007ff7004012a0
0x00007ff700401dd8

$ decant-cli resolve 3120 0x140010200 0x10    # pointer chain: base plus offsets
0x0000000000140010290  ->  u64=0x539 (1337)

$ decant-cli diagnostics
connector: memflow:kvm   reads: 42  writes: 3  unsupported_ops: 0
```

Full set: `processes`, `modules <pid>`, `exports <pid> <module>`, `read <pid> <addr> <len>`, `write <pid> <addr> <hexbytes>`, `memory-map <pid>`, `scan <pid> "<AOB>"`, `resolve <pid> <base> <off>...`, `diagnostics`. Add `--json` for machine-readable output.

## Running the daemon

Mock backend (no VM, default; develop the whole stack against a mock guest):

```bash
decant-daemon --backend mock --bind 127.0.0.1:7878
```

VM backend (memflow over QEMU/KVM, runs as root; see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), ADR-0005):

```bash
cargo build -p decant-daemon --features memflow

QPID=$(pgrep -f 'guest=<vm-name>')          # the qemu-system process for your VM
sudo env \
  MEMFLOW_PLUGIN_PATH=/path/to/plugins \
  DECANT_CONNECTOR_ARGS="$QPID" \
  ./target/debug/decant-daemon --backend memflow --connector kvm --bind 127.0.0.1:7878
# decant-daemon listening on 127.0.0.1:7878 (backend: memflow:kvm)
```

Usage notes (memflow over QEMU/KVM):

- The qemu PID is memflow's bare default arg. A `pid=` named arg fails with `Error(Connector, ArgValidation)`.
- The plugin ABI is the integer `MEMFLOW_PLUGIN_VERSION`, not the crate version; a 0.2.4 core loads 0.2.1 plugins.
- KVM needs root (`/dev/memflow` is `root:root`). The backend connects before binding the socket, so a failure exits with a message instead of leaving a partial server.
- Write to stable memory (zero padding), not active heap. Actively-used slots get reclaimed during a test.

## Limits

memflow reads and writes existing memory and enumerates or resolves. It does not run guest
code. Decant returns a structured error and increments a diagnostics counter for any operation
it cannot perform, and never returns a false success.

| Supported | Unsupported (returns an error) |
|---|---|
| Read and write existing memory | `VirtualAllocEx` and new guest allocations |
| AOB scan | `CreateRemoteThread` and remote threads |
| Pointer-chain resolution | DLL injection into the target |
| Module and export resolution | `SetWindowsHookEx` |
| In-place byte patching | Calling a guest function |
| `VirtualProtectEx` (no-op success) | |
| `VirtualQueryEx` (best-effort) | |

Notes:

- Hooks are event-driven; Decant polls. It cannot deliver a `SetWindowsHookEx`-style callback.
- There is no atomic read-modify-write across the VM boundary, and a paged-out guest page reads as not-present (a `ReadFailed`, not truncated bytes).
- Interception is by IAT patching, so a tool that imports the Win32 memory APIs directly (for example the bundled `sample-tool`) routes through the interposer and reaches the guest. A tool that resolves those APIs at runtime through a function pointer, or enumerates processes via `NtQuerySystemInformation` (for example Cheat Engine), is not captured by IAT patching and does not route. The carafe patches the static import slots; calls that never go through those slots are not seen.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) section 3.

## Version-agnosticism

The carafe binds only to the public Win32/NT export ABI and the PE format (IAT patching), never
Wine internals (`__wine_unix_call`, the wineserver protocol, syscall-dispatch thunks). That
surface is the most stable part of Wine, so the DLL runs on any Wine version without a recompile
tied to Wine's layout.

- Delivery: launcher-driven remote-thread injection (`decant-launcher`). Suspended-create, then `LoadLibrary` via `CreateRemoteThread`, then `DllMain` installs the IAT hooks. The target stays unmodified.
- Limitation: a tool that issues a raw `syscall` instruction, never calling the named `Nt*` export, bypasses export-level interception. Catching it would need Wine-internal syscall-dispatch hooking, which Decant avoids to keep portability.

See the Version-agnosticism section and ADR-0006 in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Crate layout

Mixed-target Cargo workspace. Host crates are `default-members`; the Windows crates build only
with `--target x86_64-pc-windows-gnu` (ADR-0003). x86_64 throughout (ADR-0004).

| Path | Target | Role |
|---|---|---|
| `crates/decant` | host | Library facade: re-exports backends, scanner and resolver, and the client |
| `crates/decant-protocol` | host + win-gnu | Wire contract and shared domain types; `write_msg`/`read_msg` framing |
| `crates/decant-client` | host + win-gnu | Daemon client over decant-protocol |
| `crates/decant-backend` | host | `MemoryBackend` trait, `MockBackend`, `MockGuest` |
| `crates/decant-memflow` | host | `MemflowBackend` (VM, feature-gated) |
| `crates/decant-core` | host | AOB scanner and pointer-chain resolver |
| `crates/decant-daemon` | host | TCP server and dispatch (the cellar) |
| `crates/decant-cli` | host | user CLI |
| `crates/decant-wine-harness` | host | launches exes under Wine for `cargo test` |
| `crates/decant-interpose` | win-gnu (cdylib) | interposer DLL (the carafe), IAT patching |
| `testbins/guest-target` | win-gnu | sample target for VM tests |
| `testbins/sample-tool` | win-gnu | stand-in tool for harness tests |
| `testbins/decant-launcher` | win-gnu | suspended-create and remote-thread DLL injector |
| `testbins/dll-smoke` | win-gnu | loads `hello-dll`, checks the toolchain under Wine |
| `testbins/hello-dll` | win-gnu (cdylib) | minimal PE32+ DLL exporting `add` |
| `xtask` | host | build and test orchestration |

## Status

Decant reads and writes guest memory, runs AOB scans, resolves pointer chains, and
provides an interposer that redirects an unmodified tool's Win32 calls. The memflow
backend is validated against a Windows 10 guest; the interposer vector is documented
in ADR-0006.

79 tests, run offline with no VM.

## Testing

Two modes behind one trait: a mock backend offline, and memflow against a VM.

```bash
cargo test               # mock mode: protocol, dispatch, scanner/resolver, CLI; no VM
cargo xtask wine-smoke   # cross-compile and load a DLL under Wine
cargo test -- --ignored  # VM mode, gated on DECANT_LIVE=1 and a running guest
```

Writes are verified by read-back, not by the return value. Unsupported operations return a
structured error, asserted in tests so they cannot become silent corruption.

Design rationale and the ADR log are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

Dual-licensed under MIT OR Apache-2.0.
