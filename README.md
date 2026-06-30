<p align="center">
  <img src="assets/decant_banner_dark_sm.png" alt="Decant">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/edition-2024-orange" alt="Rust">
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue" alt="License">
  <img src="https://img.shields.io/badge/target-x86__64-lightgrey" alt="x86_64">
</p>

Run an **unmodified** Windows memory-editing tool (like Cheat Engine) under Wine on Linux, with its memory reads and writes redirected to a **separate running Windows VM** via [memflow](https://github.com/memflow/memflow).

The tool sees a local Windows process. The bytes come from the guest VM, read out-of-band by the hypervisor. Decant is passive introspection: it reads and writes *existing* guest memory from the outside, and does not execute guest code.

```console
$ decant-cli read 2980 0x00007ff756d00000 16
0x00007ff756d00000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00   MZ..............
#                   bytes from the VM's explorer.exe, served to a Wine-hosted tool
```

## How it works

```
  ┌──────────────────────────────────────────────┐
  │  Windows guest VM  (QEMU/KVM)                │
  │    target.exe, unmodified                    │
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
- `MemflowBackend` (`--features memflow`): reads guest physical RAM.

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

VM backend (memflow; see the memflow backend section of [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)). Build it once:

```bash
cargo build -p decant-daemon --features memflow
```

The **QEMU connector** (default) reads the qemu process directly: no kernel module, and no root once the binary has ptrace capability. Its arg is the VM name from `qemu -name guest=<name>`; leave it empty to auto-detect a single VM.

```bash
sudo setcap 'CAP_SYS_PTRACE=ep' target/debug/decant-daemon       # one-time, instead of sudo
MEMFLOW_PLUGIN_PATH=/path/to/plugins DECANT_CONNECTOR_ARGS=<vm-name> \
  ./target/debug/decant-daemon --backend memflow --connector qemu --bind 127.0.0.1:7878
# decant-daemon listening on 127.0.0.1:7878 (backend: memflow:qemu)
```

The **KVM connector** reads through the `memflow.ko` kernel module: lower overhead, needs root and the qemu PID as its arg.

```bash
sudo env MEMFLOW_PLUGIN_PATH=/path/to/plugins \
  DECANT_CONNECTOR_ARGS=$(pgrep -f 'guest=<vm-name>') \
  ./target/debug/decant-daemon --backend memflow --connector kvm --bind 127.0.0.1:7878
```

Usage notes:

- Connector arg: the qemu connector takes the VM name (or empty to auto-detect); the kvm connector takes the qemu PID. Both are memflow's bare default arg; a `pid=` named arg fails with `Error(Connector, ArgValidation)`.
- `MEMFLOW_PLUGIN_PATH` points at the directory with `libmemflow_{qemu,kvm,win32}.so`. The plugin ABI is the integer `MEMFLOW_PLUGIN_VERSION`, not the crate version; a 0.2.4 core loads 0.2.1 plugins.
- The backend connects before binding the socket, so a failure exits with a message instead of leaving a partial server.
- Write to stable memory (zero padding), not active heap; a hot slot can be reclaimed by the guest between operations.

## Running a tool under the interposer

`wine-env/run.sh` runs any unmodified Windows tool under the isolated prefix with the
carafe injected and pointed at a daemon. It co-locates `decant-launcher.exe` and
`decant_interpose.dll` next to the target, starts it suspended, injects the carafe, and
connects to `DECANT_ENDPOINT` (default `127.0.0.1:7878`).

```bash
DECANT_ENDPOINT=127.0.0.1:7878 wine-env/run.sh path/to/tool.exe [args]
```

The tool sees the guest: its process list (served from `NtQuerySystemInformation`),
scans, and reads and writes all route to the daemon. A full-region scan reads the guest's
committed memory one request per caller read; the backend reuses the resolved process and
the daemon disables Nagle, so region scans run at interactive speed (see the memflow backend section of the architecture doc). Install
a GUI tool into the prefix first with `WINEPREFIX="$PWD/wine-env/prefix" wine installer.exe`,
then point `run.sh` at its executable. If a window fails to map after an interrupted run,
reset the prefix with `WINEPREFIX="$PWD/wine-env/prefix" wineserver -k` before relaunching.

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
| `VirtualProtectEx`/`NtProtectVirtualMemory` (success; reports the page's prior protection) | |
| `VirtualQueryEx`/`NtQueryVirtualMemory` (State/Type/Protect) | |

Notes:

- Hooks are event-driven; Decant polls. It cannot deliver a `SetWindowsHookEx`-style callback.
- A paged-out guest page reads as not-present (a `ReadFailed`, not truncated bytes).
- Freezing a fast-changing or per-frame value is racy by construction. Decant reads and writes guest memory out of band; it cannot install a hook in the guest or perform an atomic read-modify-write across the boundary, so a freeze loop can lose races against the game's own writes. Slow-changing values freeze reliably.
- Cheat Engine and any other tool that resolves the memory APIs at runtime route the same as one that imports them. Such a tool does not import `ReadProcessMemory`; it looks the address up with `GetProcAddress` at runtime, and it lists processes through `NtQuerySystemInformation` rather than toolhelp. The carafe patches `GetProcAddress`'s own import slot, so every runtime lookup of an interposed memory API returns the carafe's hook, and it synthesizes `NtQuerySystemInformation` for the process list, along with `NtOpenProcess`, `NtGetNextProcess`, `Toolhelp32ReadProcessMemory`, and the `NtQueryInformationProcess` image classes. A tool that imports the APIs directly (the bundled `sample-tool`) routes through the import-table patch instead. This is general, not a Cheat-Engine special case; either way the binding stays on public Win32/NT exports. `cargo xtask dynamic` exercises the runtime-resolution path with a tool that resolves every memory API only through `GetProcAddress` and enumerates only through `NtQuerySystemInformation`. What stays unsupported is guest code execution (see the table above).
- The synthetic process handle services the full handle tail: `OpenProcess`, `ReadProcessMemory`, `WriteProcessMemory`, `CloseHandle` and `NtClose`, `DuplicateHandle`, `WaitForSingleObject`/`WaitForSingleObjectEx`/`NtWaitForSingleObject`, `GetHandleInformation`/`SetHandleInformation`, `GetProcessId`, `GetExitCodeProcess`, `GetPriorityClass`, `GetProcessTimes`, `IsWow64Process`, `QueryFullProcessImageName`, `GetProcessImageFileName`, the `NtQueryInformationProcess` basic, wow64, and image classes, `VirtualQueryEx` and `NtQueryVirtualMemory`, and `VirtualProtectEx` and `NtProtectVirtualMemory`. The protection-change pair returns success and reports the page's prior protection without altering it: memflow writes guest physical memory and is not bound by virtual page protection, so a write to a page the tool sees as read-only lands without a real protection change. `NtQueryInformationProcess(ProcessBasicInformation)` returns the pid with a PEB base of 0, since memflow's generic ABI does not expose it, so guest PEB-walking features are unavailable. The execution and process-control exports (memory allocation, remote threads, `TerminateProcess`, `NtSuspendProcess`/`NtResumeProcess`) refuse.
- `VirtualQueryEx` and `NtQueryVirtualMemory` report `State`, `Type`, and `Protect` derived from the guest page tables and module list: a region overlapping a loaded module reports `MEM_IMAGE`, others `MEM_PRIVATE`. `MEM_MAPPED` is not distinguished, reserved uncommitted memory is not enumerated, and copy-on-write and guard sub-flags are not reported. Default scans over all types are unaffected; a `Type`-filtered or `Protect`-filtered scan may differ from native.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) section 3.

## Version-agnosticism

The carafe binds only to the public Win32/NT export ABI and the PE format (IAT patching plus
`GetProcAddress` hooking), never Wine internals (`__wine_unix_call`, the wineserver protocol,
syscall-dispatch thunks). That
surface is the most stable part of Wine, so the DLL runs on any Wine version without a recompile
tied to Wine's layout.

- Delivery: launcher-driven remote-thread injection (`decant-launcher`). Suspended-create, then `LoadLibrary` via `CreateRemoteThread`, then `DllMain` installs the IAT hooks. The target stays unmodified.
- Limitation: a tool that issues a raw `syscall` instruction, never calling the named `Nt*` export, bypasses export-level interception. Catching it would need Wine-internal syscall-dispatch hooking, which Decant avoids to keep portability.

See the injection and interception, and version-agnosticism sections of [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Crate layout

Mixed-target Cargo workspace. Host crates are `default-members`; the Windows crates build only
with `--target x86_64-pc-windows-gnu`. x86_64 throughout.

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
in the injection and interception section of the architecture doc.

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

The architecture and internals are documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

Dual-licensed under MIT OR Apache-2.0.
