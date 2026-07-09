<p align="center">
  <img src="https://raw.githubusercontent.com/RobbyV2/decant/main/assets/decant_banner_dark_sm.png" alt="Decant">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-blue" alt="Version 0.1.0">
  <a href="https://github.com/RobbyV2/decant/actions/workflows/build.yml"><img src="https://github.com/RobbyV2/decant/actions/workflows/build.yml/badge.svg?branch=main" alt="CI"></a>
  <img src="https://img.shields.io/badge/edition-2024-orange" alt="Rust">
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue" alt="License">
  <img src="https://img.shields.io/badge/target-x86__64-lightgrey" alt="x86_64">
</p>

Run an **unmodified** Windows memory-editing tool, such as Cheat Engine, under Wine on Linux, with its memory reads and writes redirected to a **separate running Windows VM** via [memflow](https://github.com/memflow/memflow).

The tool sees a local Windows process. The bytes come from the guest VM, read out-of-band by the hypervisor. The interposed tool API is passive introspection: it reads and writes *existing* guest memory from the outside. Explicit guest DLL injection is a separate `decant-cli guest-inject` path that accepts DLL bytes, maps them into a selected guest process, and invokes the payload through the configured guest execution method.

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
use decant_vmi::prelude::*;

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

`xtask` subcommands: `setup`, `build-native`, `build-dll`, `test`, `test-live`, `wine-smoke`, `guest-inject-fixture`, `inject-test`, `e2e`.

## Master runner

`scripts/decant.sh` is the tracked operator entry point. It builds the required artifacts and keeps runtime VM and Wine actions behind subcommands. Fixture and regression harnesses live in `scripts/decant-test.sh`.

```bash
# Build host and Wine artifacts.
scripts/decant.sh build

# Run a Wine-hosted tool through the launcher. The target can be Cheat Engine or any PE exe.
scripts/decant.sh wine-run --method standard "$HOME/.wine/drive_c/Program Files/Cheat Engine/Cheat Engine.exe"
scripts/decant.sh wine-run --method manual-map ./target/decant-run/sample-tool.exe --inject-test

# Start the memflow daemon in the foreground.
MEMFLOW_PLUGIN_PATH=/opt/memflow scripts/decant.sh daemon --connector qemu --vm win10
MEMFLOW_PLUGIN_PATH=/opt/memflow scripts/decant.sh daemon --connector kvm --vm win10

# Inject DLL bytes into a guest process through a running daemon.
scripts/decant.sh guest-inject \
  --pid 7800 \
  --payload ./payload.dll \
  --stage-base 0x1400013b0 \
  --result-base 0x140022000

# Reproduce the tracked VM fixture. Copy target/decant-run/guest-inject-target.exe
# into the VM, start it there, then run:
MEMFLOW_PLUGIN_PATH=/opt/memflow scripts/decant-test.sh guest-fixture --connector kvm --vm win10
```

The KVM connector normally needs root access for the daemon. If running `guest-fixture` from a non-interactive shell, run `sudo -v` first so the script can start the daemon without a password prompt.

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

Choose one memflow connector path and keep its argument shape with it. The **QEMU connector**
reads the qemu process directly: no kernel module, and no root once the binary has ptrace
capability. Its arg is the VM name from `qemu -name guest=<name>`; leave it empty to
auto-detect a single VM.

```bash
# one-time, instead of sudo:
sudo setcap 'CAP_SYS_PTRACE=ep' target/debug/decant-daemon

MEMFLOW_PLUGIN_PATH=/path/to/plugins DECANT_CONNECTOR_ARGS=<vm-name> \
  ./target/debug/decant-daemon --backend memflow --connector qemu --bind 127.0.0.1:7878
# decant-daemon listening on 127.0.0.1:7878 (backend: memflow:qemu)
```

The **KVM connector** reads through the `memflow.ko` kernel module: lower overhead, needs
root and the qemu PID as its arg. Do not pass the VM name to this connector.

```bash
QEMU_PID=$(pgrep -f 'guest=<vm-name>')

sudo env MEMFLOW_PLUGIN_PATH=/path/to/plugins \
  DECANT_CONNECTOR_ARGS="$QEMU_PID" \
  ./target/debug/decant-daemon --backend memflow --connector kvm --bind 127.0.0.1:7878
```

If the QEMU connector starts, finds the qemu process, then exits with `unable to find dtb`,
the daemon never binds its TCP port and the CLI will report connection refused. That is a
connector/Windows-OS-layer startup failure, not evidence that the target process or DLL is
wrong. Use the KVM connector path if that plugin and kernel module are available, or pass
memflow-win32 OS hints such as `dtb`/`kernel_hint` once those are known:

```bash
MEMFLOW_PLUGIN_PATH=/path/to/plugins \
  DECANT_CONNECTOR_ARGS=<vm-name> \
  DECANT_OS_ARGS=':arch=x64,dtb=<hex-dtb-without-0x>,kernel_hint=<hex-va-without-0x>' \
  ./target/debug/decant-daemon --backend memflow --connector qemu --bind 127.0.0.1:7878
```

Usage notes:

- Connector arg: the qemu connector takes the VM name (or empty to auto-detect); the kvm connector takes the qemu PID. Both are memflow's bare default arg; a `pid=` named arg fails with `Error(Connector, ArgValidation)`.
- OS arg: `DECANT_OS_ARGS` is passed to memflow-win32. Use a leading `:` when only passing key/value hints, for example `:arch=x64,dtb=1aa000`.
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

### Injection configuration

`decant-launcher.exe` reads an optional TOML file from `DECANT_CONFIG`. If the file is
absent, the launcher uses the standard method and a 5000 ms ready-token timeout. A malformed
file fails before the target is resumed.

```toml
[injection]
method = "standard"        # standard | manual-map | thread-hijack | plugin | external
timeout_ms = 5000
plugin_path = "my_injector.dll"
external_command = ["my_inject.exe", "--flag"]
```

Methods:

- `standard`: public-export `CreateRemoteThread` at `kernel32!LoadLibraryA`; this is the default and keeps the version-agnostic guarantee.
- `manual-map`: maps `decant_interpose.dll` from its image bytes, applies relocations, resolves imports, runs TLS callbacks, and calls the DLL entry point. It reports `LoaderInternals` portability and is verified only by the carafe ready signal.
- `thread-hijack`: rewrites the suspended main thread context to run a small loader stub, waits for the ready signal, then releases the stub so it restores registers and jumps to the original instruction pointer. It reports `PrologueBytes` portability.
- `plugin`: loads a PE cdylib from `plugin_path` and calls its `decant_inject` export through the versioned ABI.
- `external`: starts `external_command`, writes one protocol frame containing the target PID, carafe path, carafe bytes, and ready-token name, then waits for the same ready signal.

Bring-your-own injectors must run PE-side in the same Wine prefix as the launcher. The process
handle is a wineserver handle, so an arbitrary Linux program cannot use it directly. A plugin
exports `decant_inject_abi() -> u32` and `decant_inject(*mut DecantInjectRequest) -> i32`; return
0 after starting the load, and let the harness wait on the ready token. Low-level plugin code can
reuse `decant_inject::sdk` for remote allocation, read/write, protection changes, remote
`LoadLibraryA`, remote `GetProcAddress`, and remote-thread start/wait without reaching into Wine
internals.

Guest-side DLL mapping is a separate injection domain. The daemon selects the guest process at
injection time, so config can target a PID directly or a process name plus an optional byte
pattern that disambiguates matching processes. Patterns are hex bytes with `?`/`??` wildcards.

```toml
[injection]
domain = "guest"
method = "manual-map"
timeout_ms = 10000

[guest]
process = "target.exe"          # or: pid = 1234
process_pattern = "44 45 ?? 41"
stage_pattern = "44 45 43 41 4E 54 3A 3A 53 54 41 47 45 30 30"
result_pattern = "44 45 43 41 4E 54 3A 3A 52 45 53 55 4C 54 30 34"
payload_path = "payload.dll"
allocation = "virtual-alloc"
dependency_policy = "require-loaded"  # require-loaded | load-with-guest-loader
tls = "callbacks-only"                # callbacks-only | skip | require-static
final_protections = "section"         # section | rwx
loader_metadata = "reject-unsupported" # reject-unsupported | best-effort | allow-unsupported
call_stack = "native"                 # native | registered-unwind
permission_transitions = "standard"   # standard | write-through-final
thread_starts = "existing-thread"     # existing-thread | require-module-backed
image_backing = "private"             # private | sec-image
vad_spoof = "off"                     # off | vad-image-map
hook_module = "kernel32.dll"
hook_function = "Sleep"

[guest.execution]
method = "iat-hook"
timeout_ms = 10000
```

The memflow guest injection backend maps PE32+ x64 DLL bytes, applies DIR64 relocations,
resolves normal and delay imports by name or ordinal, follows forwarded exports, materializes
newly allocated pages through the configured IAT hook, writes the image with read-after-write
checks, applies section-derived page protections by default, calls TLS callbacks according to
`tls`, and calls `DllMain`. `final_protections = "section"` allocates RW memory, writes the
mapped image, then applies PE-derived permissions before payload code runs; `rwx` is available as
an explicit compatibility mode. `dependency_policy = "require-loaded"` means every imported
module must already be present in the target process;
`load-with-guest-loader` calls the target's `LoadLibraryA` and `GetProcAddress` for missing
dependencies. By default, `loader_metadata = "reject-unsupported"` rejects payloads that need
loader metadata Decant has not been asked to model. `loader_metadata = "best-effort"` registers
x64 unwind metadata through guest `RtlAddFunctionTable` and seeds the load-config security cookie
when the mapped image exposes the default cookie slot; loader-private state such as full LDR
ownership is represented through Decant's synthesized metadata rather than by `LdrLoadDll`.
When `loader_entries = "synthesized"`, Decant allocates a static TLS slot via `TlsAlloc`, patches
the index into the image buffer, copies the TLS template, writes per-thread template copies for
existing direct TLS slots, and threads an optional `TlsSetValue` call through the DllMain thunk so
`remote-thread`, `thread-hijack`, and `apc` enter the payload with the slot installed on the
executing thread.
For payloads with load-config metadata, `loader_metadata = "best-effort"`
and `loader_entries = "synthesized"` also request a CFG valid-call-target mark
for the entry point and exported function RVAs via `SetProcessValidCallTargets`;
broader CFG/load-config metadata is still not synthesized.
`allow-unsupported` skips the guards only for payloads that do not rely on the corresponding
loader registration. `call_stack = "registered-unwind"` registers x64 unwind metadata for the
IAT-hook stub and uses a single framed stack allocation so stack walking can unwind through the
stub; it does not, by itself, spoof caller frames or shape the stack to impersonate another call
path. `permission_transitions = "write-through-final"` allocates with final-ish image
permissions, materializes pages by read-touch when the initial protection is not writable, writes
the mapped image through memflow, and skips final `VirtualProtect` calls that already match the
initial protection; the allocation/write/protect sequence is still observable.
`thread_starts = "require-module-backed"` keeps the IAT-hook path on an existing target thread
and rejects runs unless the IAT slot, original import target, and staging cave are inside loaded
module ranges; it verifies module-backed hook plumbing but does not inspect payload entrypoints
or helper calls. For `remote-thread`, `require-module-backed` requires a payload-image executable
code cave for the ThreadProc thunk and refuses to fall back to a temporary thread start.
`image_backing = "sec-image"` stages the payload as a guest temp file and maps it
through `CreateFileMappingW(SEC_IMAGE)` +
`MapViewOfFile(FILE_MAP_COPY)`, so the executable region starts as a real kernel-created
image-file section instead of private committed memory. Decant then applies relocations, imports,
delay imports, the load-config security cookie, TLS callbacks, and `DllMain` on top of that view.
The section object and image-file VAD backing are produced by the NT memory manager through
public guest exports, not forged. Pages Decant patches (imports, security cookie, IAT) become
copy-on-write private pages, while unpatched pages remain file-backed, so the
section object is real but the modified view is not identical to the on-disk image. `sec-image`
requires `allocation = "virtual-alloc"` for helper buffers and
`final_protections = "section"`, because an image-file-backed mapping uses PE-derived page
protections rather than a single RWX region.

`guest.execution.method = "iat-hook"` is the default execution path. Decant snapshots the
selected thunk, stage bytes, and writable result slot, patches them, lets one target thread run
the requested call, reads the return value, and restores the IAT-hook transaction (IAT slot,
stub bytes, result block) on every exit path. The `sec-image` trampoline and
`registered-unwind` metadata are restored or left in place separately from this transaction.
The result slot is execution scratch for this call path, not a payload success marker. For
repeatable runs, set `guest.stage_pattern` or `guest.stage_base` to executable staging bytes you
control, and set `guest.result_pattern` or `guest.result_base` to a writable scratch slot;
otherwise Decant only auto-selects memory that passes those permission checks.

`guest.execution.method = "remote-thread"` creates a kernel-tracked guest thread by first
entering the target through the IAT-hook trampoline, then calling `CreateThread` from inside the
target process. The thread starts at a `ThreadProc` thunk that calls
`DllMain(hinst, DLL_PROCESS_ATTACH, reserved)` with the proper x64 calling convention. If the mapped
payload image has a large enough executable code cave, Decant places that thunk there so the
kernel-recorded start address is inside the mapped image; `thread_starts =
"require-module-backed"` makes that placement mandatory. The ThreadProc thunk stores DllMain's
return value and a completion marker in its scratch block; the host polls those bytes through the
backend instead of requiring another target import call after `CreateThread`. Remote-thread
launch helpers use native helper-call stack handling even when `stack_shaping = "spoofed"` is
selected; DllMain itself runs on the new thread through the thunk.

`guest.execution.method = "thread-hijack"` enumerates guest threads, opens the selected thread,
suspends it through guest `SuspendThread`, captures and rewrites its x64 context, and resumes it
at a DllMain thunk. The thunk installs optional TLS, calls DllMain, writes the completion marker,
and jumps back to the original RIP. `guest.execution.method = "apc"` queues the same DllMain
thunk through `QueueUserAPC`; completion is observed through the thunk scratch block once the
target thread enters an alertable wait.

Guest injection results include `artifact audit:` notes for the observable properties of the
selected path: private or SEC_IMAGE-backed image memory, loader/module metadata state,
section-derived versus explicit-RWX permissions, registered or unregistered unwind/load-config
metadata, call-stack policy, permission-transition policy, thread-start policy, image-backing
policy, and the selected execution path. When requested, Decant can synthesize partial,
transient PEB loader-list entries. With `image_backing = "sec-image"` the section object and
image-file VAD backing are real kernel-created state produced through public guest exports, not
forged. `stack_shaping =
"spoofed"` is limited to writing a synthetic return address for selected helper/payload calls; it
does not synthesize a full caller chain or normalize arbitrary stacks. Decant does not hide all
allocation/write/protect observability. It does not synthesize or rewrite kernel thread-start
metadata. `vad_spoof = "vad-image-map"` walks EPROCESS/VadRoot through memflow and rewrites the
matched MMVAD's `u.VadType` to `VadImageMap` for private mappings; `image_backing = "sec-image"`
remains the path that obtains a real section object from the guest memory manager.

For UWP/AppContainer loader-style injection, the relevant extra requirement is DLL file access:
the AppContainer SID such as `S-1-15-2-1` must be granted read/execute access before
`LoadLibraryW` can open the file. Private guest byte manual-map does not use a guest-visible DLL
path; `image_backing = "sec-image"` stages a temporary guest file to obtain a real image section,
and loader-style methods use guest-visible paths as well.

## Limits

The interposed Win32 memory API exposes inspection and editing to the Wine-hosted tool. It does
not turn the tool's arbitrary process-control calls into guest execution. Explicit
no-guest-software DLL mapping is provided by `decant-cli guest-inject` through the separate
guest injection domain above. Decant returns a structured error and increments a diagnostics
counter for any operation it cannot perform, and never returns a false success.

| Supported | Unsupported (returns an error) |
|---|---|
| Read and write existing memory | Tool-initiated `VirtualAllocEx` and new guest allocations |
| AOB scan | `CreateRemoteThread` and remote threads |
| Pointer-chain resolution | DLL injection into the target |
| Module and export resolution | `SetWindowsHookEx` |
| In-place byte patching | Calling a guest function |
| Explicit guest DLL injection via `decant-cli guest-inject` (`manual-map` method implemented) | |
| `VirtualProtectEx`/`NtProtectVirtualMemory` (success; reports the page's prior protection) | |
| `VirtualQueryEx`/`NtQueryVirtualMemory` (State/Type/Protect) | |

Notes:

- Hooks are event-driven; Decant polls. It cannot deliver a `SetWindowsHookEx`-style callback.
- A paged-out guest page reads as not-present (a `ReadFailed`, not truncated bytes).
- Freezing a fast-changing or per-frame value is racy by construction. Decant reads and writes guest memory out of band; it cannot install a hook in the guest or perform an atomic read-modify-write across the boundary, so a freeze loop can lose races against the game's own writes. Slow-changing values freeze reliably.
- Cheat Engine and any other tool that resolves the memory APIs at runtime route the same as one that imports them. Such a tool does not import `ReadProcessMemory`; it looks the address up with `GetProcAddress` at runtime, and it lists processes through `NtQuerySystemInformation` rather than toolhelp. The carafe patches `GetProcAddress`'s own import slot, so every runtime lookup of an interposed memory API returns the carafe's hook, and it synthesizes `NtQuerySystemInformation` for the process list, along with `NtOpenProcess`, `NtGetNextProcess`, `Toolhelp32ReadProcessMemory`, and the `NtQueryInformationProcess` image classes. A tool that imports the APIs directly (the bundled `sample-tool`) routes through the import-table patch instead. This is general, not a Cheat-Engine special case; either way the binding stays on public Win32/NT exports. `cargo xtask dynamic` exercises the runtime-resolution path with a tool that resolves every memory API only through `GetProcAddress` and enumerates only through `NtQuerySystemInformation`. What stays unsupported through the hooked tool API is arbitrary guest code execution (see the table above); explicit guest DLL injection goes through `decant-cli guest-inject`.
- The synthetic process handle services the full handle tail: `OpenProcess`, `ReadProcessMemory`, `WriteProcessMemory`, `CloseHandle` and `NtClose`, `DuplicateHandle`, `WaitForSingleObject`/`WaitForSingleObjectEx`/`NtWaitForSingleObject`, `GetHandleInformation`/`SetHandleInformation`, `GetProcessId`, `GetExitCodeProcess`, `GetPriorityClass`, `GetProcessTimes`, `IsWow64Process`, `QueryFullProcessImageName`, `GetProcessImageFileName`, the `NtQueryInformationProcess` basic and image classes, `VirtualQueryEx` and `NtQueryVirtualMemory`, and `VirtualProtectEx` and `NtProtectVirtualMemory`. The protection-change pair returns success and reports the page's prior protection without altering it: memflow writes guest physical memory and is not bound by virtual page protection, so a write to a page the tool sees as read-only lands without a real protection change. `NtQueryInformationProcess(ProcessBasicInformation)` returns the pid with a PEB base of 0, since memflow's generic ABI does not expose it, so guest PEB-walking features are unavailable. The execution and process-control exports (memory allocation, remote threads, `TerminateProcess`, `NtSuspendProcess`/`NtResumeProcess`) refuse.
- `VirtualQueryEx` and `NtQueryVirtualMemory` report `State`, `Type`, and `Protect` derived from the guest page tables and module list: a region overlapping a loaded module reports `MEM_IMAGE`, others `MEM_PRIVATE`. `MEM_MAPPED` is not distinguished, reserved uncommitted memory is not enumerated, and copy-on-write and guard sub-flags are not reported. Default scans over all types are unaffected; a `Type`-filtered or `Protect`-filtered scan may differ from native.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) section 3.

## Version-agnosticism

The carafe binds only to the public Win32/NT export ABI and the PE format (IAT patching plus
`GetProcAddress` hooking), never Wine internals (`__wine_unix_call`, the wineserver protocol,
syscall-dispatch thunks). That
surface is the most stable part of Wine, so the DLL runs on any Wine version without a recompile
tied to Wine's layout.

- Delivery: launcher-driven remote-thread injection (`decant-launcher`). Suspended-create, then `LoadLibrary` via `CreateRemoteThread`, then `DllMain` installs the IAT hooks. The target stays unmodified.
- Alternative delivery: `manual-map` consumes the carafe image bytes and does not register the DLL in the loader module list; the same ready-token verification confirms hook installation.
- Limitation: a tool that issues a raw `syscall` instruction, never calling the named `Nt*` export, bypasses export-level interception. Catching it would need Wine-internal syscall-dispatch hooking, which Decant avoids to keep portability.

See the injection and interception, and version-agnosticism sections of [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Crate layout

Mixed-target Cargo workspace. Host crates are `default-members`; the Windows crates build only
with `--target x86_64-pc-windows-gnu`. x86_64 throughout.

| Path | Target | Role |
|---|---|---|
| `crates/decant-vmi` | host | Library facade: re-exports backends, scanner and resolver, and the client |
| `crates/decant-protocol` | host + win-gnu | Wire contract and shared domain types; `write_msg`/`read_msg` framing |
| `crates/decant-client` | host + win-gnu | Daemon client over decant-protocol |
| `crates/decant-backend` | host | `MemoryBackend` trait, `MockBackend`, `MockGuest` |
| `crates/decant-memflow` | host | `MemflowBackend` (VM, feature-gated) |
| `crates/decant-analysis` | host | AOB scanner and pointer-chain resolver |
| `crates/decant-daemon` | host | TCP server and dispatch (the cellar) |
| `crates/decant-cli` | host | user CLI |
| `crates/decant-wine-harness` | host | launches exes under Wine for `cargo test` |
| `crates/decant-interpose` | win-gnu (cdylib) | interposer DLL (the carafe), IAT patching |
| `crates/decant-inject` | host + win-gnu | injection trait, config, ABI, SDK, and shipped injectors |
| `testbins/guest-target` | win-gnu | sample target for VM tests |
| `testbins/sample-tool` | win-gnu | stand-in tool for harness tests |
| `testbins/decant-launcher` | win-gnu | suspended-create injection harness |
| `testbins/decant-plugin-standard` | win-gnu (cdylib) | example plugin wrapping the standard injector |
| `testbins/decant-external-standard` | win-gnu | example external command wrapping the standard injector |
| `testbins/dll-smoke` | win-gnu | loads `hello-dll`, checks the toolchain under Wine |
| `testbins/hello-dll` | win-gnu (cdylib) | minimal PE32+ DLL exporting `add` |
| `xtask` | host | build and test orchestration |

## Status

Decant reads and writes guest memory, runs AOB scans, resolves pointer chains, and
provides an interposer that redirects an unmodified tool's Win32 calls. The memflow
backend is validated against a Windows 10 guest. Guest injection with the `manual-map` method is
also exercised against that VM through the tracked fixture: the daemon allocates guest memory,
materializes the pages, writes a relocated DLL image from bytes, and calls `DllMain`. The fixture
payload updates its own marker so the test can assert that the payload ran; normal
`guest-inject` does not add a marker or require the target to report success.

The regular test set runs offline with no VM.

## Testing

Two modes behind one trait: a mock backend offline, and memflow against a VM.

```bash
cargo test               # mock mode: protocol, dispatch, scanner/resolver, CLI; no VM
cargo xtask wine-smoke   # cross-compile and load a DLL under Wine
scripts/decant-test.sh inject-test  # standard, plugin, manual-map, thread-hijack, external, timeout
scripts/decant-test.sh guest-fixture  # VM guest injection fixture, needs MEMFLOW_PLUGIN_PATH
cargo test -- --ignored  # VM mode, gated on DECANT_LIVE=1 and a running guest
```

Writes are verified by read-back, not by the return value. Unsupported operations return a
structured error, asserted in tests so they cannot become silent corruption.

The architecture and internals are documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

Dual-licensed under MIT OR Apache-2.0.
