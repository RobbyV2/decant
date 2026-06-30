# Decant Architecture

Decant lets an **unmodified** Windows memory-editing tool run under Wine while its
memory accesses are redirected to a *separate* Windows VM. The tool sees local process
memory; each read and write is serviced by reading the guest VM's physical RAM from
outside via [memflow](https://github.com/memflow/memflow).

---

## 1. Component topology

```
  ┌────────────────────────────────────────────────────────────────┐
  │  Windows guest VM (QEMU/KVM)                                   │
  │    target.exe, the game/process being inspected                │
  │    (runs unmodified)                                           │
  └───────────────▲────────────────────────────────────────────────┘
                  │  physical RAM read out-of-band
                  │  (hypervisor memory introspection)
                  │
  ┌───────────────┴──────────── memflow connector (QEMU/KVM) ──────┐
  │  HOST (Linux), where the hypervisor runs                       │
  │                                                                │
  │   ┌──────────────────────────────┐                             │
  │   │  decant-daemon  "the cellar" │  reads/writes guest memory  │
  │   │  MemoryBackend dispatch      │  via MemflowBackend         │
  │   └──────────────▲───────────────┘                             │
  │                  │  localhost TCP, length-prefixed bincode     │
  │                  │  (decant-protocol Request/Response)         │
  │   ┌──────────────┴───────────────┐                             │
  │   │  Wine process                │                             │
  │   │   target tool (unmodified)   │                             │
  │   │   + decant-interpose.dll     │  "the carafe"               │
  │   │     intercepts Win32/NT      │                             │
  │   │     memory exports, marshals │                             │
  │   │     them to the cellar       │                             │
  │   └──────────────────────────────┘                             │
  └────────────────────────────────────────────────────────────────┘
```

- **The guest**: the Windows VM and its `target.exe`. Decant reads and writes its
  memory from outside, never runs code in it (section 3).
- **The cellar** (`decant-daemon`): a host-side TCP server owning the active
  `MemoryBackend` and dispatching `decant-protocol` requests to it; `--backend mock`
  (default, no VM) or `memflow` (VM).
- **MemflowBackend** (`decant-memflow`): reads guest physical RAM through a QEMU/KVM
  connector, resolving it into virtual-memory reads, process/module enumeration, and
  export tables. A `MemoryBackend` implementor.
- **The carafe** (`decant-interpose`): the DLL loaded into the tool under Wine. It
  intercepts the Win32/NT memory and introspection exports, marshals each to the cellar,
  maintains a synthetic handle table, synthesizes process/module snapshots from daemon
  data, and forwards everything else to the Wine builtin.

---

## 2. The narrow waist

Every Win32/NT memory-introspection call a tool can make (`ReadProcessMemory`,
`WriteProcessMemory`, `NtReadVirtualMemory`, `VirtualQueryEx`,
`CreateToolhelp32Snapshot`, `Module32First/Next`, `EnumProcessModules`,
`GetModuleHandle`, `GetProcAddress`, …) collapses onto the
[`MemoryBackend`](../crates/decant-backend/src/lib.rs) trait:

```rust
fn list_processes(&self) -> Result<Vec<ProcessInfo>>;
fn process_by_pid(&self, pid: Pid) -> Result<ProcessInfo>;
fn process_by_name(&self, name: &str) -> Result<ProcessInfo>;
fn module_list(&self, pid: Pid) -> Result<Vec<ModuleInfo>>;
fn module_by_name(&self, pid: Pid, name: &str) -> Result<ModuleInfo>;
fn module_exports(&self, pid: Pid, module: &str) -> Result<Vec<(String, u64)>>;
fn read(&self, pid: Pid, addr: u64, len: usize) -> Result<Vec<u8>>;
fn write(&self, pid: Pid, addr: u64, data: &[u8]) -> Result<usize>;
fn memory_map(&self, pid: Pid) -> Result<Vec<MemRegion>>;
```

The [`Request`/`Response`](../crates/decant-protocol/src/lib.rs) wire enums mirror these
one-to-one. Translate the nine once and every Win32 API above them is handled; an exotic
toolhelp/psapi combination still bottoms out in read, query, or enumerate. Anything
requiring the guest to execute code does not fit, and is not simulated (section 3).

---

## 3. Host/VM reality

memflow reads the VM's physical RAM from outside the guest, where the hypervisor
exposes it. Two consequences:

1. **memflow runs where the hypervisor runs.** The QEMU/KVM connector reads the QEMU
   process's mapping of guest RAM, so the daemon lives on the host beside the VM while
   the carafe lives in the Wine-hosted tool. They are separate processes bridged only by
   TCP; that split is why a daemon exists.

2. **Unsupported operations.** memflow reads and writes guest memory and enumerates
   processes, modules, and exports, but cannot run guest code: no `VirtualAllocEx`,
   `CreateRemoteThread`, DLL injection into the target, or calling a guest function. A
   request needing guest execution returns `ProtoError::Unsupported { op }`
   (`BackendError::Unsupported` on the backend side) and increments
   `Diagnostics::unsupported_ops`, never a false success. Read, write, scan, and
   pointer-resolve are supported.

The synthetic process handle services the full handle tail. `OpenProcess` mints it; then
`ReadProcessMemory`/`WriteProcessMemory`, `CloseHandle`/`NtClose`, `DuplicateHandle`,
`WaitForSingleObject`/`WaitForSingleObjectEx`/`NtWaitForSingleObject`,
`GetHandleInformation`/`SetHandleInformation`, `GetProcessId`, `GetExitCodeProcess`,
`GetPriorityClass`, `GetProcessTimes`, `IsWow64Process`, `QueryFullProcessImageName`,
`GetProcessImageFileName`, the `NtQueryInformationProcess` basic/wow64/image classes, and
`VirtualQueryEx`/`NtQueryVirtualMemory` all resolve against it.
`NtQueryInformationProcess(ProcessBasicInformation)` returns the pid with a PEB base of 0:
memflow's generic plugin ABI does not expose the PEB, so guest PEB-walking features are
unavailable.

On a synthetic handle, the execution and process-control exports
(`VirtualAllocEx`/`VirtualFreeEx`, `NtAllocateVirtualMemory`/`NtFreeVirtualMemory`,
`CreateRemoteThread`/`CreateRemoteThreadEx`, `NtCreateThreadEx`, `TerminateProcess`,
`NtSuspendProcess`, `NtResumeProcess`) return their documented failure sentinel (null or
`STATUS_NOT_SUPPORTED`), report the refusal to the daemon, and write to the tool's stderr.

`SetWindowsHookEx` and `QueueUserAPC` are forwarded, not intercepted: neither carries a
guest process handle (an event hook targets the local Wine session, an APC a thread
handle Decant never mints), so neither is expressible against the guest. Intercepting
them would only break the tool's local use.

The carafe is injected into the Wine-hosted tool, which is host-side process
manipulation; the no-execution limit is about the *guest VM*, which memflow cannot inject
into.

---

## 4. The mock-backend testability seam

`MemoryBackend` is the single seam all memory access flows through, so the stack above it
runs against a mock guest with no VM. That is
[`MockBackend`](../crates/decant-backend/src/mock.rs), built by `MockGuest`:

```rust
let guest = MockGuest::new()
    .process("target.exe", 1234)
        .module("target.exe", 0x1400000000, 0x80000)
        .export("add", 0x1000)
        .region(0x1400000000, /* r,w,x */ true, true, false)
            .u32_at(0x1400000010, 0xdeadbeef)
            .bytes_at(0x1400000020, &[1, 2, 3, 4])
        .done()
    .build();
let backend = MockBackend::new(guest);
```

The mock implements every method deterministically and round-trips writes (a `write`
then a `read` of the same range returns the new bytes), so the read-back
write-verification strategy works without a VM. This keeps development VM-free:

- `decant-core` (AOB scanner, pointer-chain resolver) runs entirely against a `MockGuest`.
- `decant-daemon` dispatch is tested with the server on a `MockBackend`.
- `decant-cli` and the carafe's marshaling run end-to-end against the mock behind the daemon.

Only `MemflowBackend` needs a VM; it swaps in behind the same trait.

---

## 5. Crate layout

Mixed-target Cargo workspace. Host crates are `default-members`; the Windows-gnu crates
are members built only with `--target x86_64-pc-windows-gnu`.

| Crate | Target | Role |
|---|---|---|
| `crates/decant-protocol` | host + win-gnu | Wire contract + shared domain types; `write_msg`/`read_msg` framing |
| `crates/decant-backend` | host | `MemoryBackend` trait + `MockBackend`/`MockGuest` |
| `crates/decant-memflow` | host | `MemflowBackend` |
| `crates/decant-core` | host | AOB scanner + pointer-chain resolver |
| `crates/decant-client` | host + win-gnu | shared RPC `Client` over `decant-protocol` |
| `crates/decant-daemon` | host | "the cellar", TCP server + dispatch |
| `crates/decant-cli` | host | user CLI |
| `crates/decant` | host | library facade re-exporting backends, scanner/resolver, client |
| `crates/decant-wine-harness` | host | launches exes under Wine for `cargo test` |
| `crates/decant-interpose` | win-gnu (cdylib) | "the carafe" interposer DLL |
| `testbins/hello-dll` | win-gnu (cdylib) | minimal PE32+ DLL exporting `add` |
| `testbins/dll-smoke` | win-gnu (exe) | loads `hello-dll`, proves the toolchain under Wine |
| `testbins/guest-target` | win-gnu | sample target for VM tests |
| `testbins/sample-tool` | win-gnu | stand-in memory tool for harness tests |
| `testbins/decant-launcher` | win-gnu | suspended-create and remote-thread DLL injector |
| `xtask` | host | build/test orchestration |

---

## 6. Shared domain types and the wire protocol

The domain types (`Pid`, `ProcessInfo`, `ModuleInfo`, `MemRegion`) live once in
`decant-protocol`; the `MemoryBackend` trait re-uses them directly (`decant-backend`
re-exports them), so the trait's return types *are* the wire types. A domain-type change
recompiles both ends at once, with no `From`/`Into` marshaling and no drift between
backend and wire. `decant-protocol` stays light (`serde` + `bincode`), compiling
unchanged for the daemon (`x86_64-unknown-linux-gnu`) and the carafe DLL
(`x86_64-pc-windows-gnu`). Backend-internal errors (`BackendError`, a `thiserror` enum)
stay separate from the wire `ProtoError` (a plain `serde` enum), bridged by a single
`From` at the daemon edge.

Carafe and cellar exchange the primitives over **localhost TCP** carrying
**length-prefixed bincode**: a little-endian `u32` byte count then a `bincode`
`Request`/`Response`, via `write_msg`/`read_msg` over any `Read`/`Write`. Wine's Winsock
maps onto host TCP, and the framing tests over an in-memory `Cursor`. The reader caps
each message at `MAX_MSG_LEN` (64 MiB), so a corrupt prefix errors rather than
over-allocating, a truncated stream gives `UnexpectedEof`, and back-to-back messages do
not bleed. bincode is compact and schema-coupled; both ends build from the same
workspace, so cross-version wire stability is not needed. The daemon binds loopback only.

---

## 7. Workspace and target model

A handful of crates compile only for `x86_64-pc-windows-gnu` (the interposer `cdylib`
and the Windows testbins that run under Wine or in the guest); the rest are host code.
`members` lists all crates, `default-members` lists host crates only, so a bare
`cargo build`/`test` touches the host set and needs no mingw toolchain. The Windows
crates build explicitly with `cargo build -p <crate> --target x86_64-pc-windows-gnu`
(via `xtask`), sharing one `Cargo.lock` and `target/`. `decant-protocol` and
`decant-client` build for both worlds, linking the same wire contract and RPC client into
the daemon and the DLL.

Everything targets **x86_64** (guest, Wine prefix, DLL, testbins); no `i686`. This gives
one calling convention for every intercepted and forwarded export and undecorated export
names (`add`, not `_add@8`), and avoids a second WoW64 memory layout. 32-bit-only tools
are out of scope.

---

## 8. The memflow backend

`MemflowBackend` (`crates/decant-memflow/src/backend.rs`) implements `MemoryBackend` over
a memflow connector:

| `MemoryBackend` | memflow call |
|---|---|
| `list_processes` | `os.process_info_list()` → `{Pid(i.pid), i.name.to_string()}` |
| `process_by_pid` / `_name` | `os.process_info_by_pid(u32)` / `process_info_by_name(&str)` |
| `module_list` | `proc.module_list()` → `{name, base.to_umem(), size}` |
| `module_by_name` | `proc.module_by_name(&str)` |
| `module_exports` | `proc.module_export_list(&minfo)` → `(name, base + offset)` (RVA→VA) |
| `read` | `proc.read_raw(Address::from(addr), len)` |
| `write` | `proc.write_raw(Address::from(addr), data)` |
| `memory_map` | `proc.mapped_mem_vec(-1)` → `CTup3<Address, umem, PageType>`; `w = PageType::WRITEABLE`, `x = !PageType::NOEXEC` |

`read_raw`/`write_raw` return a `PartialResult`; a paged-out guest page yields a partial
error, surfaced as a hard `ReadFailed`/`WriteFailed` rather than silently-truncated bytes.
`memory_map` permission flags are coarse (page-table derived, not full Win32 `PAGE_*`).
`Pid` is `u32`.

The connector and OS layer are **runtime plugins**, not linked. `Inventory::scan()`
discovers the `qemu`/`kvm` connector `.so` and the `win32` `.os` plugin;
`inventory.builder().connector(<name>).args(<ConnectorArgs>).os("win32").build()` yields
an `OsInstanceArcBox<'static>`. The only dependency is
`memflow = { version = "0.2", features = ["plugins"], optional = true }`, no compile-time
`memflow-win32`. So `decant-memflow` compiles with no VM, and `connect()` succeeds only on
the host where the plugins are installed.

Operational facts for running against a guest:

- Two connectors read the same guest. The `qemu` connector (default) reads the qemu
  process directly through ptrace; it needs `CAP_SYS_PTRACE` on the daemon (or root), no
  kernel module, and takes the VM name as its arg (`DECANT_CONNECTOR_ARGS=<name>`, or empty
  to auto-detect a single VM). The `kvm` connector reads through the `memflow.ko` kernel
  module for lower overhead; it needs root and takes the qemu process PID as its arg. Both
  pass the arg as memflow's **default (unnamed) arg**; a `pid=` *named* arg fails
  `Error(Connector, ArgValidation)`.
- The plugin ABI is the integer `MEMFLOW_PLUGIN_VERSION` (`=1`), not the crate version, so
  a `memflow` 0.2.4 core loads 0.2.1 plugins.
- `MEMFLOW_PLUGIN_PATH` must point at the directory holding the
  `libmemflow_{qemu,kvm,win32}.so` plugins. The daemon resolves the backend before binding
  the socket, so a connector failure exits with a message instead of a partial server.
- Writes should target stable memory (zero padding); a hot heap slot can be reclaimed or
  rewritten by the guest between operations.

memflow handles take `&mut self` and are not `Sync`, while `MemoryBackend` is `&self` +
`Send + Sync`, so the OS handle sits behind a `Mutex`. The backend caches the resolved
process per pid (an owned `os.clone().into_process_by_pid`, refreshed on pid change)
rather than re-resolving every read and rebuilding the address translation; the daemon
sets `TCP_NODELAY` on accepted connections. Together these keep a multi-region scan
interactive.

Install the plugins on the VM host (x86_64 Linux):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.memflow.io | sh   # memflowup
memflowup install memflow-qemu memflow-win32     # (+ memflow-kvm for KVM)
```

The QEMU connector reads the qemu process via procfs and needs `CAP_SYS_PTRACE`
(`sudo setcap 'CAP_SYS_PTRACE=ep' <daemon>`, or run as root); KVM needs the `memflow.ko`
module (DKMS) plus a `memflow` group/udev rule.

---

## 9. Injection and interception

The carafe must load into an unmodified tool under Wine and take over the relevant memory
exports, binding only to public exports and the PE format (section 11).

**Delivery: launcher-driven remote-thread injection.** `testbins/decant-launcher` does
`CreateProcessW(target, CREATE_SUSPENDED)` → `VirtualAllocEx`+`WriteProcessMemory` (the
DLL path) → `CreateRemoteThread` at `kernel32!LoadLibraryA` → wait → `ResumeThread`. The
carafe's `DllMain` (`DLL_PROCESS_ATTACH`) self-installs its hooks, so the target stays
unmodified. This is the `wine-env/run.sh <tool>` entry point.

**Interception: Import Address Table (IAT) patching.** The carafe walks a loaded module's
PE import directory (DOS header → NT headers → data-directory entry 1 →
`IMAGE_IMPORT_DESCRIPTOR` array → INT/IAT thunk pairs) and, for each import matching a
target name (e.g. `kernel32.dll!ReadProcessMemory`), overwrites the 8-byte IAT slot with a
pointer to the carafe's replacement, guarded by `VirtualProtect(PAGE_READWRITE)` and
restored afterward. It patches the main exe via `GetModuleHandleW(NULL)` and every other
loaded module via `psapi!EnumProcessModules`. Only the named slots are redirected; every
other import still points at the Wine builtin, so unimplemented exports forward with no
proxy DLL or export table to maintain. No code bytes are touched, only a pointer table the
loader already built.

**Runtime resolution.** IAT patching only catches exports a tool resolved at load time.
Tools that resolve the memory APIs at runtime through `GetProcAddress`, or enumerate
processes through `NtQuerySystemInformation` (Cheat Engine among them), would bypass the
patched slots. The carafe widens the surface, still binding only to public exports:

- **`GetProcAddress` redirector.** `GetProcAddress` is patched like any other export. The
  hook returns the carafe's replacement for any name it interposes and forwards every
  other name (and all ordinal lookups) to the original `GetProcAddress`. The export-name
  set the IAT installer patches and the set the redirector recognizes come from one macro
  list (`interpose_exports!`), so they cannot drift.
- **`NtQuerySystemInformation` synthesis.** For `SystemProcessInformation`, the carafe
  builds the `SYSTEM_PROCESS_INFORMATION` list from the daemon's process list, writing
  only the documented, x64-stable field subset (`NextEntryOffset`, `UniqueProcessId`,
  `ImageName`) and honoring the two-call `STATUS_INFO_LENGTH_MISMATCH` size negotiation.
  Other classes forward.
- **Alternate paths.** `NtOpenProcess`, `NtGetNextProcess`, `Toolhelp32ReadProcessMemory`,
  and the `NtQueryInformationProcess` image classes are served the same way.

`NtQueryInformationProcess(ProcessBasicInformation)` returns the requested
`PROCESS_BASIC_INFORMATION` with the pid filled in and a PEB base of 0: memflow's generic
plugin ABI does not expose the PEB, so a guest PEB walk is unavailable, and the module
discovery it would do is already served by the module hooks.

**Region walk.** A scanner queries `VirtualQueryEx`/`NtQueryVirtualMemory` upward from a
low address. The hooks return committed regions from the daemon's memory map and span the
gaps as `MEM_FREE`, so the walk advances past them instead of stalling at address 0. Each
region reports `State`, `Type`, and `Protect` derived from the guest page tables and
module list: a region overlapping a loaded module reports `MEM_IMAGE`, others
`MEM_PRIVATE`. `MEM_MAPPED` is not distinguished, reserved uncommitted memory is not
enumerated, and copy-on-write and guard sub-flags are not reported, so a default scan over
all types is unaffected while a `Type`- or `Protect`-filtered scan may differ from native.
The map is cached per pid for the walk to avoid a round trip per query. A scan then reads
each region through the marshaled `ReadProcessMemory` in one request per caller read,
passing the requested size through rather than paging slot by slot.

**Alternatives that do not apply on Wine.** `AppInit_DLLs` does not load the DLL:
`kernelbase!LoadAppInitDlls` is a no-op stub on Wine (its body is `test [dbg_flag],8` /
`ret`), and nothing invokes it during process init. A `WINEDLLOVERRIDES` proxy must
re-export the *entire* shadowed surface and only works for an incidental import
(DXVK/ReShade style), not the early/KnownDLL-class `kernel32`/`ntdll` loads a memory tool
depends on. Inline-hooking the `Nt*` prologues would tie the carafe to a specific Wine
build (section 11). Remote-thread injection plus IAT patching is the one mechanism that
interposes an unmodified tool on stock Wine using public exports and the PE format only.

---

## 10. Library facade and shared client

Decant is usable three ways: embed a backend in-process (as memflow is used), connect a
`Client` to a running daemon, or drive the CLI. `decant-client` holds `Client` (lazy
connect, reconnect-once, typed methods); depending only on `decant-protocol` and
`thiserror`, it builds for host and windows-gnu and is shared by the CLI, the interposer's
`rpc` module, and library users. The `decant` crate re-exports the backend trait,
`MockBackend`/`MockGuest`, the scanner and resolver, `MemflowBackend` (behind the
`memflow` feature), and `Client` behind a `prelude`. The CLI adds `--json`.

---

## 11. Version-agnosticism

The carafe binds to one boundary: the **public Win32/NT export ABI**, the named functions
a Windows DLL exports (`kernel32`, `ntdll`, `psapi`, …) with their documented signatures.
Every Windows program depends on it, so Wine keeps it stable across releases. The carafe
intercepts a handful of memory and introspection exports (`ReadProcessMemory`,
`WriteProcessMemory`, `NtReadVirtualMemory`, `VirtualQueryEx`, toolhelp/psapi enumeration,
`GetModuleHandle`/`GetProcAddress`, …) and forwards the rest to the Wine builtin, so a new
Wine version needs no recompile. The x86_64-only target reinforces this with one calling
convention and undecorated names.

### Forbidden Wine internals

Unstable Wine implementation details the carafe never binds to:

- **`__wine_unix_call` / the unixlib (PE↔Unix) boundary.** Wine's private path for a
  builtin's PE side to call its `.so` Unix side; its indices, struct layouts, and ABI are
  version-specific.
- **The wineserver IPC protocol.** A private request/reply format that changes with the
  server. Decant gets process/module facts from memflow, not wineserver.
- **Internal cross-DLL import paths.** Reaching a builtin's non-exported helper. Only
  public exports may be called.
- **Syscall-dispatch thunks / the internal syscall table.** Wine's private `Nt*`→Unix
  dispatch is an internal detail; Decant interposes at the named-export level.

### Version dependence and a coverage limitation

The shipped interposition (IAT patching plus the `GetProcAddress` redirector) works
unchanged across Wine versions. Only inline-hooking the `Nt*` prologues would not:
overwriting `ntdll`'s exported `Nt*` stubs depends on byte layout that can shift between
Wine builds, needing per-version revalidation. The shipped path patches no prologues.

A call by name is covered whether resolved at load time (IAT patch) or at runtime through
`GetProcAddress` (section 9). A **raw syscall**, with the syscall number in a register and
`syscall`/`int 2e` executed directly, never goes through a named export, so the carafe
cannot see it; catching it would need syscall-dispatch hooking, the Wine-internal
territory above. Such a call still cannot escape the guest-execution limit (section 3);
this is about interception visibility, not power over the guest.
