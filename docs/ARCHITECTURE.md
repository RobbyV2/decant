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

- **The guest**: the Windows VM and its `target.exe`. The interposed tool API reads
  and writes its memory from outside. Explicit guest injection is a separate domain
  where the daemon maps DLL bytes and invokes the payload through a configured guest
  execution method (section 3).
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
toolhelp/psapi combination still bottoms out in read, query, or enumerate. Anything requiring
arbitrary tool-initiated guest execution does not fit this interface and is not simulated
(section 3). Guest DLL mapping uses the separate guest injection request type.

---

## 3. Host/VM reality

memflow reads the VM's physical RAM from outside the guest, where the hypervisor
exposes it. Two consequences:

1. **memflow runs where the hypervisor runs.** The QEMU/KVM connector reads the QEMU
   process's mapping of guest RAM, so the daemon lives on the host beside the VM while
   the carafe lives in the Wine-hosted tool. They are separate processes bridged only by
   TCP; that split is why a daemon exists.

2. **Tool API unsupported operations.** The Wine-hosted tool sees a synthetic process handle.
   Through that handle, Decant exposes guest read/write, scan, module/export lookup, and
   pointer resolution. It does not translate arbitrary tool-initiated process-control calls into
   guest execution: `VirtualAllocEx`, `CreateRemoteThread`, DLL injection, and direct guest
   function calls return `ProtoError::Unsupported { op }` (`BackendError::Unsupported` on the
   backend side) and increment `Diagnostics::unsupported_ops`, never a false success. Explicit
   no-guest-software DLL injection is a separate `decant-cli guest-inject` path with its own
   method/capability contract; it is not exposed through the synthetic handle. The implemented
   guest method maps DLL bytes and invokes the payload through an IAT-hook call in the selected
   target.

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
manipulation. Guest DLL injection is only performed by the explicit guest injection domain,
where the daemon accepts a DLL byte image and applies the guest mapper/execution policy.

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

- `decant-analysis` (AOB scanner, pointer-chain resolver) runs entirely against a `MockGuest`.
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
| `crates/decant-analysis` | host | AOB scanner + pointer-chain resolver |
| `crates/decant-client` | host + win-gnu | shared RPC `Client` over `decant-protocol` |
| `crates/decant-daemon` | host | "the cellar", TCP server + dispatch |
| `crates/decant-cli` | host | user CLI |
| `crates/decant-vmi` | host | library facade re-exporting backends, scanner/resolver, client |
| `crates/decant-wine-harness` | host | launches exes under Wine for `cargo test` |
| `crates/decant-interpose` | win-gnu (cdylib) | "the carafe" interposer DLL |
| `testbins/hello-dll` | win-gnu (cdylib) | minimal PE32+ DLL exporting `add` |
| `testbins/dll-smoke` | win-gnu (exe) | loads `hello-dll`, proves the toolchain under Wine |
| `testbins/guest-target` | win-gnu | sample target for VM tests |
| `testbins/sample-tool` | win-gnu | stand-in memory tool for harness tests |
| `testbins/decant-launcher` | win-gnu | suspended-create injection harness |
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
- These arg shapes are not interchangeable. For qemu, run with a VM name:
  `DECANT_CONNECTOR_ARGS=<vm-name> decant-daemon --backend memflow --connector qemu`.
  For kvm, run with the qemu PID:
  `DECANT_CONNECTOR_ARGS=$(pgrep -f 'guest=<vm-name>') sudo -E decant-daemon --backend memflow --connector kvm`.
  If qemu finds the qemu process and memory map but memflow-win32 then fails with
  `unable to find dtb`, the daemon exits before binding its TCP port. That is a connector
  and Windows-OS-layer startup failure, not a target-process failure. KVM may still work
  on the same guest, or the operator can provide memflow-win32 hints through
  `DECANT_OS_ARGS=':arch=x64,dtb=<hex-dtb-without-0x>,kernel_hint=<hex-va-without-0x>'`.
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
interactive. If a write fails after guest-side allocation, the backend clears that cached
process view and retries; large writes fall back to page-sized chunks so newly materialized
pages are addressed through fresh translation state.

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

**Protection changes.** A tool that edits a page it sees as read-only typically calls
`VirtualProtectEx` (or `NtProtectVirtualMemory`) to grant write access, writes, then
restores the prior protection. The carafe services both for a synthetic handle: it returns
success and reports the page's current protection from the region map as the prior value,
without changing anything. No change is needed because the write is marshaled to the daemon
and applied by memflow to guest physical memory, which translates the address through the
page tables and writes the underlying physical page directly; the guest's virtual page
protection does not gate it. So a write to a read-only page lands whether or not the
protection call succeeds. For a real handle both forward to the original export.

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

## 12. Pluggable injection and method-agnostic verification

Section 9 fixes one delivery mechanism into the tool. Injection is now a capability behind a
single trait, so a user can pick a shipped method by config or supply their own against a
stable boundary. The harness and its verification contract are the durable interface; injectors
are implementations of that interface.

An `Injector` performs only the load: `inject(&InjectionRequest) -> Result<LoadInfo,
InjectError>`. The harness owns spawning the target suspended and resuming it; an injector
never resumes. The request carries both a `carafe_path`, for loader-based methods that hand a
path to `LoadLibrary`, and the raw `carafe_image` bytes, for manual-map methods that
reimplement the loader, so one request type serves both method classes. Every method reports a
`Portability` tier: `PublicExportsOnly` (the `standard` method, upholding the section 11
guarantee), `LoaderInternals` (manual map), or `PrologueBytes` (thread hijack or inline). The
tier is logged at startup, and any method below `PublicExportsOnly` prints a notice that the
run opts out of the cross-version portability guarantee.

Load is confirmed by the carafe signaling a named sync primitive, the `ReadyToken`, from
`DllMain` after its hooks are installed, never by enumerating the target's module list. A
manual-mapped image is deliberately absent from the loader module list, so external
enumeration confirms `LoadLibrary` and silently fails for manual map. The harness creates the
token before injection, passes its name in, waits with a timeout, and resumes the main thread
only on success; timeout or signal failure kills the target and exits non-zero. This makes
verification identical for `LoadLibrary`, manual map, thread hijack, or APC: if the carafe is
alive and hooking, it reports. Waiting on the token stays in the harness, so a plugin cannot
report "hooks installed" on its own.

Pre-made injectors are selected by config: `[injection] method = "standard" | "manual-map" |
"thread-hijack" | "plugin" | "external"` with `timeout_ms`. The standard method is the current
`LoadLibraryA` remote-thread path. The manual-map method consumes `carafe_image`, maps a PE32+
image into the suspended tool process, applies base relocations, resolves imports, runs TLS
callbacks, protects sections, and calls the DLL entry point. Because that image is not registered
with the Wine loader, the ready-token signal is the only success criterion.

The thread-hijack method rewrites the suspended main thread's instruction pointer to a small
loader stub. The harness resumes the thread into that stub, waits for the carafe's ready signal,
then sets a release event; only then does the stub restore the saved register state and jump to
the original instruction pointer. This method reports `PrologueBytes` portability because it
lands on injected code bytes, even though it still uses public exports for the loader calls.

Bring-your-own is a `PluginInjector` that loads a user cdylib exporting `decant_inject` against a
versioned `#[repr(C)]` ABI (`DECANT_INJECT_ABI`); the host resolves the export, checks the ABI
version, marshals the request, and maps the result back. The plugin returns once the carafe's
`DllMain` is reached; the harness still owns the ready-token wait.

Injection primitives act on a Windows process handle inside a wineserver prefix, so a
bring-your-own injector cannot be an arbitrary Linux program; it must run PE-side, in the same
prefix, to share the handle namespace. This stays agnostic in the way that matters: any
toolchain targeting Windows, or any existing Windows injector, qualifies. `PluginInjector`
error messages state this constraint directly.

A fourth method, `external`, hands the load to a user-configured command that runs out of
process. The harness spawns the command and writes one length-prefixed frame to its stdin:
the target PID, the carafe path, the carafe image bytes, and the ready-token name. The command
reopens the target itself with `OpenProcess(pid)` and performs the load, using the path for a
loader-based load or the bytes for a manual map. A PID crosses the process boundary where a
handle would not, since a handle is valid only inside the harness that created it. The command
runs PE-side in the same prefix for the handle-namespace reason above, reports `PrologueBytes`
portability because its mechanism is opaque to the harness, and is verified by the same
ready-token wait: the harness resumes only after the carafe signals, whatever the command did.
The shipped `decant-external-standard` reads this frame and delegates to the standard load.

Configuration selects the method and carries the two boundaries' parameters. The launcher reads
a TOML file named by `DECANT_CONFIG`; an absent file is the standard defaults, a malformed one
is an error.

```toml
[injection]
method = "standard"        # standard | manual-map | thread-hijack | plugin | external
timeout_ms = 5000          # ready-token wait before the harness kills the target
plugin_path = "my_injector.dll"          # required for method = "plugin"
external_command = ["my_inject.exe", "--flag"]   # required for method = "external"
```

No-guest-software DLL mapping uses the same config model with `domain = "guest"`. The guest
target can be a concrete `pid`, or a `process` name plus `process_pattern`; the optional pattern
is a generic hex signature with `?`/`??` wildcards and is resolved by the daemon immediately
before injection.

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
dependency_policy = "require-loaded"
tls = "callbacks-only"
final_protections = "section"
loader_metadata = "reject-unsupported" # reject-unsupported | best-effort | allow-unsupported
call_stack = "native"                  # native | registered-unwind
permission_transitions = "standard"    # standard | write-through-final
thread_starts = "existing-thread"      # existing-thread | require-module-backed
image_backing = "private"              # private | sec-image
vad_spoof = "off"                      # off | vad-image-map
hook_module = "kernel32.dll"
hook_function = "Sleep"

[guest.execution]
method = "iat-hook"
timeout_ms = 10000
```

The memflow guest injection backend handles PE32+ x64 images, DIR64 relocations, ordinary and
delay imports, ordinal imports, API-set fallbacks, forwarded exports for modules already loaded
in the target, loader-driven dependency loads through the target's `LoadLibraryA` and
`GetProcAddress`, and section-derived final page protections. With the default
`final_protections = "section"` path, it allocates RW memory, writes the image, applies
PE-derived permissions, then calls TLS callbacks and `DllMain`; `rwx` remains an explicit
compatibility mode. `loader_metadata = "best-effort"` registers x64 unwind metadata through guest
`RtlAddFunctionTable` and seeds the load-config security cookie when the mapped image exposes the
default cookie slot. It does not synthesize loader-private VAD/section-object state, full LDR
ownership, or per-thread TLS template propagation. When
`loader_entries = "synthesized"`, Decant allocates a static TLS slot via `TlsAlloc`,
patches the index into the image buffer, copies the TLS template, and calls
`TlsSetValue` for the current helper/target thread. That does not propagate the
template to other existing threads, and `remote-thread` DllMain runs on a new
thread that does not inherit this value. For payloads with load-config metadata,
`loader_metadata = "best-effort"` and `loader_entries = "synthesized"` also request
a CFG valid-call-target mark for the entry point and exported function RVAs via
`SetProcessValidCallTargets`. Broader CFG/load-config metadata is still not synthesized.
`call_stack = "registered-unwind"` registers x64 unwind metadata for the IAT-hook stub and uses a
single framed stack allocation so stack walking can unwind through the stub; it does not, by
itself, spoof caller frames or shape the stack to impersonate another call path.
`permission_transitions = "write-through-final"` allocates with final-ish image permissions,
materializes demand-zero pages by read-touch when possible, writes through memflow, and skips
final protection calls whose target protection already matches the allocation protection. It
checks critical writes by reading them back; the allocation/write/protect sequence is still
observable. `thread_starts = "require-module-backed"` keeps the
IAT-hook path on an existing target thread and verifies that the IAT slot, original import target,
and staging cave are inside loaded module ranges; it verifies module-backed hook plumbing but does
not inspect payload entrypoints or helper calls. For `remote-thread`, `require-module-backed`
requires a payload-image executable code cave for the ThreadProc thunk and refuses to fall back to
a temporary thread start.
`image_backing = "sec-image"` stages the payload as a guest temp file and maps it through
`CreateFileMappingW(SEC_IMAGE)` + `MapViewOfFile(FILE_MAP_COPY)`, so the
executable region starts as a real kernel-created image-file section rather than private
committed memory; Decant then applies relocations, imports, delay imports, the load-config
security cookie, TLS callbacks, and `DllMain` on top of that view. The section object and
image-file VAD backing are produced by the NT memory manager through public guest exports, not
forged. Pages Decant patches
(imports, security cookie, IAT) become copy-on-write private pages, while unpatched pages remain
file-backed, so the section object is real but the modified view is not identical to the on-disk
image. `sec-image` requires
`allocation = "virtual-alloc"` for helper buffers and `final_protections = "section"`, because an
image-file-backed mapping uses PE-derived page protections rather than a single RWX region. The
default `iat-hook` execution path snapshots the configured IAT slot plus stage/result bytes,
patches them, lets one target thread run the requested function, reads the return value, and
restores on success, timeout, or error. The result block is temporary call scratch for this path,
not a payload success marker. The guest stub does not write the IAT slot from inside the target;
the host transaction owns restoration because it can write through page protections via memflow.
For `VirtualAlloc` mappings, Decant then executes a second IAT-hook call that writes one byte per
allocated page, materializing demand-zero pages before the host writes the mapped image. This path
is import-triggered: execution occurs when the target calls the configured import. The
`remote-thread` execution path still uses the IAT-hook trampoline to call public exports, but
creates the guest thread by calling `CreateThread` from inside the target process. The new thread
starts at a `ThreadProc` thunk, and that thunk calls
`DllMain(hinst, DLL_PROCESS_ATTACH, NULL)` with the proper x64 calling convention. When the
payload image has a large enough executable code cave, the thunk is placed there so the recorded
thread start is inside the mapped image; otherwise a temporary helper allocation is used.
`thread_starts = "require-module-backed"` makes the payload-image placement mandatory.
The thunk writes DllMain's return value and a completion marker into scratch memory, which the
host polls through the backend; it does not need a second target import call to wait for the new
thread. Remote-thread launch helper calls use native stack handling even when
`stack_shaping = "spoofed"` is selected.
Operators should provide `stage_pattern` or `stage_base` for executable stub bytes
plus `result_pattern` or `result_base` for a writable scratch slot; without them, auto-selection
is limited to memory that passes those separate permission checks. The strict
`loader_metadata = "reject-unsupported"`
default fails payloads that require static TLS slots, unwind registration, or load-config
processing; `best-effort` registers the public runtime metadata Decant can safely express
(including static TLS slot allocation when `loader_entries = "synthesized"`), and
`allow-unsupported` skips the guards only for payloads that do not rely on the corresponding
loader registration. The schema parses `thread-hijack`, `apc`, package/session
selectors, and static TLS registration, but this backend returns unsupported errors for them until
the needed thread/context, APC, or TLS support exists.

The mapper reports, but does not hide or synthesize away, manual-map artifacts. Successful
`GuestLoadInfo.notes` include `artifact audit:` entries covering private or SEC_IMAGE-backed image
memory, loader/module metadata state, PE metadata handled by Decant
instead of `LdrLoadDll`, section-derived versus explicit-RWX permissions, loader metadata status
for TLS/unwind/load-config records, call-stack policy, permission-transition policy,
thread-start policy, image-backing policy, and the selected execution path. When requested,
Decant can synthesize partial, transient PEB loader-list entries; it does not create VADs or
section objects. With `image_backing = "sec-image"` the section object and image-file VAD backing
are real kernel-created state produced through public guest exports, not forged. `stack_shaping =
"spoofed"` is limited to writing a synthetic return address for selected helper/payload calls; it
does not synthesize a full caller chain or normalize arbitrary stacks. Decant does not hide all
allocation/write/protect observability. It does not synthesize or rewrite kernel thread-start
metadata. `vad_spoof = "vad-image-map"` is parsed as an explicit experimental request, but the
memflow backend currently returns unsupported rather than mutating undocumented Windows VAD
fields. The supported way to obtain real image-file VAD backing is `image_backing = "sec-image"`,
which asks the guest memory manager to create that state.

The tracked guest fixture lives in `testbins/guest-inject-fixture/native/`. `xtask
guest-inject-fixture` builds a CRT-free target EXE with separate executable stub bytes and a
writable result block, plus a payload DLL that contains a real DIR64 relocation. The xtask fails
if that relocation disappears, because fallback-base manual mapping must exercise relocation
application. `scripts/decant-test.sh guest-fixture` builds the same artifacts, starts or reuses a
memflow daemon, locates the target by its fixture marker, injects the payload bytes, and checks
the fixture payload's marker update as a test assertion. Normal guest injection does not add a
marker or depend on the target reporting success.

Fate-style UWP support maps to access and selection policy rather than a distinct mapper:
loader-based PE-side methods must grant the AppContainer SID (for example `S-1-15-2-1`) read and
execute access to a path-loaded DLL before `LoadLibraryW` can open it. Private guest byte
manual-map does not require a guest-visible DLL path; `image_backing = "sec-image"` stages a
temporary guest file to obtain a real image section, and loader-style methods use guest-visible
paths as well.

The cdylib boundary is a versioned C ABI. A plugin exports `decant_inject_abi() -> u32`
returning `DECANT_INJECT_ABI` and `decant_inject(*mut DecantInjectRequest) -> i32` (0 on
success); the host resolves both, rejects a version mismatch or a missing export with a clear
error, marshals the request, and reads back `out_remote_base`. The ABI constant is bumped on any
layout change to `DecantInjectRequest`. The external boundary is the stdin frame above, so a
bring-your-own external command needs no linkage against Decant, only agreement on the frame.
Both boundaries share the same PE-side constraint: an injector acts on a process handle inside a
wineserver prefix, so it must run as a Windows image in that prefix, not as an arbitrary Linux
program. Any toolchain targeting Windows qualifies.

The Windows-only `decant_inject::sdk` module exposes the public-export primitives used by the
shipped methods: remote allocation, read, write, protection changes, remote thread start and wait,
remote `LoadLibraryA`, remote `GetProcAddress`, and a small remote-call helper. Plugin authors can
compose APC or thread-control methods against this surface without binding to Wine internals.
