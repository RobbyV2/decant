# Decant Architecture

Decant lets an **unmodified** Windows memory-editing tool run under Wine while its
memory accesses are transparently redirected to a *separate* Windows VM. The tool
believes it is poking at local process memory; in reality every read/write is
serviced by reading the guest VM's physical RAM from the outside via
[memflow](https://github.com/memflow/memflow).

This document describes the component topology, the "narrow waist" that makes the
design tractable, the host/VM physical reality that constrains the design, and
the mock-backend seam that keeps ~90% of the system testable with no VM at all.
It then records the architecturally significant decisions and the
version-agnosticism rules that bound the carafe to Wine's stable surface.

---

## 1. Component topology

```
  ┌────────────────────────────────────────────────────────────────┐
  │  Windows guest VM (QEMU/KVM)                                     │
  │    target.exe, the game/process being inspected                 │
  │    (runs real, unmodified)                                      │
  └───────────────▲────────────────────────────────────────────────┘
                  │  physical RAM read out-of-band
                  │  (hypervisor memory introspection)
                  │
  ┌───────────────┴──────────── memflow connector (QEMU/KVM) ───────┐
  │  HOST (Linux), where the hypervisor runs                        │
  │                                                                 │
  │   ┌──────────────────────────────┐                             │
  │   │  decant-daemon  "the cellar" │  reads/writes guest memory  │
  │   │  MemoryBackend dispatch      │  via MemflowBackend          │
  │   └──────────────▲───────────────┘                             │
  │                  │  localhost TCP, length-prefixed bincode      │
  │                  │  (decant-protocol Request/Response)          │
  │   ┌──────────────┴───────────────┐                             │
  │   │  Wine process                │                             │
  │   │   target tool (unmodified)   │                             │
  │   │   + decant-interpose.dll     │  "the carafe"               │
  │   │     intercepts Win32/NT      │                             │
  │   │     memory exports, marshals │                             │
  │   │     them to the cellar       │                             │
  │   └──────────────────────────────┘                             │
  └─────────────────────────────────────────────────────────────────┘
```

Named pieces (the wine metaphor is load-bearing in the code comments):

- **The guest**: the real Windows VM and the `target.exe` inside it. Decant never
  runs code in here; it only reads/writes its memory from outside (see section 3).
- **The cellar** (`decant-daemon`): a Linux-side TCP server. It owns the active
  `MemoryBackend` and dispatches `decant-protocol` requests to it. Chosen at
  startup: `--backend mock` (default, no VM) or `--backend memflow` (VM).
- **memflow + MemflowBackend** (`decant-memflow`): the memflow backend. Reads guest
  *physical* RAM through a QEMU/KVM connector and resolves it into virtual-memory
  reads, process/module enumeration, and export tables. A drop-in implementor of
  the `MemoryBackend` trait.
- **The carafe** (`decant-interpose`): the Windows DLL loaded into the unmodified
  tool under Wine. It implements the handful of Win32/NT memory + introspection
  exports the tool calls, marshals each to the cellar over `decant-protocol`,
  maintains a synthetic handle table, synthesizes process/module snapshots from
  daemon data, and forwards everything else to the real Wine builtin.

---

## 2. The narrow waist (the few primitives everything funnels into)

The entire Win32/NT memory-introspection surface a cheat tool can call
(`ReadProcessMemory`, `WriteProcessMemory`, `NtReadVirtualMemory`,
`VirtualQueryEx`, `CreateToolhelp32Snapshot`, `Module32First/Next`,
`EnumProcessModules`, `GetModuleHandle`, `GetProcAddress`, …) collapses onto a
*small* set of capability primitives. That set is the
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

These nine primitives are mirrored almost one-to-one by the
[`Request`/`Response`](../crates/decant-protocol/src/lib.rs) wire enums. This is
the design's central leverage: **translate these primitives once, and every Win32
API above them is handled too.** A new tool that calls some exotic
toolhelp/psapi combination still bottoms out in read/query/enumerate.

What does *not* fit through the waist is anything that requires the guest to
*execute code*. The design does not simulate it (see section 3, unsupported operations).

---

## 3. Host/VM reality (the physical constraint that shapes everything)

memflow performs **memory introspection from outside the guest**. It reads the
VM's physical RAM where the hypervisor exposes it. Two consequences drive the
architecture:

1. **memflow must run where the hypervisor runs.** The QEMU/KVM connector reads
   the QEMU process's mapping of guest RAM. Therefore the daemon ("the cellar")
   lives on the **host**, beside the VM, not inside the Wine process and not
   inside the guest. The carafe DLL, by contrast, lives inside the Wine-hosted
   tool. They are different machines-of-execution bridged only by the TCP
   protocol. This split is *why* there is a daemon at all.

2. **Unsupported operations.** memflow can read and write guest memory, enumerate
   processes/modules, and resolve exports. It **cannot run guest code**: no
   `VirtualAllocEx` of new guest pages backed by the guest allocator, no
   `CreateRemoteThread`, no DLL injection into the *target*, no calling a guest
   function. Any tool request that needs guest execution is unsupported. Decant
   surfaces this rather than silently corrupting state:
   `ProtoError::Unsupported { op }` / `BackendError::Unsupported { op }`, and
   `Diagnostics::unsupported_ops` counts how often a tool hit it. **Never
   synthesize an allocation or a thread.** Read, write, scan, and pointer-resolve
   are fully supported; anything beyond these limits fails clearly.

The carafe intercepts the execution-export surface that carries a guest process
handle and refuses it clearly rather than reporting a false success:
`VirtualAllocEx`/`VirtualFreeEx`, `NtAllocateVirtualMemory`/`NtFreeVirtualMemory`,
`CreateRemoteThread`/`CreateRemoteThreadEx`, and `NtCreateThreadEx` return their
documented failure sentinel (null or `STATUS_NOT_SUPPORTED`) when the handle is
synthetic, report the refusal to the daemon (incrementing
`Diagnostics::unsupported_ops`), and write a message to the tool's stderr.

`SetWindowsHookEx` and `QueueUserAPC` are deliberately left forwarded. Neither
carries a guest process handle: an event hook targets the local Wine session and
an APC targets a thread handle Decant never mints, so installing an event hook or
queueing an APC against the guest is not expressible through the handle model and
is not attempted. Intercepting them would only break the tool's own legitimate use.

(Note the layering distinction: the carafe DLL *is* injected into the Wine-hosted
tool, which is host-side Wine process manipulation. The
unsupported-operation limit is specifically about the *guest VM*, which memflow
cannot inject into.)

---

## 4. The mock-backend testability seam

Because `MemoryBackend` is the single seam through which all memory access flows,
the entire stack above it can be exercised against a **mock guest** with no VM and
no memflow. That is [`MockBackend`](../crates/decant-backend/src/mock.rs), driven
by the `MockGuest` builder:

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

The mock implements every trait method deterministically, and writes round-trip
(a `write` followed by a `read` of the same range returns the new bytes), so the
host-side write-verification strategy (read-back rather than trusting the return
value) works without a VM.

This seam keeps Decant largely VM-free to develop:

- `decant-core` (AOB scanner, pointer-chain resolver) runs entirely
  against a `MockGuest`.
- `decant-daemon` dispatch logic is tested by pointing the server at a
  `MockBackend`.
- `decant-cli` and the carafe's marshaling can be driven end-to-end with the mock
  backend behind the daemon, no VM required.

`MemflowBackend` is the *only* component that genuinely needs a VM, and it is
swapped in behind the identical trait. Everything else is proven against the mock
first.

---

## 5. Crate layout (current)

Mixed-target Cargo workspace. Host crates are `default-members`; the Windows-gnu
crates are members but built only with `--target x86_64-pc-windows-gnu`.

| Crate | Target | Role |
|---|---|---|
| `crates/decant-protocol` | host + win-gnu | Frozen wire contract + shared domain types; `write_msg`/`read_msg` framing |
| `crates/decant-backend` | host | `MemoryBackend` trait + `MockBackend`/`MockGuest` |
| `crates/decant-memflow` | host | `MemflowBackend` |
| `crates/decant-core` | host | AOB scanner + pointer-chain resolver |
| `crates/decant-daemon` | host | "the cellar", TCP server + dispatch |
| `crates/decant-cli` | host | user CLI |
| `crates/decant-wine-harness` | host | launches exes under Wine for `cargo test` |
| `crates/decant-interpose` | win-gnu (cdylib) | "the carafe" interposer DLL |
| `testbins/hello-dll` | win-gnu (cdylib) | minimal PE32+ DLL exporting `add` |
| `testbins/dll-smoke` | win-gnu (exe) | loads `hello-dll`, proves the toolchain under Wine |
| `testbins/guest-target` | win-gnu | sample target for live tests (stub) |
| `testbins/sample-tool` | win-gnu | stand-in cheat tool for harness tests (stub) |
| `xtask` | host | build/test orchestration (`test`, `wine-smoke`) |

Domain types (`Pid`, `ProcessInfo`, `ModuleInfo`, `MemRegion`, `Diagnostics`,
`ProtoError`) live in `decant-protocol` and are re-used by `MemoryBackend`, so the
trait layer and the wire layer share one set of types with zero marshaling
boilerplate (ADR-0001).

---

## Decisions

Each entry records one architecturally significant decision: its context, the
choice, and its consequences. Entries are append-only; supersede rather than rewrite.

Status legend: **Accepted** (in force, reflected in code) · **Pending** (decision
deferred pending empirical validation; placeholder reserved so downstream docs can link
it).

### ADR-0001: Shared domain types live in `decant-protocol`

**Status:** Accepted

**Context.** Two layers need the same vocabulary: the `MemoryBackend` trait
(`decant-backend`) speaks in `Pid`/`ProcessInfo`/`ModuleInfo`/`MemRegion`, and the
TCP wire protocol (`decant-protocol`) must serialize those same concepts. The
naive approach defines them twice and writes `From`/`Into` marshaling between a
"backend `ProcessInfo`" and a "wire `ProcessInfo`", boilerplate that drifts.

**Decision.** The shared domain types live **once**, in `decant-protocol`, and the
`MemoryBackend` trait re-uses them directly (`decant-backend` re-exports
`MemRegion`, `ModuleInfo`, `Pid`, `ProcessInfo`, `ProtoError` from the protocol
crate). The trait's return types *are* the wire types.

**Consequences.**
- Zero marshaling between the trait layer and the wire layer.
- A change to a domain type is a single edit that recompiles both ends at once;
  the wire format cannot silently diverge from the backend's view.
- `decant-protocol` is dependency-light (`serde` + `bincode`) so it compiles
  unchanged for both `x86_64-unknown-linux-gnu` (daemon) and
  `x86_64-pc-windows-gnu` (carafe DLL).
- One concession: backend-internal errors (`BackendError`) are a *separate* enum
  from the wire `ProtoError`, with a single `From` mapping at the daemon edge.
  This keeps `thiserror` ergonomics on the backend side while the wire stays a
  plain `serde` enum. The *data* types stay shared; only the error type is
  bridged.

### ADR-0002: IPC is localhost TCP with length-prefixed bincode

**Status:** Accepted

**Context.** The carafe DLL (inside a Wine process) and the cellar daemon (a
native Linux process beside the VM) must exchange the narrow-waist primitives.
They are different machines-of-execution. Options considered: a Unix domain
socket, a named pipe, shared memory, or TCP.

**Decision.** **Localhost TCP** (`127.0.0.1:<port>`) carrying **length-prefixed
bincode**: a little-endian `u32` byte count followed by a `bincode`-serialized
`Request`/`Response`. Implemented by `write_msg`/`read_msg` in `decant-protocol`
over any `Read`/`Write`.

**Consequences.**
- Works identically for a Wine-side client and a Linux-side server; Wine's Winsock
  maps cleanly onto host TCP, avoiding Unix-socket/named-pipe translation quirks.
- Trivially mockable: the framing is tested over an in-memory `Cursor`, no socket
  needed.
- The reader enforces `MAX_MSG_LEN` (64 MiB) so a hostile/corrupt length prefix
  errors instead of allocating unboundedly; truncated streams report a clean
  `UnexpectedEof`; back-to-back messages share a stream without bleeding. (All
  three are covered by `decant-protocol` unit tests.)
- bincode is compact and schema-coupled, exactly what we want when both ends
  share the type definitions (ADR-0001). The trade-off (no cross-language /
  cross-version wire stability) is acceptable because both ends are built from the
  same workspace at the same time.
- Binding to loopback only; no remote exposure in the default posture.

### ADR-0003: Mixed-target workspace: `default-members` (host) + explicit `--target`

**Status:** Accepted

**Context.** Most crates are native host code (daemon, cli, core, backend,
protocol, memflow, wine-harness, xtask). A handful must compile *only* for
`x86_64-pc-windows-gnu`: the interposer `cdylib` and the Windows test binaries
that run under Wine or inside the guest. A bare `cargo build` must not try to
build the Windows crates for Linux (they would fail), yet they must share one
lockfile and `target/` dir.

**Decision.** A single Cargo workspace lists **all** crates in `members`, but
`default-members` lists **host crates only**. `cargo build` / `cargo test` with no
`-p`/`--target` touch only the host set. The Windows crates are built explicitly:
`cargo build -p <crate> --target x86_64-pc-windows-gnu` (orchestrated by `xtask`).

**Consequences.**
- One `Cargo.lock`, one `target/`, consistent dependency resolution across both
  worlds.
- `cargo test` runs for contributors without a mingw toolchain installed;
  the cross-compiled bits are opt-in.
- The split is documented at the top of the root `Cargo.toml` so the non-obvious
  `default-members` choice is self-explaining.
- `decant-protocol` is in *both* worlds; it builds for host and win-gnu, letting
  the same wire contract link into the daemon and the DLL.

### ADR-0004: x86_64 everywhere

**Status:** Accepted

**Context.** The guest VM, the Wine-hosted tool, and the interposer DLL must agree
on a calling convention and a name-decoration scheme for the exports the carafe
re-implements and forwards.

**Decision.** Target **x86_64 across the board** (guest, Wine prefix, DLL,
testbins). No 32-bit (`i686`) support.

**Consequences.**
- **One calling convention** (the Windows x64 ABI) for every intercepted/forwarded
  export, with no `__stdcall`/`__cdecl` ambiguity to disambiguate per function.
- **Undecorated exports.** x64 does not apply the `_name@N` stdcall decoration that
  Win32 uses, so export names are clean (`add`, not `_add@8`), which simplifies the
  carafe's `GetProcAddress`-style resolution and its own export table.
- Matches modern targets and memflow's primary focus; avoids a second WoW64 memory
  layout to model.
- Cost: 32-bit-only legacy tools are out of scope. Accepted.

### ADR-0005: Verified memflow connector API (QEMU/KVM)

**Status:** Accepted. Validated against a real
QEMU/KVM Windows 10 guest (see "Validation against the VM" below). Verified by web
research (docs.rs + GitHub source) and by a `cargo build --features memflow`
that typechecked the whole surface (the only defect a missing `mut`).
`crates/decant-memflow/src/backend.rs` is the implementation.

**Validation against the VM.** The daemon and core paths passed against
a running `win10` guest (Windows 10 `10.0.19045`):
- A `memflow` **0.2.4** core (what `decant-memflow` links) successfully loaded the
  installed **0.2.1** connector/OS plugins, confirming the ABI match is the integer
  `MEMFLOW_PLUGIN_VERSION` (`=1`), not the crate version (the source-skew risk noted
  in this ADR retired in practice). The KVM connector built the win32 kernel, downloaded `ntkrnlmp.pdb`.
- **Connector args:** the connector takes the target as memflow's **default (unnamed)
  arg**, the qemu process PID passed *bare* (`DECANT_CONNECTOR_ARGS="<pid>"`). A
  `pid=` *named* arg fails `Error(Connector, ArgValidation)` because `pid` is not a
  declared named arg. `MEMFLOW_PLUGIN_PATH` must point at the dir holding the
  `libmemflow_{kvm,win32}.so` plugins. KVM needs root (`/dev/memflow` is `root:root`).
- **Read:** `read` of `explorer.exe`'s image base returned `4d 5a 90 00 …` (the real
  `MZ`/PE header); modules (`ntdll.dll`, `KERNEL32.DLL`, …) enumerated correctly.
- **Write:** a reversible write into stable heap padding changed the bytes and
  read back the pattern, then restored the originals byte-for-byte (PASS).
- **Resolve:** a planted 2-hop pointer chain resolved to the terminal value.
- **Caveat observed:** writing into *actively-used* heap is racy. A second target
  slot was reclaimed/rewritten by the guest between operations (an atomicity /
  hot-data caveat). Prefer stable padding or a purpose-built target for writes.

**Crate pins.** `memflow = { version = "0.2", features = ["plugins"], optional =
true }`. The `plugins` feature provides the runtime `Inventory`. We deliberately do
**not** depend on `memflow-win32` at compile time (its published 0.2.0 predates core
0.2.4 and risks source skew). Instead the Windows OS layer is
loaded as a runtime `.os` plugin (`inventory.builder().os("win32")`).

**Connector model = runtime plugins.** The `qemu`/`kvm` connector and the `win32`
OS are `.so`/`.os` plugins discovered by `Inventory::scan()`, NOT linked. So
`decant-memflow` compiles with no VM present; `connect()` only succeeds on the VM host
where the plugins are installed. **This is why the offline suite needs no VM and
the VM validation is the user's to run.**

**User-side install (on the VM host, x86_64 Linux):**
```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.memflow.io | sh   # memflowup
memflowup install memflow-qemu memflow-win32     # (+ memflow-kvm for KVM)
# QEMU connector reads the qemu process via procfs → needs CAP_SYS_PTRACE:
sudo setcap 'CAP_SYS_PTRACE=ep' target/release/decant-daemon       # or run as root
```
KVM instead needs the `memflow.ko` module (DKMS) + a `memflow` group/udev rule.

**Bootstrap.** `Inventory::scan()` →
`inventory.builder().connector("qemu").args(<ConnectorArgs>).os("win32").build()` →
`OsInstanceArcBox<'static>`. The QEMU VM name is the connector arg, supplied via
`DECANT_CONNECTOR_ARGS` (memflow `key=value,flag` syntax); `--connector` /
`DECANT_CONNECTOR` selects the plugin (`qemu`/`kvm`).

**Impedance mismatch (important).** memflow handles take `&mut self` and are not
`Sync`; our `MemoryBackend` is `&self` + `Send + Sync`. Resolution: store the OS
handle in a `Mutex`; every call locks, re-resolves the process by pid, and operates.
Correctness over throughput; a per-pid handle cache is a future optimization.

**Trait → memflow mapping (all verified to compile):**

| `MemoryBackend` | memflow call |
|---|---|
| `list_processes` | `os.process_info_list()` → `{Pid(i.pid), i.name.to_string()}` |
| `process_by_pid` / `_name` | `os.process_info_by_pid(u32)` / `process_info_by_name(&str)` |
| `module_list` | `os.process_by_pid(pid)?.module_list()` → `{name, base.to_umem(), size}` |
| `module_by_name` | `proc.module_by_name(&str)` |
| `module_exports` | `proc.module_export_list(&minfo)` → `(name, base + offset)` (RVA→VA) |
| `read` | `proc.read_raw(Address::from(addr), len)` (`PartialResult`) |
| `write` | `proc.write_raw(Address::from(addr), data)` |
| `memory_map` | `proc.mapped_mem_vec(-1)` → `CTup3<Address, umem, PageType>`; `w = PageType::WRITEABLE`, `x = !PageType::NOEXEC` |

**Caveats:** `read_raw`/`write_raw` return a
`PartialResult`. Paged-out guest pages yield a partial error; we surface that as a
hard `ReadFailed`/`WriteFailed` rather than returning silently-truncated bytes.
`memory_map` permission flags are coarse (page-table derived, not full Win32
`PAGE_*`). `Pid` is `u32`. The API is compile-verified; the user runs the VM
validation per the README's daemon procedure.

### ADR-0006: Injection / interposition vector: IAT patching, delivered by remote-thread injection

**Status:** Accepted. Validated on wine-11.11
against the isolated repo-local prefix. Reproduce with `cargo xtask inject-test`.

**Context.** The carafe (`decant-interpose.dll`) must (1) get itself loaded into an
*unmodified* tool running under Wine, and (2) take over the relevant Win32/NT memory
exports, all while binding **only** to the public Win32/NT export ABI + the PE
format, never Wine internals (the public-export-only rule, see the Version-agnosticism
section). Two questions, evaluated separately: the **interception mechanism** and the
**delivery vector**.

**Decision.**

- **Interception mechanism = Import Address Table (IAT) patching.** The carafe walks
  a loaded module's PE import directory (DOS header → NT headers → data-directory
  entry 1 → `IMAGE_IMPORT_DESCRIPTOR` array → INT/IAT thunk pairs) and, for each
  import matching a target name (e.g. `kernel32.dll!ReadProcessMemory`), overwrites
  the 8-byte IAT slot with a pointer to the carafe's replacement. It patches the main
  exe via `GetModuleHandleW(NULL)` and every other loaded module via
  `psapi!EnumProcessModules`. The only image mutation is a pointer in a data table,
  guarded by `VirtualProtect(PAGE_READWRITE)` and restored afterward. Implemented in
  `crates/decant-interpose/src/lib.rs` (`patch_module_iat` / `patch_all_modules` /
  `write_iat_slot`).

- **Delivery vector = launcher-driven remote-thread injection.**
  `testbins/decant-launcher` does `CreateProcessW(target, CREATE_SUSPENDED)` →
  `VirtualAllocEx`+`WriteProcessMemory` (the DLL path) → `CreateRemoteThread` at
  `kernel32!LoadLibraryA` → wait → `ResumeThread`. The carafe's `DllMain`
  (`DLL_PROCESS_ATTACH`) self-installs the IAT hooks, so the target is *unmodified*.
  This is the `wine-env/run.sh <tool>` entry point Decant ships: the user
  runs their tool *through* the launcher.

**Public-export-only surface.** Every primitive is on the stable side of
the Wine boundary:
- Mechanism: `GetModuleHandleW`, `GetProcAddress`, `VirtualProtect`,
  `psapi!EnumProcessModules`, and the **frozen PE image format**.
- Vector: `CreateProcessW`, `VirtualAllocEx`, `WriteProcessMemory`,
  `GetModuleHandleA`/`GetProcAddress`, `CreateRemoteThread`, `ResumeThread`.
None of `__wine_unix_call`, the wineserver protocol, internal cross-DLL import paths,
or syscall-dispatch thunks is touched. **There is no inline prologue patching**; we
rewrite a pointer table the loader already built, not code bytes, so the single
"fragile spot" flagged in the Version-agnosticism section is **avoided entirely**;
nothing needs per-Wine-version re-validation.

**Forwarding for the unimplemented ~95%.** IAT patching is inherently surgical: only
the named slots we choose to patch are redirected; every other import keeps pointing
at the real Wine builtin, so unimplemented exports forward with no proxy
DLL, no `.def`, and no export-table to maintain (contrast a `WINEDLLOVERRIDES` proxy,
which must re-export *every* symbol of the shadowed DLL).

**Vectors evaluated and results (literal Wine stdout):**

| Vector | What | Result on wine-11.11 |
|---|---|---|
| cooperative bootstrap | `sample-tool --cooperative` `LoadLibraryA`s the carafe, `GetProcAddress`es `decant_install_hooks`, calls it, then `ReadProcessMemory` | **PASS**. `decant_install_hooks patched 1 slot(s)` then `INTERCEPTED` |
| baseline (control) | `sample-tool` with no injection | `passthrough` (proves the probe discriminates) |
| `AppInit_DLLs` | set `AppInit_DLLs`/`LoadAppInit_DLLs=1`/`RequireSignedAppInit_DLLs=0`; run unmodified `sample-tool` (which imports `user32`) | **FAIL: not supported on Wine.** The DLL is never loaded. Disassembly of `kernelbase!LoadAppInitDlls` shows a **no-op stub** (its body is `test [dbg_flag],8` / optional `FIXME` / `ret`); no builtin contains the `AppInit_DLLs` registry-value string, and nothing invokes it during process init. A real-Windows-only path. |
| `WINEDLLOVERRIDES` proxy | name the carafe to shadow a DLL the tool imports | **Rejected by design.** `sample-tool` imports only `kernel32`/`user32`; both are early/KnownDLL-class loads the proxy trick can't cleanly shadow (the KnownDLL early-load problem), and a proxy must re-export the *entire* shadowed surface. Viable only for tools that import an incidental DLL (DXVK/ReShade style); not general. Not implemented. |
| launcher injection | `decant-launcher sample-tool.exe` (suspended-create + `CreateRemoteThread`/`LoadLibrary`), `DECANT_AUTOHOOK=1`; `sample-tool` **unmodified** | **PASS**. `INTERCEPTED`. Control with `DECANT_AUTOHOOK` unset: DLL is confirmed injected (loaddll trace shows `decant_interpose.dll … native`); `DllMain` declines to install, giving `passthrough`, isolating the install step as the cause. |

The `0xCC` marker is the observable: the hook fills the caller's buffer with `0xCC`
and returns `TRUE`, so `sample-tool` distinguishes a rerouted call (`INTERCEPTED`)
from real bytes (`passthrough`). Daemon marshaling replaces the hook body in the
end-to-end path; this check only proves the call is rerouted.

**Why this beats the alternatives.** It is the only evaluated vector that interposes an
*unmodified* tool on stock Wine 11.11 using public exports + PE only: `AppInit_DLLs`
is a Wine stub; the override-proxy needs a shadowable incidental import and a full
re-export surface; inline `Nt*` prologue hooking is version-fragile (see the
Version-agnosticism section, the residual fragile spot) and unnecessary because the
export-level IAT patch already covers any tool that
calls the memory APIs by name. Remote-thread injection + IAT patching keeps Decant
entirely on the version-portable side.

**Residual fragility:** none from this vector. The IAT patch depends only on the PE
format and four documented exports; the launcher on six. No prologue bytes, no Wine
build coupling.

**Documented limitation (see the Version-agnosticism section, the raw-syscall
limitation).** A tool that issues a **raw `syscall` instruction** (syscall number in
a register, executed directly, never calling the named `Nt*` export) **bypasses IAT
interception entirely**; no import slot is ever read, so there is nothing to patch.
Catching it would require operating at the syscall-dispatch layer (SUD /
`seccomp-unotify`), which is exactly the Wine-internal, version-fragile territory the
public-export-only rule forbids. Decant deliberately keeps version-portability and
does not cover raw-syscall tools; this is stated in the docs and exercised by the
carafe-injection adversarial test. (Such a call still cannot escape the
unsupported-operation limit regardless; the limitation is about interception
*visibility* in the Wine-hosted tool, not new power over the guest.)

**Reproduce:** `cargo xtask inject-test` (builds carafe + `sample-tool` + launcher, stages
them, runs the cooperative bootstrap + baseline + launcher injection under the isolated prefix, asserts the
markers). Manual: build `-p decant-interpose -p sample-tool -p decant-launcher
--target x86_64-pc-windows-gnu`, co-locate the three artifacts, then under the
prefix `wine sample-tool.exe --cooperative` (cooperative bootstrap) and
`DECANT_AUTOHOOK=1 wine decant-launcher.exe sample-tool.exe` (launcher injection).

### ADR-0007: Library facade (`decant`) and a shared client (`decant-client`)

**Status:** Accepted

**Context.** Decant is usable three ways: embed a backend in a Rust program the way
memflow is used, connect to a running daemon, or drive it from the CLI. The RPC
client logic existed twice, in the CLI and in the interposer, duplicating the
connect, frame, and reconnect handling.

**Decision.** One `decant-client` crate holds `Client` (lazy connect, reconnect-once,
typed methods over `decant-protocol`). It depends only on `decant-protocol` and
`thiserror`, so it builds for the host and for `x86_64-pc-windows-gnu`. The CLI, the
interposer, and library users all use it. A top-level `decant` crate re-exports the
backend trait, `MockBackend`/`MockGuest`, the scanner and resolver, `MemflowBackend`
(behind the `memflow` feature), and `Client`, with a `prelude`, so a consumer writes
`use decant::prelude::*`.

**Consequences.**
- The client lives in one place; the interposer `rpc` module is a thin wrapper over it.
- Two usage modes from one import: an in-process backend (`MockBackend` or
  `MemflowBackend`) with `scan`/`resolve`, or a remote `Client` against a daemon.
- `decant-client` carries no host-only dependency, so the interposer keeps building
  for windows-gnu.
- The CLI gains `--json` for machine-readable output; the default stays human-readable.

---

## Version-agnosticism

This section explains *why* Decant runs across Wine versions without a recompile,
states the Wine internals the carafe is **forbidden** to bind to, and documents the
one residual fragile spot and the one coverage limitation.

### Bind only to the public export ABI

Wine guarantees stability at exactly one boundary: the **public Win32/NT export
ABI**, the set of named functions a real Windows DLL exports (`kernel32`,
`ntdll`, `psapi`, …), with their documented signatures and calling convention.
That contract is what *every* Windows program in the world depends on, so Wine
treats it as sacrosanct and keeps it stable release over release.

Decant's carafe (`decant-interpose`) binds to **that boundary and nothing else**.
It re-implements/intercepts a handful of public memory + introspection exports
(`ReadProcessMemory`, `WriteProcessMemory`, `NtReadVirtualMemory`, `VirtualQueryEx`,
toolhelp/psapi enumeration, `GetModuleHandle`/`GetProcAddress`, …) and forwards
everything else to the real Wine builtin through the same public interface.

Because that surface is the most stable thing Wine offers, Decant inherits its
stability: drop in a new Wine version and the carafe keeps working, with no
recompile tied to Wine's internal layout. This is reinforced by ADR-0004
(x86_64-only): one calling convention, undecorated export names, no per-function
`_name@N` decoration to track across Wine builds.

### Forbidden Wine internals (and why)

Everything below is an **unstable implementation detail** of Wine. It changes
between releases without notice and is explicitly *not* a contract. Decant must
never bind to any of it:

- **`__wine_unix_call` / the unixlib (PE↔Unix) boundary.** This is Wine's private
  mechanism for a builtin DLL's PE side to call into its `.so` Unix side. Its
  function indices, struct layouts, and ABI are internal and version-specific.
  Touching it couples Decant to a single Wine build. *Forbidden.*
- **The wineserver IPC protocol.** The request/reply wire format spoken to
  `wineserver` is a private protocol that changes whenever the server does. Decant
  gets process/module facts from **memflow reading the guest**, not from
  wineserver. *Forbidden.*
- **Internal cross-DLL import paths.** Reaching "through" a builtin to call another
  builtin's *non-exported* helper, or relying on one builtin's private knowledge of
  another's internals. Only public exports may be called. *Forbidden.*
- **Syscall-dispatch thunks / the internal syscall table.** Wine's private
  `Nt*`→Unix dispatch thunks and syscall-number tables are an internal detail.
  Decant interposes at the *named export* level, not by hooking Wine's syscall
  dispatch machinery. *Forbidden.*

The rule in one line: **bind to public Win32/NT exports; never to Wine internals.**
If a vector under consideration requires any of the above, it is rejected.

### The one residual fragile spot

The injection/interposition vector is chosen in ADR-0006. Most
candidate vectors (e.g. `WINEDLLOVERRIDES` builtin/native substitution, EAT/IAT
patching) stay on the public-export side and are version-robust.

The exception: **if the vector lands on inline-hooking the `Nt*` prologues**,
overwriting the first instructions of `ntdll`'s exported `Nt*` stubs to redirect
them, then Decant becomes sensitive to the *exact byte layout* of those prologues.
That layout is still a property of a *public export*, so this does not cross into
the forbidden list above. The specific prologue bytes and length can shift between
Wine builds, so an inline hook may need re-validation per Wine version. This is the
single fragile point, and it is called out here so that the dependency is documented
rather than hidden. The chosen vector (ADR-0006) avoids prologue patching, so the
fragility does not apply to the shipped path.

### The limitation: raw syscalls bypass export-level interception

Decant intercepts at the **named-export** layer. A tool that calls
`ReadProcessMemory`/`NtReadVirtualMemory` *by name* is fully covered.

A tool that issues a **raw syscall**, placing the syscall number in a register and
executing the `syscall`/`int 2e` instruction directly, never going through the
named `Nt*` export, **bypasses the carafe entirely.** Nothing at the export level
can see it, because no export was called.

This is an accepted limitation:

- Decant does **not** claim to cover raw-syscall tools. The docs and diagnostics
  state this plainly (the carafe-injection adversarial test exercises it).
- Closing it would require operating at the syscall-dispatch layer, which is
  the Wine-internal territory forbidden above, so doing so would trade
  version-portability for coverage. Decant deliberately keeps the portability.
- Such a call still cannot escape the limits on guest execution
  (section 3): even a raw syscall in the *guest* cannot make memflow
  run guest code. The limitation concerns interception visibility in the Wine-hosted
  tool; it does not give the tool new power over the guest.

A second coverage boundary: `SetWindowsHookEx` and `QueueUserAPC` are forwarded
to the real Wine builtin, not intercepted. Neither carries a guest process
handle. An event hook targets the local Wine session and an APC targets a thread
handle Decant never mints, so installing an event hook or queueing an APC against
the guest is not expressible through the handle model and is not attempted.
Interposing them would only break the tool's own legitimate use of the local
Wine session.
