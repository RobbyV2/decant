# Decant Architecture Decision Record (ADR) Log

Each ADR records one architecturally significant decision: its context, the
choice, and its consequences. ADRs are append-only; supersede rather than rewrite.

Status legend: **Accepted** (in force, reflected in code) · **Pending** (decision
deferred pending empirical validation; placeholder reserved so downstream docs can link
it).

---

## ADR-0001: Shared domain types live in `decant-protocol`

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

---

## ADR-0002: IPC is localhost TCP with length-prefixed bincode

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

---

## ADR-0003: Mixed-target workspace: `default-members` (host) + explicit `--target`

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

---

## ADR-0004: x86_64 everywhere

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

---

## ADR-0005: Verified memflow connector API (QEMU/KVM)

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
validation per `docs/TESTING.md`.

---

## ADR-0006: Injection / interposition vector: IAT patching, delivered by remote-thread injection

**Status:** Accepted. Validated on wine-11.11
against the isolated repo-local prefix. Reproduce with `cargo xtask inject-test`.

**Context.** The carafe (`decant-interpose.dll`) must (1) get itself loaded into an
*unmodified* tool running under Wine, and (2) take over the relevant Win32/NT memory
exports, all while binding **only** to the public Win32/NT export ABI + the PE
format, never Wine internals (the public-export-only rule, `docs/VERSIONING.md`). Two questions, evaluated
separately: the **interception mechanism** and the **delivery vector**.

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
"fragile spot" flagged in `docs/VERSIONING.md` section 3 is **avoided entirely**; nothing
needs per-Wine-version re-validation.

**Forwarding for the unimplemented ~95%.** IAT patching is inherently surgical: only
the named slots we choose to patch are redirected; every other import keeps pointing
at the real Wine builtin, so unimplemented exports forward with no proxy
DLL, no `.def`, and no export-table to maintain (contrast a `WINEDLLOVERRIDES` proxy,
which must re-export *every* symbol of the shadowed DLL).

**Vectors evaluated and results (literal Wine stdout):**

| Vector | What | Result on wine-11.11 |
|---|---|---|
| cooperative bootstrap | `mock-cheat --cooperative` `LoadLibraryA`s the carafe, `GetProcAddress`es `decant_install_hooks`, calls it, then `ReadProcessMemory` | **PASS**. `decant_install_hooks patched 1 slot(s)` then `INTERCEPTED` |
| baseline (control) | `mock-cheat` with no injection | `passthrough` (proves the probe discriminates) |
| `AppInit_DLLs` | set `AppInit_DLLs`/`LoadAppInit_DLLs=1`/`RequireSignedAppInit_DLLs=0`; run unmodified `mock-cheat` (which imports `user32`) | **FAIL: not supported on Wine.** The DLL is never loaded. Disassembly of `kernelbase!LoadAppInitDlls` shows a **no-op stub** (its body is `test [dbg_flag],8` / optional `FIXME` / `ret`); no builtin contains the `AppInit_DLLs` registry-value string, and nothing invokes it during process init. A real-Windows-only path. |
| `WINEDLLOVERRIDES` proxy | name the carafe to shadow a DLL the tool imports | **Rejected by design.** `mock-cheat` imports only `kernel32`/`user32`; both are early/KnownDLL-class loads the proxy trick can't cleanly shadow (the KnownDLL early-load problem), and a proxy must re-export the *entire* shadowed surface. Viable only for tools that import an incidental DLL (DXVK/ReShade style); not general. Not implemented. |
| launcher injection | `decant-launcher mock-cheat.exe` (suspended-create + `CreateRemoteThread`/`LoadLibrary`), `DECANT_AUTOHOOK=1`; `mock-cheat` **unmodified** | **PASS**. `INTERCEPTED`. Control with `DECANT_AUTOHOOK` unset: DLL is confirmed injected (loaddll trace shows `decant_interpose.dll … native`); `DllMain` declines to install, giving `passthrough`, isolating the install step as the cause. |

The `0xCC` marker is the observable: the hook fills the caller's buffer with `0xCC`
and returns `TRUE`, so `mock-cheat` distinguishes a rerouted call (`INTERCEPTED`)
from real bytes (`passthrough`). Daemon marshaling replaces the hook body in the
end-to-end path; this check only proves the call is rerouted.

**Why this beats the alternatives.** It is the only evaluated vector that interposes an
*unmodified* tool on stock Wine 11.11 using public exports + PE only: `AppInit_DLLs`
is a Wine stub; the override-proxy needs a shadowable incidental import and a full
re-export surface; inline `Nt*` prologue hooking is version-fragile (`VERSIONING.md`
section 3) and unnecessary because the export-level IAT patch already covers any tool that
calls the memory APIs by name. Remote-thread injection + IAT patching keeps Decant
entirely on the version-portable side.

**Residual fragility:** none from this vector. The IAT patch depends only on the PE
format and four documented exports; the launcher on six. No prologue bytes, no Wine
build coupling.

**Documented limitation (`docs/VERSIONING.md` section 4).** A tool that issues
a **raw `syscall` instruction** (syscall number in a register, executed directly,
never calling the named `Nt*` export) **bypasses IAT interception entirely**; no
import slot is ever read, so there is nothing to patch. Catching it would require
operating at the syscall-dispatch layer (SUD / `seccomp-unotify`), which is exactly
the Wine-internal, version-fragile territory the public-export-only rule forbids. Decant deliberately
keeps version-portability and does not cover raw-syscall tools; this is stated in the
docs and exercised by the carafe-injection adversarial review (`docs/TESTING.md`). (Such a call still
cannot escape the unsupported-operation limit regardless; the limitation is about
interception *visibility* in the Wine-hosted tool, not new power over the guest.)

**Reproduce:** `cargo xtask inject-test` (builds carafe + `mock-cheat` + launcher, stages
them, runs the cooperative bootstrap + baseline + launcher injection under the isolated prefix, asserts the
markers). Manual: build `-p decant-interpose -p mock-cheat -p decant-launcher
--target x86_64-pc-windows-gnu`, co-locate the three artifacts, then under the
prefix `wine mock-cheat.exe --cooperative` (cooperative bootstrap) and
`DECANT_AUTOHOOK=1 wine decant-launcher.exe mock-cheat.exe` (launcher injection).

## ADR-0007: Library facade (`decant`) and a shared client (`decant-client`)

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
