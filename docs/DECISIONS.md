# Decant — Architecture Decision Record (ADR) log

Each ADR records one architecturally significant decision: its context, the
choice, and its consequences. ADRs are append-only; supersede rather than rewrite.

Status legend: **Accepted** (in force, reflected in code) · **Pending** (decision
deferred to an empirical spike; placeholder reserved so downstream docs can link
it).

---

## ADR-0001 — Shared domain types live in `decant-protocol`

**Status:** Accepted

**Context.** Two layers need the same vocabulary: the `MemoryBackend` trait
(`decant-backend`) speaks in `Pid`/`ProcessInfo`/`ModuleInfo`/`MemRegion`, and the
TCP wire protocol (`decant-protocol`) must serialize those same concepts. The
naive approach defines them twice and writes `From`/`Into` marshaling between a
"backend `ProcessInfo`" and a "wire `ProcessInfo`" — boilerplate that drifts.

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

## ADR-0002 — IPC is localhost TCP with length-prefixed bincode

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
- bincode is compact and schema-coupled — exactly what we want when both ends
  share the type definitions (ADR-0001). The trade-off (no cross-language /
  cross-version wire stability) is acceptable because both ends are built from the
  same workspace at the same time.
- Binding to loopback only; no remote exposure in the default posture.

---

## ADR-0003 — Mixed-target workspace: `default-members` (host) + explicit `--target`

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
- `cargo test` "just works" for contributors without a mingw toolchain installed;
  the cross-compiled bits are opt-in.
- The split is documented at the top of the root `Cargo.toml` so the non-obvious
  `default-members` choice is self-explaining.
- `decant-protocol` is in *both* worlds — it builds for host and win-gnu — which
  is exactly what lets the same wire contract link into the daemon and the DLL.

---

## ADR-0004 — x86_64 everywhere

**Status:** Accepted

**Context.** The guest VM, the Wine-hosted tool, and the interposer DLL must agree
on a calling convention and a name-decoration scheme for the exports the carafe
re-implements and forwards.

**Decision.** Target **x86_64 across the board** (guest, Wine prefix, DLL,
testbins). No 32-bit (`i686`) support.

**Consequences.**
- **One calling convention** (the Windows x64 ABI) for every intercepted/forwarded
  export — no `__stdcall`/`__cdecl` ambiguity to disambiguate per function.
- **Undecorated exports.** x64 does not apply the `_name@N` stdcall decoration that
  Win32 uses, so export names are clean (`add`, not `_add@8`), which simplifies the
  carafe's `GetProcAddress`-style resolution and its own export table.
- Matches modern targets and memflow's primary focus; avoids a second WoW64 memory
  layout to model.
- Cost: 32-bit-only legacy tools are out of scope. Accepted.

---

## ADR-0005 — Verified memflow connector API (QEMU/KVM)

**Status:** Accepted (Phase 1) — **LIVE-VALIDATED 2026-06-29** against a real
QEMU/KVM Windows-10 guest (see "Live validation" below). Originally verified by web
research (docs.rs + GitHub source) and by an actual `cargo build --features memflow`
that typechecked the whole surface (the only defect a missing `mut`).
`crates/decant-memflow/src/backend.rs` is the implementation.

**Live validation (2026-06-29).** The Phase 1 *and* Phase 2 live gates passed against
a running `win10` guest (Windows 10 `10.0.19045`):
- A `memflow` **0.2.4** core (what `decant-memflow` links) successfully loaded the
  installed **0.2.1** connector/OS plugins — confirming the ABI gate is the integer
  `MEMFLOW_PLUGIN_VERSION` (`=1`), *not* the crate version (ADR-0005 §9 risk retired
  in practice). The KVM connector built the win32 kernel, downloaded `ntkrnlmp.pdb`.
- **Connector args:** the connector takes the target as memflow's **default (unnamed)
  arg** — the qemu process PID passed *bare* (`DECANT_CONNECTOR_ARGS="<pid>"`). A
  `pid=` *named* arg fails `Error(Connector, ArgValidation)` because `pid` is not a
  declared named arg. `MEMFLOW_PLUGIN_PATH` must point at the dir holding the
  `libmemflow_{kvm,win32}.so` plugins. KVM needs root (`/dev/memflow` is `root:root`).
- **Read:** `read` of `explorer.exe`'s image base returned `4d 5a 90 00 …` (the real
  `MZ`/PE header); modules (`ntdll.dll`, `KERNEL32.DLL`, …) enumerated correctly.
- **Write:** a reversible write into stable heap padding changed the bytes and
  read back the pattern, then restored the originals byte-for-byte (PASS).
- **Resolve:** a planted 2-hop pointer chain resolved live to the terminal value.
- **Caveat observed:** writing into *actively-used* heap is racy — a second target
  slot was reclaimed/rewritten by the guest between operations (spec §9 atomicity /
  hot-data caveat). Prefer stable padding or a purpose-built target for writes.

**Crate pins.** `memflow = { version = "0.2", features = ["plugins"], optional =
true }`. The `plugins` feature provides the runtime `Inventory`. We deliberately do
**not** depend on `memflow-win32` at compile time (its published 0.2.0 predates core
0.2.4 and risks source skew, ADR-0005 research §9). Instead the Windows OS layer is
loaded as a runtime `.os` plugin (`inventory.builder().os("win32")`).

**Connector model = runtime plugins.** The `qemu`/`kvm` connector and the `win32`
OS are `.so`/`.os` plugins discovered by `Inventory::scan()`, NOT linked. So
`decant-memflow` compiles with no VM, but `connect()` only succeeds on the VM host
where the plugins are installed. **This is why the autonomous suite needs no VM and
the live gate is the user's.**

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
Correctness over throughput — a per-pid handle cache is a future optimization.

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

**Known caveats / honesty (spec §9):** `read_raw`/`write_raw` return a
`PartialResult` — paged-out guest pages yield a partial error; we surface that as a
hard `ReadFailed`/`WriteFailed` rather than returning silently-truncated bytes.
`memory_map` permission flags are coarse (page-table derived, not full Win32
`PAGE_*`). `Pid` is `u32`. Live-untested in this environment (no VM) — the API is
compile-verified; the user runs the live gate per `docs/TESTING.md`.

---

## ADR-0006 — Injection / interposition vector *(placeholder)*

**Status:** Pending (to be resolved in Phase 3)

**Context.** The carafe (`decant-interpose.dll`) must get itself loaded into the
unmodified tool under Wine *and* take over the relevant Win32/NT memory exports.
Candidate vectors (to be spiked, not assumed): `WINEDLLOVERRIDES` builtin/native
substitution, an `AppInit`-style load, IAT/EAT patching from a loader, or
inline-hooking the `Nt*` prologues. Each has different fragility and different
exposure to Wine internals.

**Decision.** *Deferred.* The injection vector is chosen by the Phase 3 spike and
recorded here as an ADR *before* `decant-interpose` is implemented. Phase 0 ships
an empty `cdylib` so the cross-compile target is wired and builds.

**To record here when resolved:** the chosen vector; why it beat the alternatives;
exactly which public exports are interposed and how the real builtin is reached for
forwarding; and the residual fragility (e.g. if it lands on inline-hooking `Nt*`
prologues — see `docs/VERSIONING.md`). The chosen mechanism must bind only to the
public export ABI, never Wine internals.
