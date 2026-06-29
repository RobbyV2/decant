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

## ADR-0005 — Verified memflow connector API *(placeholder)*

**Status:** Pending (to be resolved in Phase 1)

**Context.** `MemflowBackend` must call memflow's real API: connector inventory
construction (QEMU/KVM), the OS object, `process_by_pid`/`process_by_name`, module
enumeration, export-table resolution, virtual `read_raw`/`write_raw`, and the
VAD/page-map walk that backs `memory_map`. The exact crate versions and method
names **must not be guessed** — per the operating rules they have to be verified
empirically against the pinned docs.rs pages and a live connector.

**Decision.** *Deferred.* No memflow API surface is committed to until verified.
The `decant-memflow` crate is a stub and its `memflow` feature is a hard
`compile_error!` until this ADR is filled in.

**To record here when resolved:** pinned `memflow` / `memflow-win32` (or
successor) crate versions; the exact connector-inventory call; the OS/process/
module/export method names actually used; how virtual→physical translation and the
region/permission map are obtained; and any capability gaps found.

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
