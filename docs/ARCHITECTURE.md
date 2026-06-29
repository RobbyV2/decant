# Decant Architecture

Decant lets an **unmodified** Windows memory-editing tool run under Wine while its
memory accesses are transparently redirected to a *separate* Windows VM. The tool
believes it is poking at local process memory; in reality every read/write is
serviced by reading the guest VM's physical RAM from the outside via
[memflow](https://github.com/memflow/memflow).

This document describes the component topology, the "narrow waist" that makes the
design tractable, the host/VM physical reality that constrains the design, and
the mock-backend seam that keeps ~90% of the system testable with no VM at all.

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
host-side write-verification strategy (see `docs/TESTING.md`) works without a VM.

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
