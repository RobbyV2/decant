# Decant Wine Versioning & ABI Stability

This document explains *why* Decant is plug-and-play across Wine versions, states
the Wine internals it is **forbidden** to touch (and why), and documents the
one residual fragile spot and the one coverage limitation.

---

## 1. Why Decant is version-portable: bind only to the public export ABI

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

---

## 2. Forbidden Wine internals (and why)

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

---

## 3. The one residual fragile spot

The injection/interposition vector is chosen in ADR-0006. Most
candidate vectors (e.g. `WINEDLLOVERRIDES` builtin/native substitution, EAT/IAT
patching) stay on the public-export side and are version-robust.

The exception: **if the vector lands on inline-hooking the `Nt*` prologues**,
overwriting the first instructions of `ntdll`'s exported `Nt*` stubs to redirect
them, then Decant becomes sensitive to the *exact byte layout* of those prologues.
That layout is still a property of a *public export*, so this does not cross into
the forbidden list above. The specific prologue bytes and length can shift between
Wine builds, so an inline hook may need re-validation per Wine version. This is the
single fragile point, and it is called out here so that, if ADR-0006
selects it, the dependency is documented rather than hidden. Prefer a vector that
avoids prologue patching where one is viable.

---

## 4. The limitation: raw syscalls bypass export-level interception

Decant intercepts at the **named-export** layer. A tool that calls
`ReadProcessMemory`/`NtReadVirtualMemory` *by name* is fully covered.

A tool that issues a **raw syscall**, placing the syscall number in a register and
executing the `syscall`/`int 2e` instruction directly, never going through the
named `Nt*` export, **bypasses the carafe entirely.** Nothing at the export level
can see it, because no export was called.

This is an accepted limitation:

- Decant does **not** claim to cover raw-syscall tools. The docs and diagnostics
  state this plainly (the carafe-injection adversarial review in `docs/TESTING.md` exercises it).
- Closing it would require operating at the syscall-dispatch layer, which is
  the Wine-internal territory forbidden in section 2, so doing so would trade
  version-portability for coverage. Decant deliberately keeps the portability.
- Such a call still cannot escape the limits on guest execution
  (`docs/ARCHITECTURE.md` section 3): even a raw syscall in the *guest* cannot make memflow
  run guest code. The limitation concerns interception visibility in the Wine-hosted
  tool; it does not give the tool new power over the guest.
