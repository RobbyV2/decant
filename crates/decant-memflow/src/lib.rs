//! # decant-memflow — the real backend (Phase 1)
//!
//! `MemflowBackend` implements [`decant_backend::MemoryBackend`] over a memflow
//! connector reading the guest's physical RAM out of the VM process. It is a
//! drop-in swap behind the same trait `MockBackend` implements, so the daemon and
//! everything above are unchanged.
//!
//! API verified empirically against memflow 0.2.4 — see `docs/DECISIONS.md`
//! ADR-0005 for the full mapping, version pins, and the user-side connector
//! install. Two facts shape the implementation:
//!
//! * **Runtime plugins.** The `qemu`/`kvm` connector and the `win32` OS layer are
//!   loaded at runtime via [`Inventory`], not linked. So this crate compiles with
//!   no VM present, but [`MemflowBackend::connect`] only succeeds on the VM host
//!   where the plugins are installed (`memflowup install memflow-qemu`) and the
//!   process has the needed privilege (`CAP_SYS_PTRACE` for qemu).
//! * **`&mut self`, not `Sync`.** memflow handles require `&mut self` and are not
//!   `Sync`. Our `MemoryBackend` is `&self` + `Send + Sync`, so we wrap the OS
//!   handle in a [`Mutex`]. Every call locks, re-resolves the process by pid, and
//!   operates — correctness over throughput; a handle cache is a later optimization.

#![allow(dead_code)]

#[cfg(feature = "memflow")]
mod backend;
#[cfg(feature = "memflow")]
pub use backend::MemflowBackend;
