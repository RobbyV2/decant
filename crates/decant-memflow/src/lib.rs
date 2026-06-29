//! # decant-memflow — the real backend (Phase 1)
//!
//! `MemflowBackend` implements [`decant_backend::MemoryBackend`] over a memflow
//! connector (QEMU/KVM) reading the guest's physical RAM out of the VM process.
//! It is a drop-in swap behind the same trait the `MockBackend` implements.
//!
//! Per spec operating rule #3, the memflow crate versions and the exact method
//! names (connector inventory, OS object, `process_by_*`, `read_raw`/`write_raw`,
//! export list, VAD/page-map walk) MUST be verified empirically against the
//! pinned docs.rs pages and recorded in `docs/DECISIONS.md` BEFORE this is
//! implemented. The stub stands so the workspace compiles in Phase 0.

#![allow(dead_code)]

#[cfg(feature = "memflow")]
compile_error!(
    "the `memflow` feature is not implemented yet — Phase 1 wires the real \
     connector after verifying the memflow API (see docs/DECISIONS.md)."
);
