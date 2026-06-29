//! # decant-core — backend-agnostic analysis primitives
//!
//! The AOB/signature **scanner** and the pointer-chain **resolver**. Both operate
//! purely through the [`decant_backend::MemoryBackend`] trait, so they run
//! identically over a `MockGuest` (offline tests) and the live `MemflowBackend`
//! (the VM) — and the daemon runs them server-side so region reads stay local to
//! the backend (spec §2.1, §4 Phase 2).

#![allow(clippy::manual_map)]

use decant_backend::{BackendError, MemoryBackend, Pid};

pub mod pattern;
pub mod resolver;
pub mod scanner;

pub use pattern::Pattern;
pub use resolver::resolve;
pub use scanner::{scan, scan_with_chunk};

/// Errors from the analysis primitives.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid AOB pattern: {0}")]
    Pattern(String),

    #[error(transparent)]
    Backend(#[from] BackendError),
}

pub type Result<T> = std::result::Result<T, CoreError>;

/// Read exactly 8 bytes at `addr` and interpret them as a little-endian `u64`
/// pointer — the single dereference both the resolver and value-reads are built on.
pub(crate) fn read_u64(backend: &dyn MemoryBackend, pid: Pid, addr: u64) -> Result<u64> {
    let bytes = backend.read(pid, addr, 8)?;
    // backend.read returns exactly the requested length on success.
    let arr: [u8; 8] = bytes
        .try_into()
        .map_err(|_| CoreError::Backend(BackendError::ReadFailed {
            addr,
            len: 8,
            reason: "short read resolving pointer".into(),
        }))?;
    Ok(u64::from_le_bytes(arr))
}
