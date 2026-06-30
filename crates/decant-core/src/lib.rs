#![allow(clippy::manual_map)]

use decant_backend::{BackendError, MemoryBackend, Pid};

pub mod pattern;
pub mod resolver;
pub mod scanner;

pub use pattern::Pattern;
pub use resolver::resolve;
pub use scanner::{scan, scan_with_chunk};

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid AOB pattern: {0}")]
    Pattern(String),

    #[error(transparent)]
    Backend(#[from] BackendError),
}

pub type Result<T> = std::result::Result<T, CoreError>;

pub(crate) fn read_u64(backend: &dyn MemoryBackend, pid: Pid, addr: u64) -> Result<u64> {
    let bytes = backend.read(pid, addr, 8)?;
    let arr: [u8; 8] = bytes.try_into().map_err(|_| {
        CoreError::Backend(BackendError::ReadFailed {
            addr,
            len: 8,
            reason: "short read resolving pointer".into(),
        })
    })?;
    Ok(u64::from_le_bytes(arr))
}
