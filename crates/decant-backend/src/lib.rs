//! # decant-backend — the `MemoryBackend` seam
//!
//! Everything in Decant that reads or writes guest memory does so through the one
//! trait in this crate. There are two implementations:
//!
//! * [`MockBackend`] — a scriptable in-memory fake guest ("the tasting"), the
//!   keystone of Decant's autonomy. ~90% of the system is testable with no VM
//!   because every layer above can run against this (spec §1.2, §3).
//! * `MemflowBackend` (in `decant-memflow`, feature-gated) — the real connector
//!   that reads guest physical RAM out of the VM. A drop-in swap behind this same
//!   trait.
//!
//! ## The narrow waist (spec §2.1)
//!
//! The whole Win32 introspection surface funnels into the few primitives below:
//! read/write virtual memory, query regions, enumerate processes/modules, resolve
//! exports. Translate these and everything above comes along for free.
//!
//! The domain types (`Pid`, `ProcessInfo`, `ModuleInfo`, `MemRegion`) live in
//! `decant-protocol` so there is zero marshaling between the trait and the wire
//! (ADR-0001). They are re-exported here for ergonomic `use decant_backend::*`.

pub use decant_protocol::{MemRegion, ModuleInfo, Pid, ProcessInfo, ProtoError};

mod mock;
pub use mock::{MockBackend, MockGuest};

/// The result type every backend method returns.
pub type Result<T> = std::result::Result<T, BackendError>;

/// A backend-side error. The daemon maps this into a wire-stable
/// [`decant_protocol::ProtoError`] before it crosses the socket.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("no such process (pid={pid:?}, name={name:?})")]
    NoSuchProcess { pid: Option<u32>, name: Option<String> },

    #[error("no such module {module:?} in pid {pid}")]
    NoSuchModule { pid: u32, module: String },

    #[error("read of {len} bytes at {addr:#x} failed: {reason}")]
    ReadFailed { addr: u64, len: u64, reason: String },

    #[error("write at {addr:#x} failed: {reason}")]
    WriteFailed { addr: u64, reason: String },

    /// Requested operation needs guest execution; memflow cannot do it (spec §9).
    #[error("execution wall: {op}")]
    ExecutionWall { op: String },

    #[error("backend error: {0}")]
    Other(String),
}

impl From<BackendError> for ProtoError {
    fn from(e: BackendError) -> Self {
        match e {
            BackendError::NoSuchProcess { pid, name } => ProtoError::NoSuchProcess { pid, name },
            BackendError::NoSuchModule { pid, module } => ProtoError::NoSuchModule { pid, module },
            BackendError::ReadFailed { addr, len, reason } => {
                ProtoError::ReadFailed { addr, len, reason }
            }
            BackendError::WriteFailed { addr, reason } => ProtoError::WriteFailed { addr, reason },
            BackendError::ExecutionWall { op } => ProtoError::ExecutionWall { op },
            BackendError::Other(message) => ProtoError::Backend { message },
        }
    }
}

/// The seam. Object-safe (`dyn MemoryBackend` is used by the daemon) and
/// `Send + Sync` so the daemon can share one backend across connection threads.
///
/// FROZEN CONTRACT (spec operating rule #10): do not change these signatures
/// without updating every implementor and the daemon dispatch in lockstep.
pub trait MemoryBackend: Send + Sync {
    fn list_processes(&self) -> Result<Vec<ProcessInfo>>;
    fn process_by_pid(&self, pid: Pid) -> Result<ProcessInfo>;
    fn process_by_name(&self, name: &str) -> Result<ProcessInfo>;
    fn module_list(&self, pid: Pid) -> Result<Vec<ModuleInfo>>;
    fn module_by_name(&self, pid: Pid, name: &str) -> Result<ModuleInfo>;
    fn module_exports(&self, pid: Pid, module: &str) -> Result<Vec<(String, u64)>>;
    fn read(&self, pid: Pid, addr: u64, len: usize) -> Result<Vec<u8>>;
    fn write(&self, pid: Pid, addr: u64, data: &[u8]) -> Result<usize>;
    fn memory_map(&self, pid: Pid) -> Result<Vec<MemRegion>>;
}
