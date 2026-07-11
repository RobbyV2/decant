//! Backend trait and mock guest model for Decant memory access.

pub use decant_protocol::{
    MemRegion, ModuleInfo, PhysicalMemoryInfo, PhysicalRead, PhysicalWrite, Pid, ProcessInfo,
    ProtoError,
};

mod mock;
pub use mock::{MockBackend, MockGuest};

pub mod fixtures;

pub type Result<T> = std::result::Result<T, BackendError>;

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("no such process (pid={pid:?}, name={name:?})")]
    NoSuchProcess {
        pid: Option<u32>,
        name: Option<String>,
    },

    #[error("no such module {module:?} in pid {pid}")]
    NoSuchModule { pid: u32, module: String },

    #[error("read of {len} bytes at {addr:#x} failed: {reason}")]
    ReadFailed { addr: u64, len: u64, reason: String },

    #[error("write at {addr:#x} failed: {reason}")]
    WriteFailed { addr: u64, reason: String },

    #[error("unsupported operation: {op}")]
    Unsupported { op: String },

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
            BackendError::Unsupported { op } => ProtoError::Unsupported { op },
            BackendError::Other(message) => ProtoError::Backend { message },
        }
    }
}

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

    /// Describe the raw connector address space for consumers that perform
    /// their own operating-system analysis (for example MemProcFS/Orpheus).
    fn physical_memory_info(&self) -> Result<PhysicalMemoryInfo> {
        Err(BackendError::Unsupported {
            op: "raw physical-memory metadata".into(),
        })
    }

    fn read_physical(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        Err(BackendError::Unsupported {
            op: format!("raw physical-memory read at {address:#x}+{length:#x}"),
        })
    }

    fn write_physical(&self, address: u64, _data: &[u8]) -> Result<usize> {
        Err(BackendError::Unsupported {
            op: format!("raw physical-memory write at {address:#x}"),
        })
    }

    /// Batched physical reads preserve per-range failure, matching the
    /// scatter contract used by LeechCore.
    fn read_physical_scatter(&self, ranges: &[PhysicalRead]) -> Vec<Option<Vec<u8>>> {
        ranges
            .iter()
            .map(|range| {
                self.read_physical(range.address, range.length as usize)
                    .ok()
            })
            .collect()
    }

    fn write_physical_scatter(&self, ranges: &[PhysicalWrite]) -> Vec<bool> {
        ranges
            .iter()
            .map(|range| {
                self.write_physical(range.address, &range.data)
                    .is_ok_and(|written| written == range.data.len())
            })
            .collect()
    }
}
