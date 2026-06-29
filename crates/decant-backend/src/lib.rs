pub use decant_protocol::{MemRegion, ModuleInfo, Pid, ProcessInfo, ProtoError};

mod mock;
pub use mock::{MockBackend, MockGuest};

pub mod fixtures;

pub type Result<T> = std::result::Result<T, BackendError>;

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
}
