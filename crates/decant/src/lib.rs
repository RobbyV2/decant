pub use decant_protocol::{Diagnostics, MemRegion, ModuleInfo, Pid, ProcessInfo, ProtoError};
pub use decant_backend::{BackendError, MemoryBackend, MockBackend, MockGuest};
pub use decant_client::{Client, ClientError};
pub use decant_core::{resolve, scan, scan_with_chunk, CoreError, Pattern};

#[cfg(feature = "memflow")]
pub use decant_memflow::MemflowBackend;

pub mod protocol {
    pub use decant_protocol::*;
}

pub mod prelude {
    pub use crate::{
        resolve, scan, Client, MemoryBackend, MockBackend, MockGuest, Pattern, Pid, ProcessInfo,
    };
    #[cfg(feature = "memflow")]
    pub use crate::MemflowBackend;
}
