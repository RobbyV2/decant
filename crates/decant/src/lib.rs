pub use decant_backend::{BackendError, MemoryBackend, MockBackend, MockGuest};
pub use decant_client::{Client, ClientError};
pub use decant_core::{CoreError, Pattern, resolve, scan, scan_with_chunk};
pub use decant_protocol::{Diagnostics, MemRegion, ModuleInfo, Pid, ProcessInfo, ProtoError};

#[cfg(feature = "memflow")]
pub use decant_memflow::MemflowBackend;

pub mod protocol {
    pub use decant_protocol::*;
}

pub mod prelude {
    #[cfg(feature = "memflow")]
    pub use crate::MemflowBackend;
    pub use crate::{
        Client, MemoryBackend, MockBackend, MockGuest, Pattern, Pid, ProcessInfo, resolve, scan,
    };
}
