use std::sync::Mutex;

use decant_backend::{BackendError, MemoryBackend, Result};
use decant_protocol::{MemRegion, ModuleInfo, Pid, ProcessInfo};

use memflow::prelude::v1::*;

pub struct MemflowBackend {
    os: Mutex<OsInstanceArcBox<'static>>,
    connector: String,
}

fn other<E: std::fmt::Debug>(e: E) -> BackendError {
    BackendError::Other(format!("memflow: {e:?}"))
}

impl MemflowBackend {
    pub fn connect(connector: &str) -> anyhow::Result<Self> {
        let mut inventory = Inventory::scan();
        let args = std::env::var("DECANT_CONNECTOR_ARGS").ok();

        let os = match args {
            Some(a) => {
                let cargs: ConnectorArgs = a
                    .parse()
                    .map_err(|e| anyhow::anyhow!("parsing DECANT_CONNECTOR_ARGS {a:?}: {e:?}"))?;
                inventory
                    .builder()
                    .connector(connector)
                    .args(cargs)
                    .os("win32")
                    .build()
            }
            None => inventory.builder().connector(connector).os("win32").build(),
        }
        .map_err(|e| {
            anyhow::anyhow!(
                "building memflow OS via connector {connector:?} (is the plugin installed \
                 and the VM running? see ADR-0005): {e:?}"
            )
        })?;

        Ok(MemflowBackend { os: Mutex::new(os), connector: connector.to_string() })
    }

    pub fn connector(&self) -> &str {
        &self.connector
    }
}

impl MemoryBackend for MemflowBackend {
    fn list_processes(&self) -> Result<Vec<ProcessInfo>> {
        let mut os = self.os.lock().unwrap();
        let infos = os.process_info_list().map_err(other)?;
        Ok(infos
            .into_iter()
            .map(|i| ProcessInfo { pid: Pid(i.pid), name: i.name.to_string() })
            .collect())
    }

    fn process_by_pid(&self, pid: Pid) -> Result<ProcessInfo> {
        let mut os = self.os.lock().unwrap();
        match os.process_info_by_pid(pid.0) {
            Ok(i) => Ok(ProcessInfo { pid: Pid(i.pid), name: i.name.to_string() }),
            Err(_) => Err(BackendError::NoSuchProcess { pid: Some(pid.0), name: None }),
        }
    }

    fn process_by_name(&self, name: &str) -> Result<ProcessInfo> {
        let mut os = self.os.lock().unwrap();
        match os.process_info_by_name(name) {
            Ok(i) => Ok(ProcessInfo { pid: Pid(i.pid), name: i.name.to_string() }),
            Err(_) => Err(BackendError::NoSuchProcess { pid: None, name: Some(name.to_string()) }),
        }
    }

    fn module_list(&self, pid: Pid) -> Result<Vec<ModuleInfo>> {
        let mut os = self.os.lock().unwrap();
        let mut proc = os.process_by_pid(pid.0).map_err(|_| BackendError::NoSuchProcess {
            pid: Some(pid.0),
            name: None,
        })?;
        let mods = proc.module_list().map_err(other)?;
        Ok(mods.into_iter().map(module_to_info).collect())
    }

    fn module_by_name(&self, pid: Pid, name: &str) -> Result<ModuleInfo> {
        let mut os = self.os.lock().unwrap();
        let mut proc = os.process_by_pid(pid.0).map_err(|_| BackendError::NoSuchProcess {
            pid: Some(pid.0),
            name: None,
        })?;
        let m = proc
            .module_by_name(name)
            .map_err(|_| BackendError::NoSuchModule { pid: pid.0, module: name.to_string() })?;
        Ok(module_to_info(m))
    }

    fn module_exports(&self, pid: Pid, module: &str) -> Result<Vec<(String, u64)>> {
        let mut os = self.os.lock().unwrap();
        let mut proc = os.process_by_pid(pid.0).map_err(|_| BackendError::NoSuchProcess {
            pid: Some(pid.0),
            name: None,
        })?;
        let m = proc
            .module_by_name(module)
            .map_err(|_| BackendError::NoSuchModule { pid: pid.0, module: module.to_string() })?;
        let exports = proc.module_export_list(&m).map_err(other)?;
        let base = m.base.to_umem() as u64;
        Ok(exports
            .into_iter()
            .map(|e| (e.name.to_string(), base + e.offset as u64))
            .collect())
    }

    fn read(&self, pid: Pid, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut os = self.os.lock().unwrap();
        let mut proc = os.process_by_pid(pid.0).map_err(|_| BackendError::NoSuchProcess {
            pid: Some(pid.0),
            name: None,
        })?;
        proc.read_raw(Address::from(addr), len).map_err(|e| BackendError::ReadFailed {
            addr,
            len: len as u64,
            reason: format!("{e:?}"),
        })
    }

    fn write(&self, pid: Pid, addr: u64, data: &[u8]) -> Result<usize> {
        let mut os = self.os.lock().unwrap();
        let mut proc = os.process_by_pid(pid.0).map_err(|_| BackendError::NoSuchProcess {
            pid: Some(pid.0),
            name: None,
        })?;
        proc.write_raw(Address::from(addr), data)
            .map_err(|e| BackendError::WriteFailed { addr, reason: format!("{e:?}") })?;
        Ok(data.len())
    }

    fn memory_map(&self, pid: Pid) -> Result<Vec<MemRegion>> {
        let mut os = self.os.lock().unwrap();
        let mut proc = os.process_by_pid(pid.0).map_err(|_| BackendError::NoSuchProcess {
            pid: Some(pid.0),
            name: None,
        })?;
        let ranges = proc.mapped_mem_vec(-1);
        Ok(ranges
            .into_iter()
            .map(|CTup3(addr, size, page_type): CTup3<Address, umem, PageType>| MemRegion {
                base: addr.to_umem() as u64,
                size: size as u64,
                readable: true,
                writable: page_type.contains(PageType::WRITEABLE),
                executable: !page_type.contains(PageType::NOEXEC),
            })
            .collect())
    }
}

fn module_to_info(m: ModuleInfo_) -> ModuleInfo {
    ModuleInfo { name: m.name.to_string(), base: m.base.to_umem() as u64, size: m.size as u64 }
}

// aliased to avoid clash with our wire ModuleInfo
use memflow::os::module::ModuleInfo as ModuleInfo_;
