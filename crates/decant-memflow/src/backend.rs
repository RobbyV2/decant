use std::sync::Mutex;

use decant_backend::{BackendError, MemoryBackend, Result};
use decant_inject::guest::{
    GuestCapabilities, GuestInjectError, GuestMemoryBackend, GuestMemoryRegion, GuestModuleInfo,
    GuestProcessInfo,
};
use decant_protocol::{MemRegion, ModuleInfo, Pid, ProcessInfo};

use memflow::prelude::v1::*;

const PAGE_SIZE: usize = 0x1000;

pub struct MemflowBackend {
    os: Mutex<OsInstanceArcBox<'static>>,
    proc_cache: Mutex<Option<(u32, IntoProcessInstanceArcBox<'static>)>>,
    connector: String,
}

fn other<E: std::fmt::Debug>(e: E) -> BackendError {
    BackendError::Other(format!("memflow: {e:?}"))
}

fn guest_other<E: std::fmt::Display>(e: E) -> GuestInjectError {
    GuestInjectError::Backend(e.to_string())
}

impl MemflowBackend {
    pub fn connect(connector: &str) -> anyhow::Result<Self> {
        let mut inventory = Inventory::scan();
        let connector_args = std::env::var("DECANT_CONNECTOR_ARGS")
            .ok()
            .filter(|s| !s.is_empty());
        let os_args = std::env::var("DECANT_OS_ARGS")
            .ok()
            .filter(|s| !s.is_empty());

        let mut builder = inventory.builder().connector(connector);
        if let Some(a) = connector_args {
            let args: ConnectorArgs = a
                .parse()
                .map_err(|e| anyhow::anyhow!("parsing DECANT_CONNECTOR_ARGS {a:?}: {e:?}"))?;
            builder = builder.args(args);
        }

        let builder = builder.os("win32");
        let os = if let Some(a) = os_args {
            let args: OsArgs = a
                .parse()
                .map_err(|e| anyhow::anyhow!("parsing DECANT_OS_ARGS {a:?}: {e:?}"))?;
            builder.args(args).build()
        } else {
            builder.build()
        }
        .map_err(|e| {
            anyhow::anyhow!(
                "building memflow OS via the {connector:?} connector: {e:?}. Check the {connector} \
                 plugin is in MEMFLOW_PLUGIN_PATH and the VM is running. The qemu connector needs \
                 ptrace access (CAP_SYS_PTRACE on the daemon, or root); the kvm connector needs root \
                 and the memflow kernel module."
            )
        })?;

        Ok(MemflowBackend {
            os: Mutex::new(os),
            proc_cache: Mutex::new(None),
            connector: connector.to_string(),
        })
    }

    pub fn connector(&self) -> &str {
        &self.connector
    }

    // Reuse a resolved process across calls; re-resolving per read makes memflow
    // rebuild the address translation every time and dominates scan latency. Keyed by
    // pid, refreshed when the pid changes.
    fn with_process<R>(
        &self,
        pid: Pid,
        f: impl FnOnce(&mut IntoProcessInstanceArcBox<'static>) -> Result<R>,
    ) -> Result<R> {
        let os = self.os.lock().unwrap();
        let mut cache = self.proc_cache.lock().unwrap();
        if cache.as_ref().map(|(p, _)| *p) != Some(pid.0) {
            let proc =
                os.clone()
                    .into_process_by_pid(pid.0)
                    .map_err(|_| BackendError::NoSuchProcess {
                        pid: Some(pid.0),
                        name: None,
                    })?;
            *cache = Some((pid.0, proc));
        }
        f(&mut cache.as_mut().unwrap().1)
    }

    fn clear_process_cache(&self, pid: Pid) {
        let mut cache = self.proc_cache.lock().unwrap();
        if cache.as_ref().map(|(p, _)| *p) == Some(pid.0) {
            *cache = None;
        }
    }

    fn write_once(&self, pid: Pid, addr: u64, data: &[u8]) -> Result<usize> {
        self.with_process(pid, |proc| {
            proc.write_raw(Address::from(addr), data)
                .map_err(|e| BackendError::WriteFailed {
                    addr,
                    reason: format!("{e:?}"),
                })?;
            Ok(data.len())
        })
    }

    fn write_paged(&self, pid: Pid, addr: u64, data: &[u8]) -> Result<usize> {
        let mut offset = 0usize;
        while offset < data.len() {
            let cur = addr + offset as u64;
            let page_remaining = PAGE_SIZE - (cur as usize & (PAGE_SIZE - 1));
            let chunk_len = page_remaining.min(data.len() - offset);
            self.write_once(pid, cur, &data[offset..offset + chunk_len])?;
            offset += chunk_len;
        }
        Ok(data.len())
    }
}

impl MemoryBackend for MemflowBackend {
    fn list_processes(&self) -> Result<Vec<ProcessInfo>> {
        let mut os = self.os.lock().unwrap();
        let infos = os.process_info_list().map_err(other)?;
        Ok(infos
            .into_iter()
            .map(|i| ProcessInfo {
                pid: Pid(i.pid),
                name: i.name.to_string(),
            })
            .collect())
    }

    fn process_by_pid(&self, pid: Pid) -> Result<ProcessInfo> {
        let mut os = self.os.lock().unwrap();
        match os.process_info_by_pid(pid.0) {
            Ok(i) => Ok(ProcessInfo {
                pid: Pid(i.pid),
                name: i.name.to_string(),
            }),
            Err(_) => Err(BackendError::NoSuchProcess {
                pid: Some(pid.0),
                name: None,
            }),
        }
    }

    fn process_by_name(&self, name: &str) -> Result<ProcessInfo> {
        let mut os = self.os.lock().unwrap();
        match os.process_info_by_name(name) {
            Ok(i) => Ok(ProcessInfo {
                pid: Pid(i.pid),
                name: i.name.to_string(),
            }),
            Err(_) => Err(BackendError::NoSuchProcess {
                pid: None,
                name: Some(name.to_string()),
            }),
        }
    }

    fn module_list(&self, pid: Pid) -> Result<Vec<ModuleInfo>> {
        let mut os = self.os.lock().unwrap();
        let mut proc = os
            .process_by_pid(pid.0)
            .map_err(|_| BackendError::NoSuchProcess {
                pid: Some(pid.0),
                name: None,
            })?;
        let mods = proc.module_list().map_err(other)?;
        Ok(mods.into_iter().map(module_to_info).collect())
    }

    fn module_by_name(&self, pid: Pid, name: &str) -> Result<ModuleInfo> {
        let mut os = self.os.lock().unwrap();
        let mut proc = os
            .process_by_pid(pid.0)
            .map_err(|_| BackendError::NoSuchProcess {
                pid: Some(pid.0),
                name: None,
            })?;
        let m = module_by_name_ci(&mut proc, pid, name)?;
        Ok(module_to_info(m))
    }

    fn module_exports(&self, pid: Pid, module: &str) -> Result<Vec<(String, u64)>> {
        let mut os = self.os.lock().unwrap();
        let mut proc = os
            .process_by_pid(pid.0)
            .map_err(|_| BackendError::NoSuchProcess {
                pid: Some(pid.0),
                name: None,
            })?;
        let m = module_by_name_ci(&mut proc, pid, module)?;
        let exports = proc.module_export_list(&m).map_err(other)?;
        let base = m.base.to_umem();
        Ok(exports
            .into_iter()
            .map(|e| (e.name.to_string(), base + e.offset))
            .collect())
    }

    fn read(&self, pid: Pid, addr: u64, len: usize) -> Result<Vec<u8>> {
        self.with_process(pid, |proc| {
            proc.read_raw(Address::from(addr), len)
                .map_err(|e| BackendError::ReadFailed {
                    addr,
                    len: len as u64,
                    reason: format!("{e:?}"),
                })
        })
    }

    fn write(&self, pid: Pid, addr: u64, data: &[u8]) -> Result<usize> {
        match self.write_once(pid, addr, data) {
            Ok(written) => Ok(written),
            Err(first) => {
                self.clear_process_cache(pid);
                match self.write_once(pid, addr, data) {
                    Ok(written) => Ok(written),
                    Err(second) => {
                        self.clear_process_cache(pid);
                        self.write_paged(pid, addr, data).map_err(|third| {
                            BackendError::WriteFailed {
                                addr,
                                reason: format!(
                                    "{third}; after full-write retry failures: {first}; {second}"
                                ),
                            }
                        })
                    }
                }
            }
        }
    }

    fn memory_map(&self, pid: Pid) -> Result<Vec<MemRegion>> {
        let mut os = self.os.lock().unwrap();
        let mut proc = os
            .process_by_pid(pid.0)
            .map_err(|_| BackendError::NoSuchProcess {
                pid: Some(pid.0),
                name: None,
            })?;
        let ranges = proc.mapped_mem_vec(-1);
        Ok(ranges
            .into_iter()
            .map(
                |CTup3(addr, size, page_type): CTup3<Address, umem, PageType>| MemRegion {
                    base: addr.to_umem(),
                    size,
                    readable: true,
                    writable: page_type.contains(PageType::WRITEABLE),
                    executable: !page_type.contains(PageType::NOEXEC),
                },
            )
            .collect())
    }
}

impl GuestMemoryBackend for MemflowBackend {
    fn capabilities(&self) -> GuestCapabilities {
        GuestCapabilities::memflow_guest_injection()
    }

    fn list_processes(&self) -> std::result::Result<Vec<GuestProcessInfo>, GuestInjectError> {
        <Self as MemoryBackend>::list_processes(self)
            .map(|processes| {
                processes
                    .into_iter()
                    .map(|p| GuestProcessInfo {
                        pid: p.pid.0,
                        name: p.name,
                    })
                    .collect()
            })
            .map_err(guest_other)
    }

    fn module_list(&self, pid: u32) -> std::result::Result<Vec<GuestModuleInfo>, GuestInjectError> {
        <Self as MemoryBackend>::module_list(self, Pid(pid))
            .map(|modules| {
                modules
                    .into_iter()
                    .map(|m| GuestModuleInfo {
                        name: m.name,
                        base: m.base,
                        size: m.size,
                    })
                    .collect()
            })
            .map_err(guest_other)
    }

    fn module_exports(
        &self,
        pid: u32,
        module: &str,
    ) -> std::result::Result<Vec<(String, u64)>, GuestInjectError> {
        <Self as MemoryBackend>::module_exports(self, Pid(pid), module).map_err(guest_other)
    }

    fn memory_map(
        &self,
        pid: u32,
    ) -> std::result::Result<Vec<GuestMemoryRegion>, GuestInjectError> {
        <Self as MemoryBackend>::memory_map(self, Pid(pid))
            .map(|regions| {
                regions
                    .into_iter()
                    .map(|r| GuestMemoryRegion {
                        base: r.base,
                        size: r.size,
                        readable: r.readable,
                        writable: r.writable,
                        executable: r.executable,
                    })
                    .collect()
            })
            .map_err(guest_other)
    }

    fn read(
        &self,
        pid: u32,
        addr: u64,
        len: usize,
    ) -> std::result::Result<Vec<u8>, GuestInjectError> {
        <Self as MemoryBackend>::read(self, Pid(pid), addr, len).map_err(guest_other)
    }

    fn write(&self, pid: u32, addr: u64, data: &[u8]) -> std::result::Result<(), GuestInjectError> {
        <Self as MemoryBackend>::write(self, Pid(pid), addr, data)
            .map(|_| ())
            .map_err(guest_other)
    }
}

fn module_by_name_ci<P: memflow::os::Process + ?Sized>(
    proc: &mut P,
    pid: Pid,
    name: &str,
) -> Result<ModuleInfo_> {
    if let Ok(module) = proc.module_by_name(name) {
        return Ok(module);
    }
    let modules = proc.module_list().map_err(other)?;
    modules
        .into_iter()
        .find(|module| module_matches(module, name))
        .ok_or_else(|| BackendError::NoSuchModule {
            pid: pid.0,
            module: name.to_string(),
        })
}

fn module_matches(module: &ModuleInfo_, name: &str) -> bool {
    let module_name = module.name.to_string();
    if module_name.eq_ignore_ascii_case(name) {
        return true;
    }
    module
        .path
        .to_string()
        .rsplit(['\\', '/'])
        .next()
        .is_some_and(|base| base.eq_ignore_ascii_case(name))
}

fn module_to_info(m: ModuleInfo_) -> ModuleInfo {
    ModuleInfo {
        name: m.name.to_string(),
        base: m.base.to_umem(),
        size: m.size,
    }
}

// aliased to avoid clash with our wire ModuleInfo
use memflow::os::module::ModuleInfo as ModuleInfo_;
