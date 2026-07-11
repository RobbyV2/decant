use std::sync::Mutex;
use std::sync::atomic::AtomicU64;

use decant_backend::{BackendError, MemoryBackend, Result};
use decant_inject::guest::{
    GuestCapabilities, GuestHwbp, GuestIatHook, GuestInjectError, GuestMemoryBackend,
    GuestMemoryRegion, GuestModuleInfo, GuestProcessInfo, GuestTeb, GuestThreadContext,
    GuestThreadInfo, GuestThreadState, MapHandle,
};
use decant_protocol::{
    MemRegion, ModuleInfo, PhysicalMemoryInfo, PhysicalRead, PhysicalWrite, Pid, ProcessInfo,
};

use memflow::prelude::v1::*;

const PAGE_SIZE: usize = 0x1000;

struct MappedRegion {
    id: u64,
    remote_base: u64,
    data: Vec<u8>,
}

static NEXT_MAP_ID: AtomicU64 = AtomicU64::new(1);

fn next_map_id() -> u64 {
    NEXT_MAP_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

pub struct MemflowBackend {
    os: Mutex<OsInstanceArcBox<'static>>,
    proc_cache: Mutex<Option<(u32, IntoProcessInstanceArcBox<'static>)>>,
    kernel_bootstrap_lock: Mutex<()>,
    connector: String,
    mapped_regions: Mutex<Vec<MappedRegion>>,
}

fn other<E: std::fmt::Debug>(e: E) -> BackendError {
    BackendError::Other(format!("memflow: {e:?}"))
}

fn guest_other<E: std::fmt::Display>(e: E) -> GuestInjectError {
    GuestInjectError::Backend(e.to_string())
}

fn vad_vpn_range(base: u64, size: u64) -> std::result::Result<(u64, u64), GuestInjectError> {
    let end = base
        .checked_add(size.max(1) - 1)
        .ok_or_else(|| GuestInjectError::Backend("VAD range overflow".into()))?;
    Ok((base >> 12, end >> 12))
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
            kernel_bootstrap_lock: Mutex::new(()),
            connector: connector.to_string(),
            mapped_regions: Mutex::new(Vec::new()),
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

    fn read_kernel_virtual(
        &self,
        _pid: u32,
        addr: u64,
        len: usize,
    ) -> std::result::Result<Vec<u8>, GuestInjectError> {
        let mut os = self.os.lock().unwrap();
        let view = as_mut!(&mut *os impl MemoryView).ok_or_else(|| {
            GuestInjectError::Backend("memflow OS has no kernel memory view".into())
        })?;
        view.read_raw(Address::from(addr), len)
            .map_err(|e| BackendError::ReadFailed {
                addr,
                len: len as u64,
                reason: format!("kernel read {addr:#x}+{len:#x}: {e:?}"),
            })
            .map_err(guest_other)
    }

    fn write_kernel_virtual(
        &self,
        _pid: u32,
        addr: u64,
        data: &[u8],
    ) -> std::result::Result<(), GuestInjectError> {
        let mut os = self.os.lock().unwrap();
        let view = as_mut!(&mut *os impl MemoryView).ok_or_else(|| {
            GuestInjectError::Backend("memflow OS has no kernel memory view".into())
        })?;
        view.write_raw(Address::from(addr), data)
            .map_err(|e| BackendError::WriteFailed {
                addr,
                reason: format!("kernel write {addr:#x}+{:#x}: {e:?}", data.len()),
            })
            .map(|_| ())
            .map_err(guest_other)
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

    fn physical_memory_info(&self) -> Result<PhysicalMemoryInfo> {
        let mut os = self.os.lock().unwrap();
        let physical =
            as_mut!(&mut *os impl PhysicalMemory).ok_or_else(|| BackendError::Unsupported {
                op: "memflow OS raw physical-memory access".into(),
            })?;
        let metadata = physical.metadata();
        Ok(PhysicalMemoryInfo {
            max_address: metadata.max_address.to_umem(),
            real_size: metadata.real_size,
            readonly: metadata.readonly,
            ideal_batch_size: metadata.ideal_batch_size,
        })
    }

    fn read_physical(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        let mut os = self.os.lock().unwrap();
        let physical =
            as_mut!(&mut *os impl PhysicalMemory).ok_or_else(|| BackendError::Unsupported {
                op: "memflow OS raw physical-memory access".into(),
            })?;
        physical
            .phys_view()
            .read_raw(Address::from(address), length)
            .map_err(|e| BackendError::ReadFailed {
                addr: address,
                len: length as u64,
                reason: format!("physical: {e:?}"),
            })
    }

    fn write_physical(&self, address: u64, data: &[u8]) -> Result<usize> {
        let mut os = self.os.lock().unwrap();
        let physical =
            as_mut!(&mut *os impl PhysicalMemory).ok_or_else(|| BackendError::Unsupported {
                op: "memflow OS raw physical-memory access".into(),
            })?;
        physical
            .phys_view()
            .write_raw(Address::from(address), data)
            .map_err(|e| BackendError::WriteFailed {
                addr: address,
                reason: format!("physical: {e:?}"),
            })?;
        Ok(data.len())
    }

    fn read_physical_scatter(&self, ranges: &[PhysicalRead]) -> Vec<Option<Vec<u8>>> {
        let mut os = self.os.lock().unwrap();
        let Some(physical) = as_mut!(&mut *os impl PhysicalMemory) else {
            return vec![None; ranges.len()];
        };
        let mut view = physical.phys_view();
        ranges
            .iter()
            .map(|range| {
                view.read_raw(Address::from(range.address), range.length as usize)
                    .ok()
            })
            .collect()
    }

    fn write_physical_scatter(&self, ranges: &[PhysicalWrite]) -> Vec<bool> {
        let mut os = self.os.lock().unwrap();
        let Some(physical) = as_mut!(&mut *os impl PhysicalMemory) else {
            return vec![false; ranges.len()];
        };
        let mut view = physical.phys_view();
        ranges
            .iter()
            .map(|range| {
                view.write_raw(Address::from(range.address), &range.data)
                    .is_ok()
            })
            .collect()
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

    fn call_iat_hook(
        &self,
        pid: u32,
        _hook: &GuestIatHook,
        function: u64,
        args: &[u64],
        timeout_ms: u32,
    ) -> std::result::Result<u64, GuestInjectError> {
        self.call_via_kernel_bootstrap(pid, function, args, timeout_ms)
    }

    fn touch_iat_hook(
        &self,
        _pid: u32,
        _hook: &GuestIatHook,
        addr: u64,
        len: usize,
        _timeout_ms: u32,
    ) -> std::result::Result<(), GuestInjectError> {
        let zero = vec![0u8; len];
        <Self as MemoryBackend>::write(self, Pid(_pid), addr, &zero)
            .map(|_| ())
            .map_err(guest_other)
    }

    fn read_touch_iat_hook(
        &self,
        _pid: u32,
        _hook: &GuestIatHook,
        addr: u64,
        len: usize,
        _timeout_ms: u32,
    ) -> std::result::Result<(), GuestInjectError> {
        <Self as MemoryBackend>::read(self, Pid(_pid), addr, len)
            .map(|_| ())
            .map_err(guest_other)
    }

    fn preserve_touch_iat_hook(
        &self,
        _pid: u32,
        _hook: &GuestIatHook,
        addr: u64,
        len: usize,
        _timeout_ms: u32,
    ) -> std::result::Result<(), GuestInjectError> {
        let data =
            <Self as MemoryBackend>::read(self, Pid(_pid), addr, len).map_err(guest_other)?;
        <Self as MemoryBackend>::write(self, Pid(_pid), addr, &data)
            .map(|_| ())
            .map_err(guest_other)
    }

    fn spoof_vad_type(
        &self,
        pid: u32,
        base: u64,
        size: u64,
    ) -> std::result::Result<(), GuestInjectError> {
        let eprocess = {
            let mut os = self.os.lock().unwrap();
            let proc_info = os
                .process_info_by_pid(pid)
                .map_err(|_| GuestInjectError::Backend(format!("pid {pid} not found")))?;
            if proc_info.address.is_null() {
                return Err(GuestInjectError::Backend(
                    "VAD spoof: EPROCESS address is null".into(),
                ));
            }
            proc_info.address.to_umem()
        };
        let (target_start_vpn, target_end_vpn) = vad_vpn_range(base, size)?;
        let mut vad_root = 0u64;
        for &off in &[2008usize, 1624usize] {
            let Ok(bytes) = self.read_kernel_virtual(pid, eprocess + off as u64, 8) else {
                continue;
            };
            let candidate = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
            if candidate != 0 {
                vad_root = candidate;
                break;
            }
        }
        if vad_root == 0 {
            return Err(GuestInjectError::Backend(
                "VAD spoof: VadRoot not found at known offsets".into(),
            ));
        }
        let mut current = vad_root;
        for _ in 0..512 {
            if current == 0 {
                break;
            }
            let node_bytes = self.read_kernel_virtual(pid, current, 64)?;
            let start_vpn = u32::from_le_bytes(node_bytes[24..28].try_into().unwrap()) as u64
                | ((node_bytes[32] as u64) << 32);
            let end_vpn = u32::from_le_bytes(node_bytes[28..32].try_into().unwrap()) as u64
                | ((node_bytes[33] as u64) << 32);
            if target_start_vpn >= start_vpn && target_end_vpn <= end_vpn {
                let u_bytes = self.read_kernel_virtual(pid, current + 48, 8)?;
                let mut u_val = u64::from_le_bytes(u_bytes[0..8].try_into().unwrap());
                let old_type = u_val & 0x7;
                u_val = (u_val & !0x7) | 0x3;
                self.write_kernel_virtual(pid, current + 48, &u_val.to_le_bytes())?;
                tracing::info!(
                    pid,
                    eprocess = format_args!("{eprocess:#x}"),
                    vad_node = format_args!("{current:#x}"),
                    old_vad_type = old_type,
                    "VAD spoof: changed VadType to VadImageMap"
                );
                return Ok(());
            }
            let left = u64::from_le_bytes(node_bytes[8..16].try_into().unwrap());
            let right = u64::from_le_bytes(node_bytes[16..24].try_into().unwrap());
            current = if target_start_vpn < start_vpn {
                left
            } else {
                right
            };
        }
        Err(GuestInjectError::Backend(format!(
            "VAD spoof: no MMVAD covers {base:#x}+{size:#x}"
        )))
    }

    fn configure_va_protection(
        &self,
        pid: u32,
        base: u64,
        size: u64,
        protection: u32,
    ) -> std::result::Result<(), GuestInjectError> {
        let eprocess = {
            let mut os = self.os.lock().unwrap();
            let proc_info = os
                .process_info_by_pid(pid)
                .map_err(|_| GuestInjectError::Backend(format!("pid {pid} not found")))?;
            if proc_info.address.is_null() {
                return Err(GuestInjectError::Backend(
                    "VAD protect: EPROCESS address is null".into(),
                ));
            }
            proc_info.address.to_umem()
        };
        let (target_start_vpn, target_end_vpn) = vad_vpn_range(base, size)?;
        let mut vad_root = 0u64;
        for &off in &[2008usize, 1624usize] {
            let Ok(bytes) = self.read_kernel_virtual(pid, eprocess + off as u64, 8) else {
                continue;
            };
            let candidate = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
            if candidate != 0 {
                vad_root = candidate;
                break;
            }
        }
        if vad_root == 0 {
            return Err(GuestInjectError::Backend(
                "VAD protect: VadRoot not found at known offsets".into(),
            ));
        }
        let mut current = vad_root;
        for _ in 0..512 {
            if current == 0 {
                break;
            }
            let node_bytes = self.read_kernel_virtual(pid, current, 64)?;
            let start_vpn = u32::from_le_bytes(node_bytes[24..28].try_into().unwrap()) as u64
                | ((node_bytes[32] as u64) << 32);
            let end_vpn = u32::from_le_bytes(node_bytes[28..32].try_into().unwrap()) as u64
                | ((node_bytes[33] as u64) << 32);
            if target_start_vpn >= start_vpn && target_end_vpn <= end_vpn {
                let u_bytes = self.read_kernel_virtual(pid, current + 48, 8)?;
                let mut u_val = u64::from_le_bytes(u_bytes[0..8].try_into().unwrap());
                let protection_mask: u64 = 0x1F << 7;
                let old_protection = (u_val >> 7) & 0x1F;
                u_val = (u_val & !protection_mask) | ((protection as u64 & 0x1F) << 7);
                self.write_kernel_virtual(pid, current + 48, &u_val.to_le_bytes())?;
                tracing::info!(
                    pid,
                    eprocess = format_args!("{eprocess:#x}"),
                    vad_node = format_args!("{current:#x}"),
                    old_protection,
                    new_protection = protection,
                    "VAD protect: changed MMVAD.u.Protection"
                );
                return Ok(());
            }
            let left = u64::from_le_bytes(node_bytes[8..16].try_into().unwrap());
            let right = u64::from_le_bytes(node_bytes[16..24].try_into().unwrap());
            current = if target_start_vpn < start_vpn {
                left
            } else {
                right
            };
        }
        Err(GuestInjectError::Backend(format!(
            "VAD protect: no MMVAD covers {base:#x}+{size:#x}"
        )))
    }

    fn patch_entry_point(
        &self,
        pid: u32,
        module_base: u64,
        new_entry: u64,
    ) -> std::result::Result<(), GuestInjectError> {
        let header = GuestMemoryBackend::read(self, pid, module_base, 0x40)?;
        if header.len() < 0x40 || u16::from_le_bytes([header[0], header[1]]) != 0x5A4D {
            return Err(GuestInjectError::Image(format!(
                "module at {module_base:#x} has no MZ header"
            )));
        }
        let nt_off =
            u32::from_le_bytes([header[0x3C], header[0x3D], header[0x3E], header[0x3F]]) as u64;
        if nt_off == 0 || nt_off > 0x400 {
            return Err(GuestInjectError::Image(format!(
                "invalid NT header offset {nt_off:#x} at module {module_base:#x}"
            )));
        }
        let entry_point_field = module_base + nt_off + 40;
        let current = GuestMemoryBackend::read(self, pid, entry_point_field, 4)?;
        if current.len() < 4 {
            return Err(GuestInjectError::Image(format!(
                "short read at entry point field {entry_point_field:#x}"
            )));
        }
        let old_rva = u32::from_le_bytes([current[0], current[1], current[2], current[3]]);
        let new_rva = (new_entry - module_base) as u32;
        GuestMemoryBackend::write(self, pid, entry_point_field, &new_rva.to_le_bytes())?;
        tracing::info!(
            pid,
            module_base = format_args!("{module_base:#x}"),
            old_entry_rva = format_args!("{old_rva:#x}"),
            new_entry_rva = format_args!("{new_rva:#x}"),
            "patched PE AddressOfEntryPoint"
        );
        Ok(())
    }

    fn list_threads(
        &self,
        pid: u32,
    ) -> std::result::Result<Vec<GuestThreadInfo>, GuestInjectError> {
        walk_threads(self, pid, |ethread, teb, start_addr, state| {
            Ok::<GuestThreadInfo, GuestInjectError>(GuestThreadInfo {
                tid: ethread.tid,
                teb,
                start_address: start_addr,
                state,
            })
        })
    }

    fn read_teb(&self, pid: u32, tid: u32) -> std::result::Result<GuestTeb, GuestInjectError> {
        let ethread = find_ethread_by_tid(self, pid, tid)?;
        let teb_va = ethread.teb;
        if teb_va == 0 {
            return Err(GuestInjectError::Backend(format!(
                "tid {tid} has null TEB pointer"
            )));
        }
        let buf = GuestMemoryBackend::read(self, pid, teb_va, 0x80)?;
        let exception_list = u64::from_le_bytes(buf[0x00..0x08].try_into().unwrap());
        let stack_base = u64::from_le_bytes(buf[0x08..0x10].try_into().unwrap());
        let stack_limit = u64::from_le_bytes(buf[0x10..0x18].try_into().unwrap());
        let arbitrary_user_pointer = u64::from_le_bytes(buf[0x28..0x30].try_into().unwrap());
        let last_error_value = u32::from_le_bytes(buf[0x68..0x6c].try_into().unwrap());
        let tls_array = GuestMemoryBackend::read(self, pid, teb_va + 0x1480, 8)
            .ok()
            .and_then(|tls_buf| tls_buf.get(0..8).and_then(|b| b.try_into().ok()))
            .map(u64::from_le_bytes)
            .unwrap_or(0);
        Ok(GuestTeb {
            base: teb_va,
            exception_list,
            stack_base,
            stack_limit,
            arbitrary_user_pointer,
            tls_array,
            last_error_value,
        })
    }

    fn suspend_thread(
        &self,
        pid: u32,
        tid: u32,
        hook: &GuestIatHook,
        timeout_ms: u32,
    ) -> std::result::Result<(), GuestInjectError> {
        decant_inject::guest::guest_suspend_thread(self, pid, tid, hook, timeout_ms)
    }

    fn resume_thread(
        &self,
        pid: u32,
        tid: u32,
        hook: &GuestIatHook,
        timeout_ms: u32,
    ) -> std::result::Result<(), GuestInjectError> {
        decant_inject::guest::guest_resume_thread(self, pid, tid, hook, timeout_ms)
    }

    fn get_thread_context(
        &self,
        pid: u32,
        tid: u32,
        hook: &GuestIatHook,
        timeout_ms: u32,
    ) -> std::result::Result<GuestThreadContext, GuestInjectError> {
        decant_inject::guest::guest_get_thread_context(self, pid, tid, hook, timeout_ms)
    }

    fn set_thread_context(
        &self,
        pid: u32,
        tid: u32,
        ctx: &GuestThreadContext,
        hook: &GuestIatHook,
        timeout_ms: u32,
    ) -> std::result::Result<(), GuestInjectError> {
        decant_inject::guest::guest_set_thread_context(self, pid, tid, ctx, hook, timeout_ms)
    }

    fn terminate_thread(
        &self,
        pid: u32,
        tid: u32,
        exit_code: u32,
        hook: &GuestIatHook,
        timeout_ms: u32,
    ) -> std::result::Result<(), GuestInjectError> {
        decant_inject::guest::guest_terminate_thread(self, pid, tid, exit_code, hook, timeout_ms)
    }

    fn add_hwbp(
        &self,
        pid: u32,
        tid: u32,
        bp: GuestHwbp,
        hook: &GuestIatHook,
        timeout_ms: u32,
    ) -> std::result::Result<u8, GuestInjectError> {
        decant_inject::guest::guest_add_hwbp(self, pid, tid, bp, hook, timeout_ms)
    }

    fn remove_hwbp(
        &self,
        pid: u32,
        tid: u32,
        index: u8,
        hook: &GuestIatHook,
        timeout_ms: u32,
    ) -> std::result::Result<(), GuestInjectError> {
        decant_inject::guest::guest_remove_hwbp(self, pid, tid, index, hook, timeout_ms)
    }

    fn map_remote_region(
        &self,
        pid: u32,
        base: u64,
        size: u64,
    ) -> std::result::Result<MapHandle, GuestInjectError> {
        let bytes = <Self as MemoryBackend>::read(self, Pid(pid), base, size as usize)
            .map_err(guest_other)?;
        let mut cache = self.mapped_regions.lock().unwrap();
        let id = next_map_id();
        cache.push(MappedRegion {
            id,
            remote_base: base,
            data: bytes,
        });
        tracing::info!(
            pid,
            base = format_args!("{base:#x}"),
            size,
            "remote region mapped to local cache"
        );
        Ok(MapHandle(id))
    }

    fn translate_address(
        &self,
        map: MapHandle,
        remote_addr: u64,
    ) -> std::result::Result<usize, GuestInjectError> {
        let cache = self.mapped_regions.lock().unwrap();
        let region = cache
            .iter()
            .find(|r| r.id == map.0)
            .ok_or_else(|| GuestInjectError::Backend("invalid map handle".into()))?;
        let offset = (remote_addr as i64 - region.remote_base as i64) as usize;
        if offset >= region.data.len() {
            return Err(GuestInjectError::Backend(format!(
                "address {remote_addr:#x} is outside mapped region starting at {:#x}",
                region.remote_base
            )));
        }
        Ok(offset)
    }

    fn unmap_remote_region(&self, map: MapHandle) -> std::result::Result<(), GuestInjectError> {
        let mut cache = self.mapped_regions.lock().unwrap();
        let before = cache.len();
        cache.retain(|r| r.id != map.0);
        if cache.len() == before {
            return Err(GuestInjectError::Backend("invalid map handle".into()));
        }
        tracing::info!(map_id = map.0, "remote region unmapped");
        Ok(())
    }

    fn resolve_loader_symbol(
        &self,
        pid: u32,
        symbol_name: &str,
    ) -> std::result::Result<u64, GuestInjectError> {
        resolve_ntdll_symbol(self, pid, symbol_name)
    }
}

fn module_by_name_ci<P: memflow::os::Process + ?Sized>(
    proc: &mut P,
    pid: Pid,
    name: &str,
) -> Result<ModuleInfo_> {
    // `module_by_name` is case-sensitive.  More importantly, the win32
    // plugin does not reliably support a second module-list traversal on the
    // same process object after that failed lookup.  Use the trait's
    // case-insensitive helper for the common path, then retain the path-name
    // fallback for unusual loader entries.
    if let Ok(module) = proc.module_by_name_ignore_ascii_case(name) {
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

// Win10 19041+ x64 and Win10 18362 x64 offsets for the kernel structures
// reached by guest thread enumeration. Probed in order; the first set that
// yields a Cid.UniqueProcess matching the requested pid is used.
struct WinOffset {
    eproc_thread_list: usize,
    ethread_list_entry: usize,
    kthread_teb: usize,
    ethread_cid: usize,
    ethread_start_address: usize,
    kthread_state: usize,
    kthread_trap_frame: usize,
    ktrap_frame_rip: usize,
    ktrap_frame_cs: usize,
}

const WIN_OFFSETS: &[WinOffset] = &[
    // Win10 19041+ x64
    WinOffset {
        eproc_thread_list: 1504,
        ethread_list_entry: 1256,
        kthread_teb: 240,
        ethread_cid: 0x478,
        ethread_start_address: 0x6F0,
        kthread_state: 0x164,
        kthread_trap_frame: 0x90,
        ktrap_frame_rip: 0x168,
        ktrap_frame_cs: 0x170,
    },
    // Win10 18362 x64
    WinOffset {
        eproc_thread_list: 1160,
        ethread_list_entry: 1720,
        kthread_teb: 240,
        ethread_cid: 0x478,
        ethread_start_address: 0x6F0,
        kthread_state: 0x163,
        kthread_trap_frame: 0x90,
        ktrap_frame_rip: 0x168,
        ktrap_frame_cs: 0x170,
    },
];

struct EthreadSummary {
    pub ethread_base: u64,
    pub tid: u32,
    pub teb: u64,
    pub start_address: u64,
    pub state: GuestThreadState,
}

#[derive(Clone, Copy)]
struct KernelHijackCandidate {
    rip_addr: u64,
    original_rip: u64,
    ethread_base: u64,
    tid: u32,
    state: GuestThreadState,
}

fn kernel_hijack_priority(state: GuestThreadState) -> u8 {
    match state {
        GuestThreadState::Running => 0,
        GuestThreadState::Ready | GuestThreadState::Standby | GuestThreadState::DeferredReady => 1,
        GuestThreadState::Transition => 2,
        GuestThreadState::Waiting => 3,
        GuestThreadState::Initialized | GuestThreadState::Other(_) => 4,
        GuestThreadState::Terminated => u8::MAX,
    }
}

fn read_u64_at(
    backend: &MemflowBackend,
    pid: u32,
    addr: u64,
) -> std::result::Result<u64, GuestInjectError> {
    let bytes = backend.read_kernel_virtual(pid, addr, 8)?;
    Ok(u64::from_le_bytes(bytes[0..8].try_into().unwrap()))
}

fn read_u32_at(
    backend: &MemflowBackend,
    pid: u32,
    addr: u64,
) -> std::result::Result<u32, GuestInjectError> {
    let bytes = backend.read_kernel_virtual(pid, addr, 4)?;
    Ok(u32::from_le_bytes(bytes[0..4].try_into().unwrap()))
}

fn read_u8_at(
    backend: &MemflowBackend,
    pid: u32,
    addr: u64,
) -> std::result::Result<u8, GuestInjectError> {
    let bytes = backend.read_kernel_virtual(pid, addr, 1)?;
    Ok(bytes[0])
}

fn probe_thread_offsets(
    backend: &MemflowBackend,
    eprocess: u64,
    pid: u32,
) -> std::result::Result<&'static WinOffset, GuestInjectError> {
    for off in WIN_OFFSETS {
        let head_flink = match read_u64_at(backend, pid, eprocess + off.eproc_thread_list as u64) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if head_flink == 0 || head_flink == eprocess + off.eproc_thread_list as u64 {
            continue;
        }
        let first_ethread = head_flink - off.ethread_list_entry as u64;
        let first_proc = match read_u32_at(backend, pid, first_ethread + off.ethread_cid as u64) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if first_proc == pid {
            return Ok(off);
        }
    }
    Err(GuestInjectError::Backend(format!(
        "thread enumeration: no offset table matched pid {pid} on EPROCESS {eprocess:#x}"
    )))
}

fn walk_threads<F, R>(
    backend: &MemflowBackend,
    pid: u32,
    mut emit: F,
) -> std::result::Result<Vec<R>, GuestInjectError>
where
    F: FnMut(
        EthreadSummary,
        u64,
        u64,
        GuestThreadState,
    ) -> std::result::Result<R, GuestInjectError>,
{
    let eprocess = {
        let mut os = backend.os.lock().unwrap();
        let proc_info = os
            .process_info_by_pid(pid)
            .map_err(|_| GuestInjectError::Backend(format!("pid {pid} not found")))?;
        if proc_info.address.is_null() {
            return Err(GuestInjectError::Backend("EPROCESS address is null".into()));
        }
        proc_info.address.to_umem()
    };
    let off = probe_thread_offsets(backend, eprocess, pid)?;
    let head = eprocess + off.eproc_thread_list as u64;
    let mut cursor = read_u64_at(backend, pid, head)?;
    if cursor == 0 {
        return Err(GuestInjectError::Backend(
            "EPROCESS.ThreadListHead.Flink is null".into(),
        ));
    }
    let mut out = Vec::new();
    for _ in 0..4096 {
        if cursor == 0 || cursor == head {
            break;
        }
        let ethread_base = cursor - off.ethread_list_entry as u64;
        let proc_id = read_u32_at(backend, pid, ethread_base + off.ethread_cid as u64)?;
        let tid = read_u32_at(backend, pid, ethread_base + off.ethread_cid as u64 + 8)?;
        let teb = read_u64_at(backend, pid, ethread_base + off.kthread_teb as u64)?;
        let start_address = read_u64_at(
            backend,
            pid,
            ethread_base + off.ethread_start_address as u64,
        )
        .unwrap_or(0);
        let state_byte =
            read_u8_at(backend, pid, ethread_base + off.kthread_state as u64).unwrap_or(0);
        let state = GuestThreadState::from(state_byte);
        if proc_id != pid {
            cursor = read_u64_at(backend, pid, cursor)?;
            continue;
        }
        let summary = EthreadSummary {
            ethread_base,
            tid,
            teb,
            start_address,
            state,
        };
        out.push(emit(summary, teb, start_address, state)?);
        cursor = read_u64_at(backend, pid, cursor)?;
    }
    Ok(out)
}

fn find_ethread_by_tid(
    backend: &MemflowBackend,
    pid: u32,
    tid: u32,
) -> std::result::Result<EthreadSummary, GuestInjectError> {
    let mut found = None;
    walk_threads(backend, pid, |summary, _teb, _start, _state| {
        if summary.tid == tid {
            found = Some(summary);
        }
        Ok(())
    })?;
    found.ok_or_else(|| GuestInjectError::Backend(format!("tid {tid} not found in pid {pid}")))
}

fn resolve_ntdll_symbol(
    backend: &MemflowBackend,
    pid: u32,
    name: &str,
) -> std::result::Result<u64, GuestInjectError> {
    let exports = <MemflowBackend as MemoryBackend>::module_exports(backend, Pid(pid), "ntdll.dll")
        .map_err(guest_other)?;
    for (export_name, addr) in &exports {
        if export_name.eq_ignore_ascii_case(name) {
            return Ok(*addr);
        }
    }
    match name {
        "LdrpHandleTlsData" => {
            let ntdll_base =
                <MemflowBackend as MemoryBackend>::module_by_name(backend, Pid(pid), "ntdll.dll")
                    .map_err(guest_other)?;
            let size = ntdll_base.size as usize;
            let text = <MemflowBackend as MemoryBackend>::read(
                backend,
                Pid(pid),
                ntdll_base.base,
                size.min(0x10_0000),
            )
            .map_err(guest_other)?;
            let patterns: &[&[u8]] = &[
                &[0x74, 0x33, 0x44, 0x8D, 0x43, 0x09],
                &[0x44, 0x8D, 0x43, 0x09, 0x4C, 0x8D, 0x4C, 0x24, 0x38],
            ];
            for pat in patterns {
                if let Some(pos) = find_pattern(&text, pat) {
                    let addr = ntdll_base.base + pos as u64;
                    tracing::info!(
                        pid,
                        symbol = name,
                        addr = format_args!("{addr:#x}"),
                        "resolved via pattern scan"
                    );
                    return Ok(addr);
                }
            }
            Err(GuestInjectError::Backend(format!(
                "could not resolve {name} via export table or pattern scan"
            )))
        }
        _ => Err(GuestInjectError::Backend(format!(
            "symbol {name} not found in ntdll exports or known patterns"
        ))),
    }
}

fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

const USER_MODE_CS: u16 = 0x33;
const LOWEST_USER_ADDRESS: u64 = 0x1_0000;
const FIRST_KERNEL_ADDRESS: u64 = 0x0000_8000_0000_0000;

const KERNEL_BOOTSTRAP_PATCH_LEN: usize = 5;
const KERNEL_BOOTSTRAP_STAGE_OFFSET: u64 = 0x80;
const KERNEL_BOOTSTRAP_MIN_CAVE_SIZE: usize = 0x800;
const KERNEL_BOOTSTRAP_STATE_OFFSET: u64 = 0;
const KERNEL_BOOTSTRAP_STATUS_OFFSET: u64 = 8;
const KERNEL_BOOTSTRAP_USER_BASE_OFFSET: u64 = 0x10;
const KERNEL_BOOTSTRAP_USER_BLOB_OFFSET: u64 = 0x600;

struct KernelBootstrapExports {
    module_base: u64,
    module_size: u64,
    hook: u64,
    zw_open_process: u64,
    zw_allocate_virtual_memory: u64,
    zw_write_virtual_memory: u64,
    zw_set_information_virtual_memory: u64,
    rtl_create_user_thread: u64,
    zw_close: u64,
}

fn trap_frame_registers(
    trap_frame: &[u8],
    rip_offset: usize,
    cs_offset: usize,
) -> Option<(u64, u16)> {
    let rip = u64::from_le_bytes(
        trap_frame
            .get(rip_offset..rip_offset.checked_add(8)?)?
            .try_into()
            .ok()?,
    );
    let cs = u16::from_le_bytes(
        trap_frame
            .get(cs_offset..cs_offset.checked_add(2)?)?
            .try_into()
            .ok()?,
    );
    Some((rip, cs))
}

fn address_is_in_module(addr: u64, modules: &[ModuleInfo]) -> bool {
    modules.iter().any(|module| {
        module
            .base
            .checked_add(module.size)
            .is_some_and(|end| module.base <= addr && addr < end)
    })
}

fn kernel_export_by_name(
    exports: &[(String, u64)],
    name: &str,
) -> std::result::Result<u64, GuestInjectError> {
    exports
        .iter()
        .find(|(export, _)| export.eq_ignore_ascii_case(name))
        .map(|(_, address)| *address)
        .ok_or_else(|| GuestInjectError::Backend(format!("kernel export {name} not found")))
}

impl MemflowBackend {
    fn call_via_kernel_bootstrap(
        &self,
        pid: u32,
        function: u64,
        args: &[u64],
        timeout_ms: u32,
    ) -> std::result::Result<u64, GuestInjectError> {
        if args.len() > 8 {
            return Err(GuestInjectError::Backend(format!(
                "kernel bootstrap supports at most eight call arguments, received {}",
                args.len()
            )));
        }
        let _bootstrap_guard = self.kernel_bootstrap_lock.lock().unwrap();
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64);

        let user_shellcode = build_kernel_bootstrap_user_shellcode(function, args);
        if user_shellcode.len() + KERNEL_BOOTSTRAP_STAGE_OFFSET as usize > 0x200 {
            return Err(GuestInjectError::Backend(format!(
                "kernel bootstrap user shellcode is too large: {:#x} bytes",
                user_shellcode.len()
            )));
        }

        let kernel = self.resolve_kernel_bootstrap_exports()?;
        let kernel_cave = find_kernel_bootstrap_cave(self, pid, &kernel)?;
        let state_addr = kernel_cave + KERNEL_BOOTSTRAP_STATE_OFFSET;
        let status_addr = kernel_cave + KERNEL_BOOTSTRAP_STATUS_OFFSET;
        let user_base_addr = kernel_cave + KERNEL_BOOTSTRAP_USER_BASE_OFFSET;
        let stage_addr = kernel_cave + KERNEL_BOOTSTRAP_STAGE_OFFSET;
        let user_blob_addr = kernel_cave + KERNEL_BOOTSTRAP_USER_BLOB_OFFSET;
        let stage = build_kernel_bootstrap_stage(
            state_addr,
            status_addr,
            user_base_addr,
            kernel.hook,
            pid,
            user_blob_addr,
            user_shellcode.len(),
            &kernel,
        );
        if stage.len() + KERNEL_BOOTSTRAP_STAGE_OFFSET as usize
            > KERNEL_BOOTSTRAP_USER_BLOB_OFFSET as usize
        {
            return Err(GuestInjectError::Backend(format!(
                "kernel bootstrap stage is too large for its code cave: {:#x} bytes",
                stage.len() + KERNEL_BOOTSTRAP_STAGE_OFFSET as usize
            )));
        }
        self.write_kernel_virtual(pid, state_addr, &0u64.to_le_bytes())?;
        self.write_kernel_virtual(pid, status_addr, &0u64.to_le_bytes())?;
        self.write_kernel_virtual(pid, user_base_addr, &0u64.to_le_bytes())?;
        self.write_kernel_virtual(pid, stage_addr, &stage)?;
        self.write_kernel_virtual(pid, user_blob_addr, &user_shellcode)?;

        let original_hook =
            self.read_kernel_virtual(pid, kernel.hook, KERNEL_BOOTSTRAP_PATCH_LEN)?;
        let relative_stage = i128::from(stage_addr) - i128::from(kernel.hook + 5);
        let relative_stage = i32::try_from(relative_stage).map_err(|_| {
            GuestInjectError::Backend(format!(
                "kernel bootstrap code cave at {stage_addr:#x} is outside the hook jump range"
            ))
        })?;
        let mut hook_patch = vec![0xE9]; // jmp rel32
        hook_patch.extend_from_slice(&relative_stage.to_le_bytes());
        self.write_kernel_virtual(pid, kernel.hook, &hook_patch)?;
        tracing::info!(
            pid,
            hook = format_args!("{:#x}", kernel.hook),
            kernel_cave = format_args!("{kernel_cave:#x}"),
            user_shellcode_len = user_shellcode.len(),
            "kernel bootstrap hook armed"
        );

        let mut restored = false;
        let kernel_status = loop {
            let state = match read_u64_at(self, pid, state_addr) {
                Ok(state) => state,
                Err(error) => {
                    let _ = self.write_kernel_virtual(pid, kernel.hook, &original_hook);
                    let _ = self.write_kernel_virtual(pid, state_addr, &2u64.to_le_bytes());
                    return Err(error);
                }
            };
            if !restored && state >= 1 {
                self.write_kernel_virtual(pid, kernel.hook, &original_hook)?;
                self.write_kernel_virtual(pid, state_addr, &2u64.to_le_bytes())?;
                restored = true;
                tracing::debug!(pid, state, "kernel bootstrap hook restored after entry");
            }
            if state >= 3 {
                break read_u64_at(self, pid, status_addr)?;
            }
            if std::time::Instant::now() >= deadline {
                if !restored {
                    let _ = self.write_kernel_virtual(pid, kernel.hook, &original_hook);
                    let _ = self.write_kernel_virtual(pid, state_addr, &2u64.to_le_bytes());
                }
                return Err(GuestInjectError::Backend(format!(
                    "kernel bootstrap hook did not create a target user thread after {timeout_ms} ms"
                )));
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        };

        if kernel_status & (1u64 << 63) != 0 {
            return Err(GuestInjectError::Backend(format!(
                "RtlCreateUserThread kernel bootstrap failed with NTSTATUS {kernel_status:#x}"
            )));
        }

        let user_base = read_u64_at(self, pid, user_base_addr)?;
        if user_base < LOWEST_USER_ADDRESS || user_base >= FIRST_KERNEL_ADDRESS {
            return Err(GuestInjectError::Backend(format!(
                "kernel bootstrap returned an invalid target allocation base {user_base:#x}"
            )));
        }

        loop {
            let flag_bytes =
                <Self as decant_inject::guest::GuestMemoryBackend>::read(self, pid, user_base, 8)?;
            let flag = u64::from_le_bytes(flag_bytes[0..8].try_into().unwrap());
            if flag == 2 {
                let result_bytes = <Self as decant_inject::guest::GuestMemoryBackend>::read(
                    self,
                    pid,
                    user_base + 8,
                    8,
                )?;
                return Ok(u64::from_le_bytes(result_bytes[0..8].try_into().unwrap()));
            }
            if std::time::Instant::now() >= deadline {
                return Err(GuestInjectError::Backend(format!(
                    "kernel bootstrap created a user thread but its call stub {} after {timeout_ms} ms",
                    if flag == 1 {
                        "entered without completing"
                    } else {
                        "was not entered"
                    }
                )));
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    fn resolve_kernel_bootstrap_exports(
        &self,
    ) -> std::result::Result<KernelBootstrapExports, GuestInjectError> {
        let mut os = self.os.lock().unwrap();
        let module = ["ntoskrnl.exe", "ntkrnlmp.exe"]
            .iter()
            .find_map(|name| os.module_by_name_ignore_ascii_case(name).ok())
            .ok_or_else(|| {
                GuestInjectError::Backend(
                    "could not resolve the loaded Windows kernel module".into(),
                )
            })?;
        let module_base = module.base.to_umem();
        let module_size = module.size;
        let exports = os
            .module_export_list(&module)
            .map_err(other)
            .map_err(guest_other)?
            .into_iter()
            .map(|export| (export.name.to_string(), module_base + export.offset))
            .collect::<Vec<_>>();

        let hook = [
            "NtWaitForSingleObject",
            "NtWaitForMultipleObjects",
            "NtDelayExecution",
            "NtYieldExecution",
        ]
        .iter()
        .find_map(|name| kernel_export_by_name(&exports, name).ok())
        .ok_or_else(|| {
            GuestInjectError::Backend(
                "none of the kernel bootstrap hook exports are available".into(),
            )
        })?;

        Ok(KernelBootstrapExports {
            module_base,
            module_size,
            hook,
            zw_open_process: kernel_export_by_name(&exports, "ZwOpenProcess")?,
            zw_allocate_virtual_memory: kernel_export_by_name(&exports, "ZwAllocateVirtualMemory")?,
            zw_write_virtual_memory: kernel_export_by_name(&exports, "ZwWriteVirtualMemory")?,
            zw_set_information_virtual_memory: kernel_export_by_name(
                &exports,
                "ZwSetInformationVirtualMemory",
            )?,
            rtl_create_user_thread: kernel_export_by_name(&exports, "RtlCreateUserThread")?,
            zw_close: kernel_export_by_name(&exports, "ZwClose")?,
        })
    }

    fn call_via_kernel_hijack(
        &self,
        pid: u32,
        function: u64,
        args: &[u64],
        timeout_ms: u32,
    ) -> std::result::Result<u64, GuestInjectError> {
        let eprocess = {
            let mut os = self.os.lock().unwrap();
            let proc_info = os
                .process_info_by_pid(pid)
                .map_err(|_| GuestInjectError::Backend(format!("pid {pid} not found")))?;
            if proc_info.address.is_null() {
                return Err(GuestInjectError::Backend("EPROCESS address is null".into()));
            }
            proc_info.address.to_umem()
        };
        let off = probe_thread_offsets(self, eprocess, pid)?;
        let head = eprocess + off.eproc_thread_list as u64;
        let modules = <Self as MemoryBackend>::module_list(self, Pid(pid)).map_err(guest_other)?;
        if modules.is_empty() {
            return Err(GuestInjectError::Backend(format!(
                "kernel hijack: no loaded modules available to validate a user RIP in pid {pid}"
            )));
        }

        let mut hijack: Option<KernelHijackCandidate> = None;
        let mut cursor = read_u64_at(self, pid, head)?;
        let mut threads_scanned = 0u32;
        let mut threads_matched = 0u32;
        let mut trap_frame_ptr_missing = 0u32;
        let mut trap_frame_ptr_invalid = 0u32;
        let mut trap_frame_read_fail = 0u32;
        let mut trap_frame_non_user = 0u32;
        let mut trap_frame_bad_rip = 0u32;
        let mut trap_frame_rip_not_in_module = 0u32;
        for _ in 0..4096 {
            if cursor == 0 || cursor == head {
                break;
            }
            let ethread_base = cursor - off.ethread_list_entry as u64;
            let proc_id =
                read_u32_at(self, pid, ethread_base + off.ethread_cid as u64).unwrap_or(0);
            threads_scanned += 1;
            if proc_id != pid {
                cursor = read_u64_at(self, pid, cursor).unwrap_or(0);
                continue;
            }
            threads_matched += 1;
            let tid =
                read_u32_at(self, pid, ethread_base + off.ethread_cid as u64 + 8).unwrap_or(0);
            let state = GuestThreadState::from(
                read_u8_at(self, pid, ethread_base + off.kthread_state as u64).unwrap_or(u8::MAX),
            );
            if state == GuestThreadState::Terminated {
                cursor = read_u64_at(self, pid, cursor).unwrap_or(0);
                continue;
            }
            let trap_frame =
                match read_u64_at(self, pid, ethread_base + off.kthread_trap_frame as u64) {
                    Ok(0) => {
                        trap_frame_ptr_missing += 1;
                        cursor = read_u64_at(self, pid, cursor).unwrap_or(0);
                        continue;
                    }
                    Ok(addr) if addr < 0xFFFF_0000_0000_0000 => {
                        trap_frame_ptr_invalid += 1;
                        cursor = read_u64_at(self, pid, cursor).unwrap_or(0);
                        continue;
                    }
                    Ok(addr) => addr,
                    Err(_) => {
                        trap_frame_ptr_missing += 1;
                        cursor = read_u64_at(self, pid, cursor).unwrap_or(0);
                        continue;
                    }
                };
            let frame_len = off.ktrap_frame_rip.max(off.ktrap_frame_cs) + 8;
            let trap_bytes = match self.read_kernel_virtual(pid, trap_frame, frame_len) {
                Ok(bytes) => bytes,
                Err(_) => {
                    trap_frame_read_fail += 1;
                    cursor = read_u64_at(self, pid, cursor).unwrap_or(0);
                    continue;
                }
            };
            let Some((saved_rip, cs)) =
                trap_frame_registers(&trap_bytes, off.ktrap_frame_rip, off.ktrap_frame_cs)
            else {
                trap_frame_read_fail += 1;
                cursor = read_u64_at(self, pid, cursor).unwrap_or(0);
                continue;
            };
            if cs != USER_MODE_CS {
                trap_frame_non_user += 1;
                cursor = read_u64_at(self, pid, cursor).unwrap_or(0);
                continue;
            }
            if !(LOWEST_USER_ADDRESS..FIRST_KERNEL_ADDRESS).contains(&saved_rip) {
                trap_frame_bad_rip += 1;
                cursor = read_u64_at(self, pid, cursor).unwrap_or(0);
                continue;
            }
            if !address_is_in_module(saved_rip, &modules) {
                trap_frame_rip_not_in_module += 1;
                cursor = read_u64_at(self, pid, cursor).unwrap_or(0);
                continue;
            }
            let trap_rip_addr = trap_frame + off.ktrap_frame_rip as u64;
            let candidate = KernelHijackCandidate {
                rip_addr: trap_rip_addr,
                original_rip: saved_rip,
                ethread_base,
                tid,
                state,
            };
            let replace = hijack.is_none_or(|current| {
                kernel_hijack_priority(candidate.state) < kernel_hijack_priority(current.state)
            });
            if replace {
                tracing::debug!(
                    pid,
                    tid,
                    state = ?state,
                    ethread = format_args!("{ethread_base:#x}"),
                    trap_frame = format_args!("{trap_frame:#x}"),
                    rip_addr = format_args!("{trap_rip_addr:#x}"),
                    saved_rip = format_args!("{saved_rip:#x}"),
                    "selected better KTHREAD.TrapFrame hijack candidate"
                );
                hijack = Some(candidate);
            }
            cursor = read_u64_at(self, pid, cursor).unwrap_or(0);
        }

        let candidate = hijack.ok_or_else(|| {
            GuestInjectError::Backend(format!(
                "no user-mode trap frame found: scanned={threads_scanned} matched={threads_matched} ptr_missing={trap_frame_ptr_missing} ptr_invalid={trap_frame_ptr_invalid} frame_read_fail={trap_frame_read_fail} non_user={trap_frame_non_user} bad_rip={trap_frame_bad_rip} rip_not_in_module={trap_frame_rip_not_in_module}"
            ))
        })?;
        tracing::info!(
            pid,
            tid = candidate.tid,
            state = ?candidate.state,
            ethread = format_args!("{:#x}", candidate.ethread_base),
            rip_addr = format_args!("{:#x}", candidate.rip_addr),
            saved_rip = format_args!("{:#x}", candidate.original_rip),
            "using highest-priority user-mode trap-frame hijack candidate"
        );
        let trap_frame = candidate.rip_addr;
        let original_rip = candidate.original_rip;

        let cave = find_kernel_hijack_cave(self, pid)?;
        let shellcode = build_kernel_hijack_shellcode(cave, function, args, original_rip);
        let shellcode_addr = cave + 0x80;
        <Self as decant_inject::guest::GuestMemoryBackend>::write(
            self,
            pid,
            cave,
            &vec![0u8; 0x80 + shellcode.len()],
        )?;
        <Self as decant_inject::guest::GuestMemoryBackend>::write(
            self,
            pid,
            shellcode_addr,
            &shellcode,
        )?;

        self.write_kernel_virtual(pid, trap_frame, &shellcode_addr.to_le_bytes())?;
        let written_rip = read_u64_at(self, pid, trap_frame)?;
        if written_rip != shellcode_addr {
            return Err(GuestInjectError::Backend(format!(
                "kernel hijack: trap-frame RIP write did not persist at {trap_frame:#x}; expected {shellcode_addr:#x}, read {written_rip:#x}"
            )));
        }

        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64);
        loop {
            let flag_bytes =
                <Self as decant_inject::guest::GuestMemoryBackend>::read(self, pid, cave, 8)?;
            let flag = u64::from_le_bytes(flag_bytes[0..8].try_into().unwrap());
            if flag == 2 {
                let result_bytes = <Self as decant_inject::guest::GuestMemoryBackend>::read(
                    self,
                    pid,
                    cave + 8,
                    8,
                )?;
                let result = u64::from_le_bytes(result_bytes[0..8].try_into().unwrap());
                restore_kernel_hijack_rip(self, pid, trap_frame, shellcode_addr, original_rip);
                return Ok(result);
            }
            if std::time::Instant::now() >= deadline {
                restore_kernel_hijack_rip(self, pid, trap_frame, shellcode_addr, original_rip);
                return Err(GuestInjectError::Backend(format!(
                    "kernel hijack timed out after {timeout_ms} ms (shellcode {})",
                    if flag == 1 {
                        "entered but did not complete"
                    } else {
                        "was not entered"
                    }
                )));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

fn restore_kernel_hijack_rip(
    backend: &MemflowBackend,
    pid: u32,
    rip_addr: u64,
    shellcode_addr: u64,
    original_rip: u64,
) {
    match read_u64_at(backend, pid, rip_addr) {
        Ok(current_rip) if current_rip == shellcode_addr => {
            if let Err(error) =
                backend.write_kernel_virtual(pid, rip_addr, &original_rip.to_le_bytes())
            {
                tracing::warn!(
                    pid,
                    rip_addr = format_args!("{rip_addr:#x}"),
                    error = %error,
                    "failed to restore kernel-hijacked RIP"
                );
            }
        }
        Ok(current_rip) => tracing::debug!(
            pid,
            rip_addr = format_args!("{rip_addr:#x}"),
            current_rip = format_args!("{current_rip:#x}"),
            "did not restore trap-frame RIP because the kernel already changed it"
        ),
        Err(error) => tracing::warn!(
            pid,
            rip_addr = format_args!("{rip_addr:#x}"),
            error = %error,
            "could not read trap-frame RIP while restoring kernel hijack"
        ),
    }
}

fn find_kernel_hijack_cave(
    backend: &MemflowBackend,
    pid: u32,
) -> std::result::Result<u64, GuestInjectError> {
    for region in
        <MemflowBackend as decant_inject::guest::GuestMemoryBackend>::memory_map(backend, pid)?
    {
        if !region.readable || !region.executable || !region.writable || region.size < 0x200 {
            continue;
        }
        let mut pos = 0u64;
        while pos < region.size {
            let len = (region.size - pos).min(0x10000) as usize;
            let addr = region.base + pos;
            if let Ok(bytes) = <MemflowBackend as decant_inject::guest::GuestMemoryBackend>::read(
                backend, pid, addr, len,
            ) {
                let mut i = 0;
                while i < bytes.len() {
                    if matches!(bytes[i], 0x00 | 0x90 | 0xCC) {
                        let mut run = 0;
                        while i + run < bytes.len() && matches!(bytes[i + run], 0x00 | 0x90 | 0xCC)
                        {
                            run += 1;
                        }
                        if run >= 0x200 {
                            return Ok(addr + i as u64);
                        }
                        i += run;
                    } else {
                        i += 1;
                    }
                }
            }
            pos += 0x10000;
        }
    }
    Err(GuestInjectError::Backend(
        "no RWX code cave found for kernel hijack".into(),
    ))
}

fn find_kernel_bootstrap_cave(
    backend: &MemflowBackend,
    pid: u32,
    kernel: &KernelBootstrapExports,
) -> std::result::Result<u64, GuestInjectError> {
    let mut pos = PAGE_SIZE as u64;
    while pos < kernel.module_size {
        let len = (kernel.module_size - pos).min(0x1_0000) as usize;
        let addr = kernel.module_base + pos;
        let bytes = backend.read_kernel_virtual(pid, addr, len)?;
        let mut index = 0usize;
        while index < bytes.len() {
            if !matches!(bytes[index], 0x00 | 0xCC) {
                index += 1;
                continue;
            }
            let mut run = 0usize;
            while index + run < bytes.len() && matches!(bytes[index + run], 0x00 | 0xCC) {
                run += 1;
            }
            if run >= KERNEL_BOOTSTRAP_MIN_CAVE_SIZE {
                return Ok(addr + index as u64);
            }
            index += run;
        }
        pos += len as u64;
    }
    Err(GuestInjectError::Backend(format!(
        "no {KERNEL_BOOTSTRAP_MIN_CAVE_SIZE:#x}-byte kernel code cave found in ntoskrnl"
    )))
}

fn emit_lea_rdx_rip_relative(code: &mut Vec<u8>, target_offset: i64) {
    code.extend_from_slice(&[0x48, 0x8D, 0x15]); // lea rdx, [rip + disp32]
    let next_instruction = (code.len() + 4) as i64;
    let displacement = i32::try_from(target_offset - next_instruction)
        .expect("kernel bootstrap user data is within RIP-relative range");
    code.extend_from_slice(&displacement.to_le_bytes());
}

fn build_kernel_bootstrap_user_shellcode(function: u64, args: &[u64]) -> Vec<u8> {
    let mut c = Vec::new();

    // This must be instruction zero: a thread-start failure (for example CFG
    // rejection) is otherwise indistinguishable from a fault in the stub's
    // prologue.
    emit_lea_rdx_rip_relative(&mut c, -0x80); // flag is 0x80 bytes before code
    c.extend_from_slice(&[0x48, 0xC7, 0x02, 1, 0, 0, 0]); // mov qword [rdx], 1

    c.extend_from_slice(&[0x55]); // push rbp
    c.extend_from_slice(&[0x48, 0x89, 0xE5]); // mov rbp, rsp
    c.extend_from_slice(&[0x48, 0x83, 0xEC, 0x60]); // sub rsp, 0x60

    let regs: &[(u64, &[u8])] = &[
        (args.first().copied().unwrap_or(0), &[0x48, 0x89, 0xC1]),
        (args.get(1).copied().unwrap_or(0), &[0x48, 0x89, 0xC2]),
        (args.get(2).copied().unwrap_or(0), &[0x49, 0x89, 0xC0]),
        (args.get(3).copied().unwrap_or(0), &[0x49, 0x89, 0xC1]),
    ];
    for (index, &(value, mov_reg)) in regs.iter().enumerate() {
        if index >= args.len() {
            break;
        }
        c.extend_from_slice(&[0x48, 0xB8]); // mov rax, argument
        c.extend_from_slice(&value.to_le_bytes());
        c.extend_from_slice(mov_reg);
    }
    for index in 4..args.len().min(8) {
        let displacement = 0x20 + ((index - 4) as u8) * 8;
        c.extend_from_slice(&[0x48, 0xB8]); // mov rax, argument
        c.extend_from_slice(&args[index].to_le_bytes());
        c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, displacement]);
    }

    c.extend_from_slice(&[0x48, 0xB8]); // mov rax, function
    c.extend_from_slice(&function.to_le_bytes());
    c.extend_from_slice(&[0xFF, 0xD0]); // call rax
    emit_lea_rdx_rip_relative(&mut c, -0x78); // result is 0x78 bytes before code
    c.extend_from_slice(&[0x48, 0x89, 0x02]); // mov [rdx], rax
    emit_lea_rdx_rip_relative(&mut c, -0x80); // flag
    c.extend_from_slice(&[0x48, 0xC7, 0x02, 2, 0, 0, 0]); // mov qword [rdx], 2

    c.extend_from_slice(&[0x48, 0x89, 0xEC]); // mov rsp, rbp
    c.extend_from_slice(&[0x5D]); // pop rbp
    c.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
    c.extend_from_slice(&[0xC3]); // ret
    c
}

fn emit_mov_imm64(code: &mut Vec<u8>, opcode: u8, value: u64) {
    code.extend_from_slice(&[0x48, opcode]);
    code.extend_from_slice(&value.to_le_bytes());
}

fn emit_store_imm64(code: &mut Vec<u8>, address: u64, value: u32) {
    emit_mov_imm64(code, 0xBA, address); // mov rdx, address
    code.extend_from_slice(&[0x48, 0xC7, 0x02]); // mov qword [rdx], imm32
    code.extend_from_slice(&value.to_le_bytes());
}

fn emit_jcc_rel32(code: &mut Vec<u8>, condition: u8) -> usize {
    code.extend_from_slice(&[0x0F, condition, 0, 0, 0, 0]);
    code.len() - 4
}

fn patch_rel32(code: &mut [u8], displacement_offset: usize, target_offset: usize) {
    let next_instruction = displacement_offset + 4;
    let displacement = (target_offset as i64 - next_instruction as i64) as i32;
    code[displacement_offset..next_instruction].copy_from_slice(&displacement.to_le_bytes());
}

fn build_kernel_bootstrap_stage(
    state_addr: u64,
    status_addr: u64,
    user_base_addr: u64,
    hook_addr: u64,
    pid: u32,
    user_blob_addr: u64,
    user_shellcode_len: usize,
    kernel: &KernelBootstrapExports,
) -> Vec<u8> {
    let mut c = Vec::new();

    c.extend_from_slice(&[0x9C]); // pushfq
    c.extend_from_slice(&[0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57]); // push volatile and callee-saved GPRs
    c.extend_from_slice(&[
        0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41,
        0x57,
    ]); // push r8-r15
    c.extend_from_slice(&[0x49, 0x89, 0xE5]); // mov r13, rsp
    c.extend_from_slice(&[0x48, 0x83, 0xE4, 0xF0]); // and rsp, -16
    c.extend_from_slice(&[0x48, 0x81, 0xEC, 0x60, 0x01, 0x00, 0x00]); // sub rsp, 0x160
    c.extend_from_slice(&[0x4C, 0x89, 0xAC, 0x24, 0x50, 0x01, 0x00, 0x00]); // mov [rsp+0x150], r13

    emit_mov_imm64(&mut c, 0xB9, state_addr); // mov rcx, state
    c.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
    c.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]); // mov edx, 1
    c.extend_from_slice(&[0xF0, 0x48, 0x0F, 0xB1, 0x11]); // lock cmpxchg [rcx], rdx
    c.extend_from_slice(&[0x41, 0x0F, 0x94, 0xC4]); // setz r12b
    c.extend_from_slice(&[0x45, 0x0F, 0xB6, 0xE4]); // movzx r12d, r12b

    let wait_for_restore = c.len();
    emit_mov_imm64(&mut c, 0xB8, state_addr); // mov rax, state
    c.extend_from_slice(&[0x48, 0x8B, 0x00]); // mov rax, [rax]
    c.extend_from_slice(&[0x48, 0x83, 0xF8, 0x02]); // cmp rax, 2
    let wait_patch = emit_jcc_rel32(&mut c, 0x82); // jb wait_for_restore
    c.extend_from_slice(&[0x45, 0x85, 0xE4]); // test r12d, r12d
    let resume_if_not_owner = emit_jcc_rel32(&mut c, 0x84); // jz resume

    c.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
    c.extend_from_slice(&[0x48, 0x8D, 0xBC, 0x24, 0x60, 0x00, 0x00, 0x00]); // lea rdi, [rsp+0x60]
    c.extend_from_slice(&[0xB9, 0x16, 0x00, 0x00, 0x00]); // mov ecx, 22
    c.extend_from_slice(&[0xF3, 0x48, 0xAB]); // rep stosq
    c.extend_from_slice(&[
        0xC7, 0x84, 0x24, 0xE0, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,
    ]); // ObjectAttributes.Length
    emit_mov_imm64(&mut c, 0xB8, pid as u64); // mov rax, pid
    c.extend_from_slice(&[0x48, 0x89, 0x84, 0x24, 0xD0, 0x00, 0x00, 0x00]); // mov [rsp+0xd0], rax

    c.extend_from_slice(&[0x48, 0x8D, 0x8C, 0x24, 0xC0, 0x00, 0x00, 0x00]); // lea rcx, [rsp+0xc0]
    c.extend_from_slice(&[0xBA, 0xFF, 0xFF, 0x1F, 0x00]); // mov edx, PROCESS_ALL_ACCESS
    c.extend_from_slice(&[0x4C, 0x8D, 0x84, 0x24, 0xE0, 0x00, 0x00, 0x00]); // lea r8, [rsp+0xe0]
    c.extend_from_slice(&[0x4C, 0x8D, 0x8C, 0x24, 0xD0, 0x00, 0x00, 0x00]); // lea r9, [rsp+0xd0]
    emit_mov_imm64(&mut c, 0xB8, kernel.zw_open_process); // mov rax, ZwOpenProcess
    c.extend_from_slice(&[0xFF, 0xD0]); // call rax
    c.extend_from_slice(&[0x48, 0x89, 0xC3]); // mov rbx, rax
    c.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
    let open_failed = emit_jcc_rel32(&mut c, 0x88); // js finalize

    emit_mov_imm64(&mut c, 0xB8, cfg_page_base); // mov rax, CFG page base
    c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x60]); // Range.VirtualAddress
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x68, 0x00, 0x10, 0x00, 0x00]); // Range.NumberOfBytes = PAGE_SIZE
    emit_mov_imm64(&mut c, 0xB8, cfg_target_offset); // mov rax, CFG target offset
    c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x70]); // CFG_CALL_TARGET_INFO.Offset
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x78, 0x01, 0x00, 0x00, 0x00]); // CFG_CALL_TARGET_VALID
    c.extend_from_slice(&[
        0xC7, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ]); // list.NumberOfEntries = 1
    c.extend_from_slice(&[0x48, 0x8D, 0x84, 0x24, 0x70, 0x00, 0x00, 0x00]); // lea rax, [rsp+0x70]
    c.extend_from_slice(&[0x48, 0x89, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00]); // list.CallTargetInfo

    c.extend_from_slice(&[0x48, 0x8B, 0x8C, 0x24, 0xC0, 0x00, 0x00, 0x00]); // mov rcx, [rsp+0xc0]
    c.extend_from_slice(&[0xBA, 0x02, 0x00, 0x00, 0x00]); // VmCfgCallTargetInformation
    c.extend_from_slice(&[0x41, 0xB8, 0x01, 0x00, 0x00, 0x00]); // mov r8d, 1
    c.extend_from_slice(&[0x4C, 0x8D, 0x4C, 0x24, 0x60]); // lea r9, [rsp+0x60]
    c.extend_from_slice(&[0x48, 0x8D, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00]); // lea rax, [rsp+0x80]
    c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]); // VmInformation
    c.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x28, 0x28, 0x00, 0x00, 0x00]); // VmInformationLength = 40
    emit_mov_imm64(&mut c, 0xB8, kernel.zw_set_information_virtual_memory); // mov rax, ZwSetInformationVirtualMemory
    c.extend_from_slice(&[0xFF, 0xD0]); // call rax
    c.extend_from_slice(&[0x48, 0x89, 0xC3]); // mov rbx, rax
    c.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
    let cfg_failed = emit_jcc_rel32(&mut c, 0x88); // js finalize

    c.extend_from_slice(&[0x48, 0x8B, 0x8C, 0x24, 0xC0, 0x00, 0x00, 0x00]); // mov rcx, [rsp+0xc0]
    c.extend_from_slice(&[0x31, 0xD2]); // xor edx, edx (SecurityDescriptor)
    c.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d, r8d (CreateSuspended)
    c.extend_from_slice(&[0x45, 0x31, 0xC9]); // xor r9d, r9d (StackZeroBits)
    c.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
    c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]); // StackReserved = NULL
    c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x28]); // StackCommit = NULL
    emit_mov_imm64(&mut c, 0xB8, user_start); // mov rax, user start
    c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x30]); // StartAddress
    c.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
    c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x38]); // StartParameter = NULL
    c.extend_from_slice(&[0x48, 0x8D, 0x84, 0x24, 0xC8, 0x00, 0x00, 0x00]); // lea rax, [rsp+0xc8]
    c.extend_from_slice(&[0x48, 0x89, 0x84, 0x24, 0x40, 0x00, 0x00, 0x00]); // ThreadHandle
    c.extend_from_slice(&[0x48, 0x8D, 0x84, 0x24, 0xD0, 0x00, 0x00, 0x00]); // lea rax, [rsp+0xd0]
    c.extend_from_slice(&[0x48, 0x89, 0x84, 0x24, 0x48, 0x00, 0x00, 0x00]); // ClientId
    emit_mov_imm64(&mut c, 0xB8, kernel.rtl_create_user_thread); // mov rax, RtlCreateUserThread
    c.extend_from_slice(&[0xFF, 0xD0]); // call rax
    c.extend_from_slice(&[0x48, 0x89, 0xC3]); // mov rbx, rax

    let finalize = c.len();
    emit_mov_imm64(&mut c, 0xBA, status_addr); // mov rdx, status
    c.extend_from_slice(&[0x48, 0x89, 0x1A]); // mov [rdx], rbx
    c.extend_from_slice(&[0x48, 0x8B, 0x8C, 0x24, 0xC8, 0x00, 0x00, 0x00]); // mov rcx, [rsp+0xc8]
    c.extend_from_slice(&[0x48, 0x85, 0xC9]); // test rcx, rcx
    let skip_thread_close = emit_jcc_rel32(&mut c, 0x84); // jz skip
    emit_mov_imm64(&mut c, 0xB8, kernel.zw_close); // mov rax, ZwClose
    c.extend_from_slice(&[0xFF, 0xD0]); // call rax
    let after_thread_close = c.len();
    c.extend_from_slice(&[0x48, 0x8B, 0x8C, 0x24, 0xC0, 0x00, 0x00, 0x00]); // mov rcx, [rsp+0xc0]
    c.extend_from_slice(&[0x48, 0x85, 0xC9]); // test rcx, rcx
    let skip_process_close = emit_jcc_rel32(&mut c, 0x84); // jz skip
    emit_mov_imm64(&mut c, 0xB8, kernel.zw_close); // mov rax, ZwClose
    c.extend_from_slice(&[0xFF, 0xD0]); // call rax
    let after_process_close = c.len();
    emit_mov_imm64(&mut c, 0xB8, state_addr); // mov rax, state
    c.extend_from_slice(&[0x48, 0xC7, 0x00, 0x03, 0x00, 0x00, 0x00]); // mov qword [rax], 3

    let resume = c.len();
    c.extend_from_slice(&[0x48, 0x8B, 0xA4, 0x24, 0x50, 0x01, 0x00, 0x00]); // mov rsp, [rsp+0x150]
    c.extend_from_slice(&[
        0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41,
        0x58, 0x5F, 0x5E, 0x5D, 0x5B, 0x5A, 0x59, 0x58, 0x9D,
    ]); // restore r15-r8, GPRs, and flags
    c.extend_from_slice(&[0xFF, 0x25, 0, 0, 0, 0]); // jmp qword [rip]
    c.extend_from_slice(&hook_addr.to_le_bytes());

    patch_rel32(&mut c, wait_patch, wait_for_restore);
    patch_rel32(&mut c, resume_if_not_owner, resume);
    patch_rel32(&mut c, open_failed, finalize);
    patch_rel32(&mut c, cfg_failed, finalize);
    patch_rel32(&mut c, skip_thread_close, after_thread_close);
    patch_rel32(&mut c, skip_process_close, after_process_close);
    c
}

fn build_kernel_hijack_shellcode(
    cave: u64,
    function: u64,
    args: &[u64],
    original_rip: u64,
) -> Vec<u8> {
    let mut c = Vec::new();

    let flag_addr = cave;
    let result_addr = cave + 8;

    c.extend_from_slice(&[0x9C]); // pushfq
    c.extend_from_slice(&[0x50]); // push rax
    c.extend_from_slice(&[0x51]); // push rcx
    c.extend_from_slice(&[0x52]); // push rdx
    c.extend_from_slice(&[0x41, 0x50]); // push r8
    c.extend_from_slice(&[0x41, 0x51]); // push r9
    c.extend_from_slice(&[0x41, 0x52]); // push r10
    c.extend_from_slice(&[0x41, 0x53]); // push r11

    c.extend_from_slice(&[0x48, 0xA1]); // mov rax, [flag]
    c.extend_from_slice(&flag_addr.to_le_bytes());
    c.extend_from_slice(&[0x48, 0x85, 0xC0]); // test rax, rax
    let skip_patch = c.len();
    c.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]); // jnz skip (placeholder)

    emit_store_imm64(&mut c, flag_addr, 1); // mov qword [flag], 1 (entered)

    // The saved user stack can have either ABI alignment when interrupted.
    // Keep its exact value outside the call frame, then establish an aligned
    // frame with shadow space, four stack arguments, and an FXSAVE area.
    // FXSAVE preserves the interrupted thread's x87/SSE/MXCSR state; unlike a
    // normal ABI call, this stub resumes at an arbitrary instruction where
    // volatile vector registers may still be live.
    c.extend_from_slice(&[0x49, 0x89, 0xE3]); // mov r11, rsp
    c.extend_from_slice(&[0x48, 0x83, 0xE4, 0xF0]); // and rsp, -16
    c.extend_from_slice(&[0x48, 0x81, 0xEC, 0x60, 0x02, 0x00, 0x00]); // sub rsp, 0x260
    c.extend_from_slice(&[0x4C, 0x89, 0x5C, 0x24, 0x40]); // mov [rsp+0x40], r11
    c.extend_from_slice(&[0x0F, 0xAE, 0x44, 0x24, 0x50]); // fxsave [rsp+0x50]

    let regs: &[(u64, &[u8])] = &[
        (args.first().copied().unwrap_or(0), &[0x48, 0x89, 0xC1]),
        (args.get(1).copied().unwrap_or(0), &[0x48, 0x89, 0xC2]),
        (args.get(2).copied().unwrap_or(0), &[0x49, 0x89, 0xC0]),
        (args.get(3).copied().unwrap_or(0), &[0x49, 0x89, 0xC1]),
    ];
    for (i, &(val, mov_reg)) in regs.iter().enumerate() {
        if i >= args.len() {
            break;
        }
        c.extend_from_slice(&[0x48, 0xB8]); // mov rax, val
        c.extend_from_slice(&val.to_le_bytes());
        c.extend_from_slice(mov_reg);
    }

    for i in 4..args.len().min(8) {
        let disp = 0x20 + ((i - 4) as u8) * 8;
        c.extend_from_slice(&[0x48, 0xB8]); // mov rax, arg
        c.extend_from_slice(&args[i].to_le_bytes());
        c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, disp]); // mov [rsp+disp], rax
    }

    c.extend_from_slice(&[0x48, 0xB8]); // mov rax, function
    c.extend_from_slice(&function.to_le_bytes());
    c.extend_from_slice(&[0xFF, 0xD0]); // call rax

    c.extend_from_slice(&[0x48, 0xA3]); // mov [result], rax
    c.extend_from_slice(&result_addr.to_le_bytes());

    emit_store_imm64(&mut c, flag_addr, 2); // mov qword [flag], 2 (complete)

    c.extend_from_slice(&[0x0F, 0xAE, 0x4C, 0x24, 0x50]); // fxrstor [rsp+0x50]
    c.extend_from_slice(&[0x48, 0x8B, 0x64, 0x24, 0x40]); // mov rsp, [rsp+0x40]
    c.extend_from_slice(&[0x41, 0x5B]); // pop r11
    c.extend_from_slice(&[0x41, 0x5A]); // pop r10
    c.extend_from_slice(&[0x41, 0x59]); // pop r9
    c.extend_from_slice(&[0x41, 0x58]); // pop r8
    c.extend_from_slice(&[0x5A]); // pop rdx
    c.extend_from_slice(&[0x59]); // pop rcx
    c.extend_from_slice(&[0x58]); // pop rax
    c.extend_from_slice(&[0x9D]); // popfq

    let skip_target = c.len() as u32;
    let skip_offset = skip_target - skip_patch as u32 - 6;
    let skip_bytes = skip_offset.to_le_bytes();
    c[skip_patch + 2] = skip_bytes[0];
    c[skip_patch + 3] = skip_bytes[1];
    c[skip_patch + 4] = skip_bytes[2];
    c[skip_patch + 5] = skip_bytes[3];

    c.extend_from_slice(&[0x48, 0xB8]); // mov rax, original_rip
    c.extend_from_slice(&original_rip.to_le_bytes());
    c.extend_from_slice(&[0xFF, 0xE0]); // jmp rax

    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_saved_user_context_at_the_fixed_ktrap_frame_offsets() {
        let mut frame = vec![0u8; 0x172];
        let rip: u64 = 0x0000_7ffb_1234_5678;
        frame[0x168..0x170].copy_from_slice(&rip.to_le_bytes());
        frame[0x170..0x172].copy_from_slice(&USER_MODE_CS.to_le_bytes());

        assert_eq!(
            trap_frame_registers(&frame, 0x168, 0x170),
            Some((rip, USER_MODE_CS))
        );
        assert_eq!(trap_frame_registers(&frame, 0x168, 0x172), None);
    }

    #[test]
    fn validates_saved_rip_against_module_ranges_without_overflow() {
        let modules = [
            ModuleInfo {
                name: "ntdll.dll".into(),
                base: 0x0000_7ffb_1000_0000,
                size: 0x20_0000,
            },
            ModuleInfo {
                name: "overflow.dll".into(),
                base: u64::MAX - 0x10,
                size: 0x20,
            },
        ];

        assert!(address_is_in_module(0x0000_7ffb_1000_0000, &modules));
        assert!(address_is_in_module(0x0000_7ffb_101f_ffff, &modules));
        assert!(!address_is_in_module(0x0000_7ffb_1020_0000, &modules));
        assert!(!address_is_in_module(u64::MAX - 8, &modules));
    }

    #[test]
    fn kernel_hijack_stub_saves_volatile_vector_state_on_an_aligned_frame() {
        let shellcode = build_kernel_hijack_shellcode(0x0000_7ffb_1000_0000, 0x1234, &[], 0x5678);

        assert!(
            shellcode
                .windows(5)
                .any(|instruction| instruction == [0x0F, 0xAE, 0x44, 0x24, 0x50])
        );
        assert!(
            shellcode
                .windows(5)
                .any(|instruction| instruction == [0x0F, 0xAE, 0x4C, 0x24, 0x50])
        );
        assert!(shellcode.len() + 0x80 <= 0x200);
    }

    #[test]
    fn favors_runnable_threads_for_trap_frame_hijacking() {
        assert!(
            kernel_hijack_priority(GuestThreadState::Running)
                < kernel_hijack_priority(GuestThreadState::Ready)
        );
        assert!(
            kernel_hijack_priority(GuestThreadState::Ready)
                < kernel_hijack_priority(GuestThreadState::Waiting)
        );
        assert_eq!(
            kernel_hijack_priority(GuestThreadState::Terminated),
            u8::MAX
        );
    }

    #[test]
    fn kernel_bootstrap_stages_fit_their_code_caves() {
        let kernel = KernelBootstrapExports {
            module_base: 0xffff_f800_0000_0000,
            module_size: 0x20_0000,
            hook: 0xffff_f800_0000_1000,
            zw_open_process: 0xffff_f800_0000_2000,
            zw_set_information_virtual_memory: 0xffff_f800_0000_2800,
            rtl_create_user_thread: 0xffff_f800_0000_3000,
            zw_close: 0xffff_f800_0000_4000,
        };
        let user = build_kernel_bootstrap_user_shellcode(0x0000_7ffb_1000_0000, 0x1234, &[1; 8]);
        let stage = build_kernel_bootstrap_stage(
            0xffff_f800_0010_0000,
            0xffff_f800_0010_0008,
            kernel.hook,
            4242,
            0x0000_7ffb_1000_0080,
            &kernel,
        );

        assert!(user.len() + 0x80 <= 0x200);
        assert!(
            stage.len() + KERNEL_BOOTSTRAP_STAGE_OFFSET as usize <= KERNEL_BOOTSTRAP_MIN_CAVE_SIZE
        );
        assert!(
            stage
                .windows(14)
                .any(|jump| jump == [0xFF, 0x25, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0xF8, 0xFF, 0xFF])
        );
    }

    #[test]
    fn user_bootstrap_stub_uses_a_true_64_bit_address_for_status_writes() {
        let cave = 0x0000_7ffb_1000_0000;
        let shellcode = build_kernel_bootstrap_user_shellcode(cave, 0x1234, &[]);
        let mut expected = vec![0x48, 0xBA]; // mov rdx, flag address
        expected.extend_from_slice(&cave.to_le_bytes());
        expected.extend_from_slice(&[0x48, 0xC7, 0x02, 1, 0, 0, 0]);

        assert!(
            shellcode
                .windows(expected.len())
                .any(|bytes| bytes == expected)
        );
        assert!(
            !shellcode
                .windows(4)
                .any(|bytes| bytes == [0x48, 0xC7, 0x04, 0x25])
        );
    }
}
