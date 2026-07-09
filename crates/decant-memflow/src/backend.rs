use std::sync::Mutex;
use std::sync::atomic::AtomicU64;

use decant_backend::{BackendError, MemoryBackend, Result};
use decant_inject::guest::{
    GuestCapabilities, GuestHwbp, GuestIatHook, GuestInjectError, GuestMemoryBackend,
    GuestMemoryRegion, GuestModuleInfo, GuestProcessInfo, GuestTeb, GuestThreadContext,
    GuestThreadInfo, GuestThreadState, MapHandle,
};
use decant_protocol::{MemRegion, ModuleInfo, Pid, ProcessInfo};

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
        pid: u32,
        addr: u64,
        len: usize,
    ) -> std::result::Result<Vec<u8>, GuestInjectError> {
        self.with_process(Pid(pid), |proc| {
            proc.read_raw(Address::from(addr), len)
                .map_err(|e| BackendError::ReadFailed {
                    addr,
                    len: len as u64,
                    reason: format!("kernel virtual read {addr:#x}+{len:#x}: {e:?}"),
                })
        })
        .map_err(guest_other)
    }

    fn write_kernel_virtual(
        &self,
        pid: u32,
        addr: u64,
        data: &[u8],
    ) -> std::result::Result<(), GuestInjectError> {
        self.with_process(Pid(pid), |proc| {
            proc.write_raw(Address::from(addr), data)
                .map_err(|e| BackendError::WriteFailed {
                    addr,
                    reason: format!("kernel virtual write {addr:#x}+{:#x}: {e:?}", data.len()),
                })?;
            Ok(())
        })
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
    },
    // Win10 18362 x64
    WinOffset {
        eproc_thread_list: 1160,
        ethread_list_entry: 1720,
        kthread_teb: 240,
        ethread_cid: 0x478,
        ethread_start_address: 0x6F0,
        kthread_state: 0x163,
    },
];

struct EthreadSummary {
    pub ethread_base: u64,
    pub tid: u32,
    pub teb: u64,
    pub start_address: u64,
    pub state: GuestThreadState,
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
