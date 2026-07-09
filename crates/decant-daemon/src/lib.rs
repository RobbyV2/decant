//! Daemon dispatch and TCP serving for Decant RPC requests.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use decant_backend::MemoryBackend;
use decant_inject::DecantConfig;
use decant_inject::guest::{
    GuestCapabilities, GuestInjectError, GuestInjectionPlan, GuestInjectionRequest, GuestInjector,
    GuestManualMapInjector, GuestMemoryBackend, GuestMemoryRegion, GuestModuleInfo,
    GuestProcessInfo, unmap_all_tracked_modules,
};
use decant_protocol::{
    Diagnostics, GuestInjectInfo, GuestUnmapInfo, Pid, ProtoError, Request, Response, read_msg,
    write_msg,
};

pub trait DaemonBackend: MemoryBackend + GuestMemoryBackend {}

impl<T> DaemonBackend for T where T: MemoryBackend + GuestMemoryBackend {}

pub struct BasicDaemonBackend<B> {
    backend: B,
}

impl<B> BasicDaemonBackend<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }
}

impl<B> MemoryBackend for BasicDaemonBackend<B>
where
    B: MemoryBackend,
{
    fn list_processes(&self) -> decant_backend::Result<Vec<decant_protocol::ProcessInfo>> {
        self.backend.list_processes()
    }

    fn process_by_pid(&self, pid: Pid) -> decant_backend::Result<decant_protocol::ProcessInfo> {
        self.backend.process_by_pid(pid)
    }

    fn process_by_name(&self, name: &str) -> decant_backend::Result<decant_protocol::ProcessInfo> {
        self.backend.process_by_name(name)
    }

    fn module_list(&self, pid: Pid) -> decant_backend::Result<Vec<decant_protocol::ModuleInfo>> {
        self.backend.module_list(pid)
    }

    fn module_by_name(
        &self,
        pid: Pid,
        name: &str,
    ) -> decant_backend::Result<decant_protocol::ModuleInfo> {
        self.backend.module_by_name(pid, name)
    }

    fn module_exports(&self, pid: Pid, module: &str) -> decant_backend::Result<Vec<(String, u64)>> {
        self.backend.module_exports(pid, module)
    }

    fn read(&self, pid: Pid, addr: u64, len: usize) -> decant_backend::Result<Vec<u8>> {
        self.backend.read(pid, addr, len)
    }

    fn write(&self, pid: Pid, addr: u64, data: &[u8]) -> decant_backend::Result<usize> {
        self.backend.write(pid, addr, data)
    }

    fn memory_map(&self, pid: Pid) -> decant_backend::Result<Vec<decant_protocol::MemRegion>> {
        self.backend.memory_map(pid)
    }
}

#[derive(Debug)]
pub struct Diag {
    pub connector: String,
    pub reads: AtomicU64,
    pub writes: AtomicU64,
    pub unsupported_ops: AtomicU64,
}

impl Diag {
    pub fn new(connector: impl Into<String>) -> Self {
        Diag {
            connector: connector.into(),
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            unsupported_ops: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> Diagnostics {
        Diagnostics {
            connector: self.connector.clone(),
            reads: self.reads.load(Ordering::Relaxed),
            writes: self.writes.load(Ordering::Relaxed),
            unsupported_ops: self.unsupported_ops.load(Ordering::Relaxed),
        }
    }
}

pub fn dispatch(req: Request, backend: &dyn DaemonBackend, diag: &Diag) -> Response {
    fn finish<T>(
        r: decant_backend::Result<T>,
        ok: impl FnOnce(T) -> Response,
        diag: &Diag,
    ) -> Response {
        match r {
            Ok(v) => ok(v),
            Err(e) => {
                let pe: ProtoError = e.into();
                if matches!(pe, ProtoError::Unsupported { .. }) {
                    diag.unsupported_ops.fetch_add(1, Ordering::Relaxed);
                }
                Response::Err(pe)
            }
        }
    }

    match req {
        Request::Ping => Response::Pong,
        Request::Diagnostics => Response::Diagnostics(diag.snapshot()),
        Request::ListProcesses => finish(
            MemoryBackend::list_processes(backend),
            Response::Processes,
            diag,
        ),
        Request::ProcessByPid(pid) => finish(
            MemoryBackend::process_by_pid(backend, pid),
            Response::Process,
            diag,
        ),
        Request::ProcessByName(name) => finish(
            MemoryBackend::process_by_name(backend, &name),
            Response::Process,
            diag,
        ),
        Request::ModuleList(pid) => finish(
            MemoryBackend::module_list(backend, pid),
            Response::Modules,
            diag,
        ),
        Request::ModuleByName(pid, name) => finish(
            MemoryBackend::module_by_name(backend, pid, &name),
            Response::Module,
            diag,
        ),
        Request::ModuleExports(pid, module) => finish(
            MemoryBackend::module_exports(backend, pid, &module),
            Response::Exports,
            diag,
        ),
        Request::Read { pid, addr, len } => {
            diag.reads.fetch_add(1, Ordering::Relaxed);
            finish(
                MemoryBackend::read(backend, pid, addr, len as usize),
                Response::Data,
                diag,
            )
        }
        Request::Write { pid, addr, data } => {
            diag.writes.fetch_add(1, Ordering::Relaxed);
            finish(
                MemoryBackend::write(backend, pid, addr, &data),
                |n| Response::Written(n as u64),
                diag,
            )
        }
        Request::MemoryMap(pid) => finish(
            MemoryBackend::memory_map(backend, pid),
            Response::MemoryMap,
            diag,
        ),
        Request::Scan { pid, pattern } => {
            match decant_analysis::scanner::scan_str(backend, pid, &pattern) {
                Ok(hits) => Response::ScanHits(hits),
                Err(e) => Response::Err(core_err_to_proto(e)),
            }
        }
        Request::Resolve { pid, base, offsets } => {
            match decant_analysis::resolve(backend, pid, base, &offsets) {
                Ok(address) => {
                    diag.reads.fetch_add(1, Ordering::Relaxed);
                    let value = MemoryBackend::read(backend, pid, address, 8).unwrap_or_default();
                    Response::Resolved { address, value }
                }
                Err(e) => Response::Err(core_err_to_proto(e)),
            }
        }
        Request::GuestInject {
            config_toml,
            payload_image,
        } => guest_inject(&config_toml, &payload_image, backend, diag),
        Request::GuestUnmap { config_toml } => guest_unmap(&config_toml, backend, diag),
        Request::ReportUnsupported { op } => {
            diag.unsupported_ops.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%op, "unsupported operation refused at the interposer");
            Response::Pong
        }
    }
}

impl<B> GuestMemoryBackend for BasicDaemonBackend<B>
where
    B: MemoryBackend,
{
    fn capabilities(&self) -> GuestCapabilities {
        GuestCapabilities {
            list_processes: true,
            module_list: true,
            module_exports: true,
            read_memory: true,
            write_memory: true,
            write_verify: true,
            memory_map: true,
            virtual_alloc: true,
            iat_hook_execution: true,
            wait_for_result: true,
            forwarded_exports: true,
            ordinal_imports: true,
            delay_imports: true,
            ..GuestCapabilities::default()
        }
    }

    fn list_processes(&self) -> Result<Vec<GuestProcessInfo>, GuestInjectError> {
        self.backend
            .list_processes()
            .map(|processes| {
                processes
                    .into_iter()
                    .map(|p| GuestProcessInfo {
                        pid: p.pid.0,
                        name: p.name,
                    })
                    .collect()
            })
            .map_err(guest_backend)
    }

    fn module_list(&self, pid: u32) -> Result<Vec<GuestModuleInfo>, GuestInjectError> {
        self.backend
            .module_list(Pid(pid))
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
            .map_err(guest_backend)
    }

    fn module_exports(
        &self,
        pid: u32,
        module: &str,
    ) -> Result<Vec<(String, u64)>, GuestInjectError> {
        self.backend
            .module_exports(Pid(pid), module)
            .map_err(guest_backend)
    }

    fn memory_map(&self, pid: u32) -> Result<Vec<GuestMemoryRegion>, GuestInjectError> {
        self.backend
            .memory_map(Pid(pid))
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
            .map_err(guest_backend)
    }

    fn read(&self, pid: u32, addr: u64, len: usize) -> Result<Vec<u8>, GuestInjectError> {
        self.backend
            .read(Pid(pid), addr, len)
            .map_err(guest_backend)
    }

    fn write(&self, pid: u32, addr: u64, data: &[u8]) -> Result<(), GuestInjectError> {
        self.backend
            .write(Pid(pid), addr, data)
            .map(|_| ())
            .map_err(guest_backend)
    }
}

fn guest_inject(
    config_toml: &str,
    payload_image: &[u8],
    backend: &dyn DaemonBackend,
    diag: &Diag,
) -> Response {
    let config = match DecantConfig::from_toml_str(config_toml) {
        Ok(config) => config,
        Err(e) => {
            return Response::Err(ProtoError::Backend {
                message: e.to_string(),
            });
        }
    };
    let plan = match GuestInjectionPlan::from_config(&config) {
        Ok(plan) => plan,
        Err(e) => return guest_error(e, diag),
    };
    let req = GuestInjectionRequest {
        payload_path: &plan.payload_path,
        payload_image,
        plan: &plan,
    };
    let guest: &dyn GuestMemoryBackend = backend;
    match GuestManualMapInjector.inject(guest, &req) {
        Ok(info) => Response::GuestInjected(GuestInjectInfo {
            method: info.method,
            pid: Pid(info.pid),
            remote_base: info.remote_base,
            notes: info.notes,
        }),
        Err(e) => guest_error(e, diag),
    }
}

fn guest_unmap(config_toml: &str, backend: &dyn DaemonBackend, diag: &Diag) -> Response {
    let config = match DecantConfig::from_toml_str(config_toml) {
        Ok(config) => config,
        Err(e) => {
            return Response::Err(ProtoError::Backend {
                message: e.to_string(),
            });
        }
    };
    let plan = match GuestInjectionPlan::from_config(&config) {
        Ok(plan) => plan,
        Err(e) => return guest_error(e, diag),
    };
    let guest: &dyn GuestMemoryBackend = backend;
    match unmap_all_tracked_modules(guest, &plan) {
        Ok((pid, modules_unmapped)) => Response::GuestUnmapped(GuestUnmapInfo {
            pid: Pid(pid),
            modules_unmapped: modules_unmapped as u64,
        }),
        Err(e) => guest_error(e, diag),
    }
}

fn guest_backend(e: decant_backend::BackendError) -> GuestInjectError {
    GuestInjectError::Backend(e.to_string())
}

fn guest_error(e: GuestInjectError, diag: &Diag) -> Response {
    if matches!(e, GuestInjectError::Unsupported { .. }) {
        diag.unsupported_ops.fetch_add(1, Ordering::Relaxed);
    }
    Response::Err(ProtoError::Backend {
        message: e.to_string(),
    })
}

fn core_err_to_proto(e: decant_analysis::CoreError) -> ProtoError {
    match e {
        decant_analysis::CoreError::Pattern(message) => ProtoError::Backend { message },
        decant_analysis::CoreError::Backend(be) => be.into(),
    }
}

pub fn serve_connection(
    mut stream: TcpStream,
    backend: &dyn DaemonBackend,
    diag: &Diag,
) -> io::Result<()> {
    loop {
        let req: Request = match read_msg(&mut stream) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let resp = dispatch(req, backend, diag);
        write_msg(&mut stream, &resp)?;
    }
}

pub fn serve(
    listener: TcpListener,
    backend: Arc<dyn DaemonBackend>,
    diag: Arc<Diag>,
) -> io::Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;
        let _ = stream.set_nodelay(true);
        let peer = stream.peer_addr().ok();
        let backend = Arc::clone(&backend);
        let diag = Arc::clone(&diag);
        std::thread::spawn(move || {
            tracing::debug!(?peer, "connection opened");
            if let Err(e) = serve_connection(stream, backend.as_ref(), diag.as_ref()) {
                tracing::warn!(?peer, error = %e, "connection error");
            } else {
                tracing::debug!(?peer, "connection closed");
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use decant_backend::fixtures::{DEMO_MAGIC, DEMO_MAGIC_ADDR, DEMO_TARGET_PID, demo_backend};
    use decant_protocol::Pid;

    fn diag() -> Diag {
        Diag::new("mock")
    }

    #[test]
    fn dispatch_reads_planted_magic() {
        let b = BasicDaemonBackend::new(demo_backend());
        let d = diag();
        let resp = dispatch(
            Request::Read {
                pid: DEMO_TARGET_PID,
                addr: DEMO_MAGIC_ADDR,
                len: 16,
            },
            &b,
            &d,
        );
        match resp {
            Response::Data(bytes) => assert_eq!(bytes, DEMO_MAGIC),
            other => panic!("expected Data, got {other:?}"),
        }
        assert_eq!(d.reads.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn dispatch_write_then_read_back() {
        let b = BasicDaemonBackend::new(demo_backend());
        let d = diag();
        let w = dispatch(
            Request::Write {
                pid: DEMO_TARGET_PID,
                addr: 0x0001_4001_0400,
                data: vec![1, 2, 3, 4],
            },
            &b,
            &d,
        );
        assert!(matches!(w, Response::Written(4)));
        let r = dispatch(
            Request::Read {
                pid: DEMO_TARGET_PID,
                addr: 0x0001_4001_0400,
                len: 4,
            },
            &b,
            &d,
        );
        assert!(matches!(r, Response::Data(ref v) if v == &vec![1, 2, 3, 4]));
        assert_eq!(d.writes.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn dispatch_unknown_pid_is_structured_error() {
        let b = BasicDaemonBackend::new(demo_backend());
        let d = diag();
        let resp = dispatch(Request::ProcessByPid(Pid(9999)), &b, &d);
        assert!(matches!(
            resp,
            Response::Err(ProtoError::NoSuchProcess { .. })
        ));
    }
}
