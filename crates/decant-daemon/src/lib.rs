use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use decant_backend::MemoryBackend;
use decant_protocol::{read_msg, write_msg, Diagnostics, ProtoError, Request, Response};

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

pub fn dispatch(req: Request, backend: &dyn MemoryBackend, diag: &Diag) -> Response {
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
        Request::ListProcesses => {
            finish(backend.list_processes(), Response::Processes, diag)
        }
        Request::ProcessByPid(pid) => {
            finish(backend.process_by_pid(pid), Response::Process, diag)
        }
        Request::ProcessByName(name) => {
            finish(backend.process_by_name(&name), Response::Process, diag)
        }
        Request::ModuleList(pid) => finish(backend.module_list(pid), Response::Modules, diag),
        Request::ModuleByName(pid, name) => {
            finish(backend.module_by_name(pid, &name), Response::Module, diag)
        }
        Request::ModuleExports(pid, module) => {
            finish(backend.module_exports(pid, &module), Response::Exports, diag)
        }
        Request::Read { pid, addr, len } => {
            diag.reads.fetch_add(1, Ordering::Relaxed);
            finish(backend.read(pid, addr, len as usize), Response::Data, diag)
        }
        Request::Write { pid, addr, data } => {
            diag.writes.fetch_add(1, Ordering::Relaxed);
            finish(backend.write(pid, addr, &data), |n| Response::Written(n as u64), diag)
        }
        Request::MemoryMap(pid) => finish(backend.memory_map(pid), Response::MemoryMap, diag),
        Request::Scan { pid, pattern } => match decant_core::scanner::scan_str(backend, pid, &pattern)
        {
            Ok(hits) => Response::ScanHits(hits),
            Err(e) => Response::Err(core_err_to_proto(e)),
        },
        Request::Resolve { pid, base, offsets } => {
            match decant_core::resolve(backend, pid, base, &offsets) {
                Ok(address) => {
                    diag.reads.fetch_add(1, Ordering::Relaxed);
                    let value = backend.read(pid, address, 8).unwrap_or_default();
                    Response::Resolved { address, value }
                }
                Err(e) => Response::Err(core_err_to_proto(e)),
            }
        }
        Request::ReportUnsupported { op } => {
            diag.unsupported_ops.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%op, "unsupported operation refused at the interposer");
            Response::Pong
        }
    }
}

fn core_err_to_proto(e: decant_core::CoreError) -> ProtoError {
    match e {
        decant_core::CoreError::Pattern(message) => ProtoError::Backend { message },
        decant_core::CoreError::Backend(be) => be.into(),
    }
}

pub fn serve_connection(
    mut stream: TcpStream,
    backend: &dyn MemoryBackend,
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
    backend: Arc<dyn MemoryBackend>,
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
    use decant_backend::fixtures::{demo_backend, DEMO_MAGIC, DEMO_MAGIC_ADDR, DEMO_TARGET_PID};
    use decant_protocol::Pid;

    fn diag() -> Diag {
        Diag::new("mock")
    }

    #[test]
    fn dispatch_reads_planted_magic() {
        let b = demo_backend();
        let d = diag();
        let resp = dispatch(
            Request::Read { pid: DEMO_TARGET_PID, addr: DEMO_MAGIC_ADDR, len: 16 },
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
        let b = demo_backend();
        let d = diag();
        let w = dispatch(
            Request::Write { pid: DEMO_TARGET_PID, addr: 0x0001_4001_0400, data: vec![1, 2, 3, 4] },
            &b,
            &d,
        );
        assert!(matches!(w, Response::Written(4)));
        let r = dispatch(
            Request::Read { pid: DEMO_TARGET_PID, addr: 0x0001_4001_0400, len: 4 },
            &b,
            &d,
        );
        assert!(matches!(r, Response::Data(ref v) if v == &vec![1, 2, 3, 4]));
        assert_eq!(d.writes.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn dispatch_unknown_pid_is_structured_error() {
        let b = demo_backend();
        let d = diag();
        let resp = dispatch(Request::ProcessByPid(Pid(9999)), &b, &d);
        assert!(matches!(resp, Response::Err(ProtoError::NoSuchProcess { .. })));
    }
}
