use std::net::TcpStream;
use std::time::Duration;

use decant_protocol::{
    Diagnostics, MemRegion, ModuleInfo, Pid, ProcessInfo, ProtoError, Request, Response, read_msg,
    write_msg,
};

pub use decant_protocol as protocol;

pub const DEFAULT_ENDPOINT: &str = "127.0.0.1:7878";

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Protocol(ProtoError),
    #[error("unexpected response: {0:?}")]
    Unexpected(Response),
}

pub type Result<T> = std::result::Result<T, ClientError>;

pub struct Client {
    endpoint: String,
    conn: Option<TcpStream>,
    timeout: Duration,
}

impl Client {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Client {
            endpoint: endpoint.into(),
            conn: None,
            timeout: Duration::from_secs(10),
        }
    }

    pub fn from_env() -> Self {
        Self::new(std::env::var("DECANT_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.into()))
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub fn send(&mut self, req: Request) -> Result<Response> {
        let mut last: Option<std::io::Error> = None;
        for _ in 0..2 {
            if self.conn.is_none() {
                let stream = TcpStream::connect(&self.endpoint)?;
                let _ = stream.set_nodelay(true);
                stream.set_read_timeout(Some(self.timeout))?;
                stream.set_write_timeout(Some(self.timeout))?;
                self.conn = Some(stream);
            }
            let stream = self.conn.as_mut().unwrap();
            match write_msg(stream, &req).and_then(|()| read_msg::<_, Response>(stream)) {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    self.conn = None;
                    last = Some(e);
                }
            }
        }
        Err(ClientError::Io(last.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "request failed")
        })))
    }

    pub fn ping(&mut self) -> Result<()> {
        expect(self.send(Request::Ping)?, |r| match r {
            Response::Pong => Ok(()),
            o => Err(o),
        })
    }

    pub fn processes(&mut self) -> Result<Vec<ProcessInfo>> {
        expect(self.send(Request::ListProcesses)?, |r| match r {
            Response::Processes(p) => Ok(p),
            o => Err(o),
        })
    }

    pub fn process_by_pid(&mut self, pid: Pid) -> Result<ProcessInfo> {
        expect(self.send(Request::ProcessByPid(pid))?, |r| match r {
            Response::Process(p) => Ok(p),
            o => Err(o),
        })
    }

    pub fn process_by_name(&mut self, name: &str) -> Result<ProcessInfo> {
        expect(
            self.send(Request::ProcessByName(name.to_string()))?,
            |r| match r {
                Response::Process(p) => Ok(p),
                o => Err(o),
            },
        )
    }

    pub fn modules(&mut self, pid: Pid) -> Result<Vec<ModuleInfo>> {
        expect(self.send(Request::ModuleList(pid))?, |r| match r {
            Response::Modules(m) => Ok(m),
            o => Err(o),
        })
    }

    pub fn module_by_name(&mut self, pid: Pid, name: &str) -> Result<ModuleInfo> {
        expect(
            self.send(Request::ModuleByName(pid, name.to_string()))?,
            |r| match r {
                Response::Module(m) => Ok(m),
                o => Err(o),
            },
        )
    }

    pub fn exports(&mut self, pid: Pid, module: &str) -> Result<Vec<(String, u64)>> {
        expect(
            self.send(Request::ModuleExports(pid, module.to_string()))?,
            |r| match r {
                Response::Exports(e) => Ok(e),
                o => Err(o),
            },
        )
    }

    pub fn read(&mut self, pid: Pid, addr: u64, len: usize) -> Result<Vec<u8>> {
        expect(
            self.send(Request::Read {
                pid,
                addr,
                len: len as u64,
            })?,
            |r| match r {
                Response::Data(d) => Ok(d),
                o => Err(o),
            },
        )
    }

    pub fn write(&mut self, pid: Pid, addr: u64, data: &[u8]) -> Result<usize> {
        expect(
            self.send(Request::Write {
                pid,
                addr,
                data: data.to_vec(),
            })?,
            |r| match r {
                Response::Written(n) => Ok(n as usize),
                o => Err(o),
            },
        )
    }

    pub fn memory_map(&mut self, pid: Pid) -> Result<Vec<MemRegion>> {
        expect(self.send(Request::MemoryMap(pid))?, |r| match r {
            Response::MemoryMap(m) => Ok(m),
            o => Err(o),
        })
    }

    pub fn scan(&mut self, pid: Pid, pattern: &str) -> Result<Vec<u64>> {
        expect(
            self.send(Request::Scan {
                pid,
                pattern: pattern.to_string(),
            })?,
            |r| match r {
                Response::ScanHits(h) => Ok(h),
                o => Err(o),
            },
        )
    }

    pub fn resolve(&mut self, pid: Pid, base: u64, offsets: &[u64]) -> Result<(u64, Vec<u8>)> {
        expect(
            self.send(Request::Resolve {
                pid,
                base,
                offsets: offsets.to_vec(),
            })?,
            |r| match r {
                Response::Resolved { address, value } => Ok((address, value)),
                o => Err(o),
            },
        )
    }

    pub fn diagnostics(&mut self) -> Result<Diagnostics> {
        expect(self.send(Request::Diagnostics)?, |r| match r {
            Response::Diagnostics(d) => Ok(d),
            o => Err(o),
        })
    }
}

fn expect<T>(
    resp: Response,
    f: impl FnOnce(Response) -> std::result::Result<T, Response>,
) -> Result<T> {
    match resp {
        Response::Err(e) => Err(ClientError::Protocol(e)),
        other => f(other).map_err(ClientError::Unexpected),
    }
}
