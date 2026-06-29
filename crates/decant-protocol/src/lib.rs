use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Pid(pub u32);

impl std::fmt::Display for Pid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for Pid {
    fn from(v: u32) -> Self {
        Pid(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: Pid,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub base: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemRegion {
    pub base: u64,
    pub size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Diagnostics {
    pub connector: String,
    pub reads: u64,
    pub writes: u64,
    pub unsupported_ops: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtoError {
    NoSuchProcess { pid: Option<u32>, name: Option<String> },
    NoSuchModule { pid: u32, module: String },
    ReadFailed { addr: u64, len: u64, reason: String },
    WriteFailed { addr: u64, reason: String },
    Unsupported { op: String },
    Backend { message: String },
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtoError::NoSuchProcess { pid, name } => {
                write!(f, "no such process (pid={pid:?}, name={name:?})")
            }
            ProtoError::NoSuchModule { pid, module } => {
                write!(f, "no such module {module:?} in pid {pid}")
            }
            ProtoError::ReadFailed { addr, len, reason } => {
                write!(f, "read of {len} bytes at {addr:#x} failed: {reason}")
            }
            ProtoError::WriteFailed { addr, reason } => {
                write!(f, "write at {addr:#x} failed: {reason}")
            }
            ProtoError::Unsupported { op } => {
                write!(f, "unsupported operation: {op} requires guest execution, which memflow cannot perform")
            }
            ProtoError::Backend { message } => write!(f, "backend error: {message}"),
        }
    }
}

impl std::error::Error for ProtoError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    Ping,
    ListProcesses,
    ProcessByPid(Pid),
    ProcessByName(String),
    ModuleList(Pid),
    ModuleByName(Pid, String),
    ModuleExports(Pid, String),
    Read { pid: Pid, addr: u64, len: u64 },
    Write { pid: Pid, addr: u64, data: Vec<u8> },
    MemoryMap(Pid),
    Diagnostics,
    Scan { pid: Pid, pattern: String },
    Resolve { pid: Pid, base: u64, offsets: Vec<u64> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Pong,
    Processes(Vec<ProcessInfo>),
    Process(ProcessInfo),
    Modules(Vec<ModuleInfo>),
    Module(ModuleInfo),
    Exports(Vec<(String, u64)>),
    Data(Vec<u8>),
    Written(u64),
    MemoryMap(Vec<MemRegion>),
    Diagnostics(Diagnostics),
    Err(ProtoError),
    ScanHits(Vec<u64>),
    Resolved { address: u64, value: Vec<u8> },
}

pub const MAX_MSG_LEN: u32 = 64 * 1024 * 1024;

fn enc_err(e: bincode::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let bytes = bincode::serialize(msg).map_err(enc_err)?;
    if bytes.len() as u64 > MAX_MSG_LEN as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {} bytes (max {MAX_MSG_LEN})", bytes.len()),
        ));
    }
    w.write_all(&(bytes.len() as u32).to_le_bytes())?;
    w.write_all(&bytes)?;
    w.flush()
}

pub fn read_msg<R: Read, T: DeserializeOwned>(r: &mut R) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_MSG_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("incoming message length {len} exceeds max {MAX_MSG_LEN}"),
        ));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    bincode::deserialize(&buf).map_err(enc_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn roundtrip_req(req: Request) {
        let mut buf = Vec::new();
        write_msg(&mut buf, &req).unwrap();
        let mut cur = Cursor::new(buf);
        let got: Request = read_msg(&mut cur).unwrap();
        assert_eq!(req, got);
    }

    fn roundtrip_resp(resp: Response) {
        let mut buf = Vec::new();
        write_msg(&mut buf, &resp).unwrap();
        let mut cur = Cursor::new(buf);
        let got: Response = read_msg(&mut cur).unwrap();
        assert_eq!(resp, got);
    }

    #[test]
    fn requests_roundtrip() {
        roundtrip_req(Request::Ping);
        roundtrip_req(Request::ListProcesses);
        roundtrip_req(Request::ProcessByPid(Pid(1234)));
        roundtrip_req(Request::ProcessByName("target.exe".into()));
        roundtrip_req(Request::ModuleList(Pid(1)));
        roundtrip_req(Request::ModuleByName(Pid(1), "ntdll.dll".into()));
        roundtrip_req(Request::ModuleExports(Pid(1), "kernel32.dll".into()));
        roundtrip_req(Request::Read { pid: Pid(7), addr: 0x1400010000, len: 64 });
        roundtrip_req(Request::Write { pid: Pid(7), addr: 0xdead, data: vec![1, 2, 3, 4] });
        roundtrip_req(Request::MemoryMap(Pid(7)));
        roundtrip_req(Request::Diagnostics);
        roundtrip_req(Request::Scan { pid: Pid(7), pattern: "DE CA ?? 00".into() });
        roundtrip_req(Request::Resolve { pid: Pid(7), base: 0x1000, offsets: vec![0x10, 0x18] });
    }

    #[test]
    fn responses_roundtrip() {
        roundtrip_resp(Response::Pong);
        roundtrip_resp(Response::Processes(vec![ProcessInfo {
            pid: Pid(1234),
            name: "target.exe".into(),
        }]));
        roundtrip_resp(Response::Process(ProcessInfo { pid: Pid(1), name: "a".into() }));
        roundtrip_resp(Response::Modules(vec![ModuleInfo {
            name: "m.dll".into(),
            base: 0x1400000000,
            size: 0x80000,
        }]));
        roundtrip_resp(Response::Module(ModuleInfo { name: "m".into(), base: 0, size: 1 }));
        roundtrip_resp(Response::Exports(vec![("add".into(), 0x1000)]));
        roundtrip_resp(Response::Data(vec![0xde, 0xad, 0xbe, 0xef]));
        roundtrip_resp(Response::Written(64));
        roundtrip_resp(Response::MemoryMap(vec![MemRegion {
            base: 0x1000,
            size: 0x2000,
            readable: true,
            writable: true,
            executable: false,
        }]));
        roundtrip_resp(Response::Diagnostics(Diagnostics::default()));
        roundtrip_resp(Response::Err(ProtoError::Unsupported { op: "VirtualAllocEx".into() }));
        roundtrip_resp(Response::ScanHits(vec![0x1400010100, 0x1400010200]));
        roundtrip_resp(Response::Resolved { address: 0x1400010290, value: vec![0x39, 5, 0, 0] });
    }

    #[test]
    fn oversized_length_prefix_is_rejected() {
        let mut bytes = (u32::MAX).to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 8]);
        let mut cur = Cursor::new(bytes);
        let got: io::Result<Request> = read_msg(&mut cur);
        assert!(got.is_err());
    }

    #[test]
    fn truncated_stream_reports_eof() {
        let buf: Vec<u8> = vec![10, 0, 0, 0, 1, 2];
        let mut cur = Cursor::new(buf);
        let got: io::Result<Request> = read_msg(&mut cur);
        assert_eq!(got.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn two_messages_back_to_back() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &Request::Ping).unwrap();
        write_msg(&mut buf, &Request::ProcessByPid(Pid(9))).unwrap();
        let mut cur = Cursor::new(buf);
        assert_eq!(read_msg::<_, Request>(&mut cur).unwrap(), Request::Ping);
        assert_eq!(
            read_msg::<_, Request>(&mut cur).unwrap(),
            Request::ProcessByPid(Pid(9))
        );
    }
}
