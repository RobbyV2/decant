//! # decant-protocol — "the funnel"
//!
//! The shared, type-checked RPC contract between the Linux-side **daemon** ("the
//! cellar") and the Windows-side **interposer DLL** ("the carafe"). Both ends
//! depend on this crate, so the wire format cannot drift: a change here is a
//! compile error on both sides at once. That is the core Rust advantage Decant
//! leans on (spec §2.2).
//!
//! This crate is also the home of the shared *domain types* (`Pid`,
//! `ProcessInfo`, `ModuleInfo`, `MemRegion`). The `MemoryBackend` trait
//! (`decant-backend`) re-uses these so there is no marshaling boilerplate
//! between the trait layer and the wire layer (see ADR-0001).
//!
//! ## Framing
//!
//! Messages are length-prefixed: a little-endian `u32` byte count followed by a
//! `bincode`-serialized payload. [`write_msg`] / [`read_msg`] implement this over
//! any [`std::io::Read`]/[`Write`], which over a localhost TCP stream is exactly
//! the transport the daemon and DLL use.
//!
//! ## Target portability
//!
//! Pure `serde` + `bincode`; compiles unchanged for `x86_64-unknown-linux-gnu`
//! (daemon) and `x86_64-pc-windows-gnu` (DLL). No platform-specific code lives here.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// A guest process id, as the guest OS sees it (not a Wine/host pid).
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

/// A guest process, as enumerated from memflow data (not from wineserver).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: Pid,
    pub name: String,
}

/// A loaded module (PE image) inside a guest process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub base: u64,
    pub size: u64,
}

/// A virtual-memory region of a guest process. Derived best-effort from the
/// VAD / page map; coarser than native per-page protection (spec §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemRegion {
    pub base: u64,
    pub size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

/// Daemon health/observability snapshot, surfaced by `decant-cli diagnostics`.
/// `exec_wall_hits` counts execution-wall refusals (spec §9) so the user can see
/// when a tool tried to do something memflow cannot.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Diagnostics {
    pub connector: String,
    pub reads: u64,
    pub writes: u64,
    pub exec_wall_hits: u64,
}

/// A structured, wire-stable error. Backends map their internal errors into this
/// before it crosses the socket; the DLL maps it back to a Win32 failure code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtoError {
    NoSuchProcess { pid: Option<u32>, name: Option<String> },
    NoSuchModule { pid: u32, module: String },
    ReadFailed { addr: u64, len: u64, reason: String },
    WriteFailed { addr: u64, reason: String },
    /// The tool asked for something requiring guest execution (alloc, remote
    /// thread, injection…). memflow cannot do this — fail loudly, never fake it.
    ExecutionWall { op: String },
    /// Catch-all for backend/connector failures.
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
            ProtoError::ExecutionWall { op } => {
                write!(f, "execution wall: {op} requires guest execution, which memflow cannot do")
            }
            ProtoError::Backend { message } => write!(f, "backend error: {message}"),
        }
    }
}

impl std::error::Error for ProtoError {}

/// A request from the carafe (DLL) to the cellar (daemon). Mirrors the
/// `MemoryBackend` trait primitives one-to-one (the narrow waist, spec §2.1).
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
    // --- Phase 2 analysis (appended; bincode variant indices above are unchanged,
    //     so this extension is wire-compatible with the frozen set above). ---
    /// AOB/signature scan; `pattern` is space-separated hex bytes with `??`
    /// wildcards, e.g. `"DE CA ?? 00 4D"`.
    Scan { pid: Pid, pattern: String },
    /// Resolve a pointer chain: `address = base; for off in offsets { address =
    /// deref_u64(address) + off }`.
    Resolve { pid: Pid, base: u64, offsets: Vec<u64> },
}

/// A response from the cellar to the carafe. `Err` carries a structured
/// [`ProtoError`] rather than a string so the DLL can pick the right Win32 code.
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
    // --- Phase 2 analysis (appended; see Request note). ---
    /// Absolute addresses where a scan pattern matched.
    ScanHits(Vec<u64>),
    /// A resolved pointer chain: the final `address` plus the 8 bytes read there
    /// (`value`, empty if that address was unreadable).
    Resolved { address: u64, value: Vec<u8> },
}

/// Hard ceiling on a single framed message (64 MiB). Guards the reader against a
/// hostile/corrupt length prefix allocating unboundedly.
pub const MAX_MSG_LEN: u32 = 64 * 1024 * 1024;

fn enc_err(e: bincode::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// Serialize `msg` and write it length-prefixed (LE u32 + bincode payload).
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

/// Read one length-prefixed message and deserialize it. Returns
/// [`io::ErrorKind::UnexpectedEof`] cleanly on a closed connection.
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
        roundtrip_resp(Response::Err(ProtoError::ExecutionWall { op: "VirtualAllocEx".into() }));
        roundtrip_resp(Response::ScanHits(vec![0x1400010100, 0x1400010200]));
        roundtrip_resp(Response::Resolved { address: 0x1400010290, value: vec![0x39, 5, 0, 0] });
    }

    #[test]
    fn oversized_length_prefix_is_rejected() {
        // A hostile 0xFFFFFFFF length prefix must error, not allocate 4 GiB.
        let mut bytes = (u32::MAX).to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 8]);
        let mut cur = Cursor::new(bytes);
        let got: io::Result<Request> = read_msg(&mut cur);
        assert!(got.is_err());
    }

    #[test]
    fn truncated_stream_reports_eof() {
        let buf: Vec<u8> = vec![10, 0, 0, 0, 1, 2]; // claims 10 bytes, only 2 present
        let mut cur = Cursor::new(buf);
        let got: io::Result<Request> = read_msg(&mut cur);
        assert_eq!(got.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn two_messages_back_to_back() {
        // Framing must let two messages share a stream without bleeding.
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
