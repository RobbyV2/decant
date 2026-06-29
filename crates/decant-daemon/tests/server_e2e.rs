//! End-to-end test of the real `decant-daemon` BINARY over a real TCP socket,
//! `--backend mock`. Spawns the daemon on an OS-assigned port, parses the port it
//! prints, then drives every request type with a raw `decant-protocol` client and
//! asserts against the scripted demo guest. This is half of the Phase 1 autonomous
//! gate ("the daemon binary serves correctly"); the CLI half lives in decant-cli.

use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};

use decant_backend::fixtures::{DEMO_MAGIC, DEMO_MAGIC_ADDR, DEMO_SLOT_ADDR, DEMO_TARGET_PID};
use decant_protocol::{read_msg, write_msg, Pid, ProtoError, Request, Response};

/// Kills the daemon when the test ends, pass or panic.
struct Daemon {
    child: Child,
    port: u16,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_daemon() -> Daemon {
    let exe = env!("CARGO_BIN_EXE_decant-daemon");
    let mut child = Command::new(exe)
        .args(["--backend", "mock", "--bind", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn decant-daemon");

    // The daemon prints "decant-daemon listening on 127.0.0.1:PORT (backend: mock)".
    let stdout = child.stdout.take().expect("daemon stdout");
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line).expect("read daemon banner");
    let addr = line
        .split("listening on ")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .unwrap_or_else(|| panic!("unexpected daemon banner: {line:?}"));
    let port = addr.rsplit(':').next().unwrap().parse().expect("daemon port");

    Daemon { child, port }
}

fn call(port: u16, req: Request) -> Response {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect daemon");
    write_msg(&mut stream, &req).expect("send request");
    read_msg(&mut stream).expect("read response")
}

#[test]
fn daemon_binary_serves_the_demo_guest() {
    let d = start_daemon();

    // Ping.
    assert!(matches!(call(d.port, Request::Ping), Response::Pong));

    // Processes: demo guest has decant-target.exe + explorer.exe.
    match call(d.port, Request::ListProcesses) {
        Response::Processes(ps) => {
            assert!(ps.iter().any(|p| p.name == "decant-target.exe" && p.pid == DEMO_TARGET_PID));
            assert!(ps.iter().any(|p| p.name == "explorer.exe"));
        }
        other => panic!("expected Processes, got {other:?}"),
    }

    // Modules of the target.
    match call(d.port, Request::ModuleList(DEMO_TARGET_PID)) {
        Response::Modules(ms) => {
            assert!(ms.iter().any(|m| m.name == "decant-target.exe"));
            assert!(ms.iter().any(|m| m.name == "kernel32.dll"));
        }
        other => panic!("expected Modules, got {other:?}"),
    }

    // Read the planted magic.
    match call(d.port, Request::Read { pid: DEMO_TARGET_PID, addr: DEMO_MAGIC_ADDR, len: 16 }) {
        Response::Data(bytes) => assert_eq!(bytes, DEMO_MAGIC),
        other => panic!("expected Data, got {other:?}"),
    }

    // Write the slot, read it back changed (the host-side write proof, offline).
    let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
    match call(d.port, Request::Write { pid: DEMO_TARGET_PID, addr: DEMO_SLOT_ADDR, data: payload.clone() }) {
        Response::Written(4) => {}
        other => panic!("expected Written(4), got {other:?}"),
    }
    match call(d.port, Request::Read { pid: DEMO_TARGET_PID, addr: DEMO_SLOT_ADDR, len: 4 }) {
        Response::Data(bytes) => assert_eq!(bytes, payload),
        other => panic!("expected Data, got {other:?}"),
    }

    // Unknown pid -> structured error, not a panic or a dropped connection.
    match call(d.port, Request::ProcessByPid(Pid(424242))) {
        Response::Err(ProtoError::NoSuchProcess { .. }) => {}
        other => panic!("expected NoSuchProcess, got {other:?}"),
    }

    // Diagnostics reflect the two reads + one write above (plus this connection's).
    match call(d.port, Request::Diagnostics) {
        Response::Diagnostics(diag) => {
            assert_eq!(diag.connector, "mock");
            assert!(diag.reads >= 2, "reads = {}", diag.reads);
            assert!(diag.writes >= 1, "writes = {}", diag.writes);
        }
        other => panic!("expected Diagnostics, got {other:?}"),
    }
}
