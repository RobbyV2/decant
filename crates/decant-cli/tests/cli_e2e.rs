//! End-to-end test of the real `decant-cli` BINARY against an in-process server
//! (the real `decant_daemon::serve` over a real socket, `--backend mock`). This is
//! the CLI half of the Phase 1 autonomous gate: `processes`, `modules`, `read`,
//! `write`-then-read-back, and `diagnostics` all produce correct output against the
//! scripted demo guest, with no VM.
//!
//! We host the server in-process rather than spawning the daemon binary so the test
//! can pick an ephemeral port deterministically; the daemon *binary* is covered
//! separately by decant-daemon/tests/server_e2e.rs.

use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::Arc;

use decant_backend::fixtures::{demo_backend, DEMO_MAGIC_ADDR, DEMO_SLOT_ADDR};
use decant_backend::MemoryBackend;
use decant_daemon::{serve, Diag};

/// Start the real server on an OS-assigned port; return the port. The serving
/// thread is detached and dies when the test binary exits.
fn start_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().unwrap().port();
    let backend: Arc<dyn MemoryBackend> = Arc::new(demo_backend());
    let diag = Arc::new(Diag::new("mock"));
    std::thread::spawn(move || {
        let _ = serve(listener, backend, diag);
    });
    port
}

/// Run the CLI binary against `port` with `args`, returning its captured output.
fn cli(port: u16, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_decant-cli"))
        .arg("--endpoint")
        .arg(format!("127.0.0.1:{port}"))
        .args(args)
        .output()
        .expect("run decant-cli")
}

fn stdout_of(out: &Output) -> String {
    assert!(
        out.status.success(),
        "cli failed: status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn processes_lists_the_demo_guest() {
    let port = start_server();
    let out = cli(port, &["processes"]);
    let s = stdout_of(&out);
    assert!(s.contains("decant-target.exe"), "got: {s}");
    assert!(s.contains("1234"), "got: {s}");
    assert!(s.contains("explorer.exe"), "got: {s}");
}

#[test]
fn modules_lists_target_modules() {
    let port = start_server();
    let s = stdout_of(&cli(port, &["modules", "1234"]));
    assert!(s.contains("decant-target.exe"), "got: {s}");
    assert!(s.contains("kernel32.dll"), "got: {s}");
}

#[test]
fn read_shows_the_planted_magic() {
    let port = start_server();
    let addr = format!("{DEMO_MAGIC_ADDR:#x}");
    let s = stdout_of(&cli(port, &["read", "1234", &addr, "16"]));
    // The hex dump's ASCII gutter renders the printable magic prefix.
    assert!(s.contains("DECANT::MAGIC"), "got: {s}");
}

#[test]
fn write_then_read_back_round_trips() {
    let port = start_server();
    let addr = format!("{DEMO_SLOT_ADDR:#x}");

    let w = stdout_of(&cli(port, &["write", "1234", &addr, "aabbccdd"]));
    assert!(w.contains("wrote 4 bytes"), "got: {w}");

    let r = stdout_of(&cli(port, &["read", "1234", &addr, "4"]));
    assert!(r.contains("aa bb cc dd"), "got: {r}");
}

#[test]
fn diagnostics_reports_the_mock_connector() {
    let port = start_server();
    let s = stdout_of(&cli(port, &["diagnostics"]));
    assert!(s.contains("connector:"), "got: {s}");
    assert!(s.contains("mock"), "got: {s}");
}

#[test]
fn unknown_pid_is_a_clean_error_not_a_crash() {
    let port = start_server();
    let out = cli(port, &["modules", "999999"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("daemon error"), "stderr: {err}");
}
