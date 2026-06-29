//! `cargo xtask` — build/test orchestration for Decant's mixed-target workspace.
//!
//! One entry point that knows the two facts a bare `cargo` call does not: which
//! crates are Windows-gnu-only (the interposer DLL + the testbins that run under
//! Wine or in the VM) and where the isolated Wine prefix lives. Subcommands:
//!
//!   setup        boot the repo-local Wine prefix (wine-env/setup.sh)
//!   build-native cargo build (host default-members)
//!   build-dll    cargo build --target x86_64-pc-windows-gnu for the Windows crates
//!   test         cargo test (host)
//!   test-live    placeholder; live VM tests need DECANT_LIVE=1 (Phase 1+)
//!   wine-smoke   THE Phase 0 gate: build hello-dll + dll-smoke, run under Wine,
//!                assert the DLL's add(2,3) prints 5
//!   spike        Phase 3 injection-vector spike (ADR-0006): build the carafe +
//!                mock-cheat + launcher, run rung 1 (cooperative) and rung 2c
//!                (launcher injection) under Wine, assert INTERCEPTED both ways
//!   demo         scripts/demo.sh if present, else explain
//!
//! Std-only arg parsing; no clap. The repo root is resolved from this crate's
//! manifest dir so the tool works from any cwd.

use std::env;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use decant_wine_harness::run_under_wine;

/// The single cross-compile target for every Windows-side crate.
const WIN_TARGET: &str = "x86_64-pc-windows-gnu";

/// Crates that build ONLY for `WIN_TARGET`: the interposer plus the testbins.
const WIN_CRATES: &[&str] = &[
    "decant-interpose",
    "guest-target",
    "mock-cheat",
    "decant-launcher",
    "dll-smoke",
    "hello-dll",
];

fn main() -> ExitCode {
    let cmd = env::args().nth(1).unwrap_or_default();
    let result = match cmd.as_str() {
        "setup" => setup(),
        "build-native" => build_native(),
        "build-dll" => build_dll(),
        "test" => test(),
        "test-live" => test_live(),
        "wine-smoke" => wine_smoke(),
        "spike" => spike(),
        "phase3" => phase3(),
        "demo" => demo(),
        other => {
            usage(other);
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask {cmd}: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn usage(unknown: &str) {
    if !unknown.is_empty() {
        eprintln!("xtask: unknown subcommand {unknown:?}");
    }
    eprintln!(
        "usage: cargo xtask \
         <setup|build-native|build-dll|test|test-live|wine-smoke|spike|phase3|demo>"
    );
}

/// Repo root = the workspace dir, one level up from this crate's manifest.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask manifest dir always has a parent")
        .to_path_buf()
}

/// A `cargo` invocation rooted at the workspace, honoring `$CARGO` if set so we use
/// the same toolchain that launched us.
fn cargo() -> Command {
    let bin = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut c = Command::new(bin);
    c.current_dir(repo_root());
    c
}

/// Run a child to completion, inheriting stdio, failing if it exits non-zero.
fn run(label: &str, cmd: &mut Command) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("failed to spawn: {label}"))?;
    if !status.success() {
        bail!("{label} exited with {status}");
    }
    Ok(())
}

fn setup() -> Result<()> {
    let script = repo_root().join("wine-env/setup.sh");
    run("wine-env/setup.sh", Command::new("bash").arg(&script))
}

fn build_native() -> Result<()> {
    run("cargo build", cargo().arg("build"))
}

fn build_dll() -> Result<()> {
    let mut c = cargo();
    c.args(["build", "--target", WIN_TARGET]);
    for krate in WIN_CRATES {
        c.args(["-p", krate]);
    }
    run("cargo build --target windows-gnu", &mut c)
}

fn test() -> Result<()> {
    run("cargo test", cargo().arg("test"))
}

fn test_live() -> Result<()> {
    println!(
        "test-live: skipped. Live tests drive a real Windows VM through memflow and \
         only run with DECANT_LIVE=1 plus a reachable guest (Phase 1+). There is no \
         VM in Phase 0, so nothing to do here yet."
    );
    Ok(())
}

/// Build `hello-dll` + `dll-smoke` for Windows, co-locate the DLL next to the exe in
/// a staging dir, run the exe under the isolated Wine prefix, and assert it prints 5.
///
/// This is the toolchain proof: Rust to PE cross-compile, DLL load under Wine, and an
/// exported-symbol call all working end to end before any real logic exists.
fn wine_smoke() -> Result<()> {
    let root = repo_root();

    let mut build = cargo();
    build.args(["build", "--target", WIN_TARGET, "-p", "hello-dll", "-p", "dll-smoke"]);
    run("cargo build hello-dll + dll-smoke", &mut build)?;

    // Ensure the prefix exists (idempotent; first boot can take ~30-60s).
    setup()?;

    let out_dir = root.join("target").join(WIN_TARGET).join("debug");
    let dll = out_dir.join("hello_dll.dll");
    let exe = out_dir.join("dll-smoke.exe");
    for artifact in [&dll, &exe] {
        if !artifact.exists() {
            bail!("expected build artifact missing: {}", artifact.display());
        }
    }

    // Stage both files in one directory. dll-smoke does LoadLibraryA("hello_dll.dll")
    // with a bare name, so the DLL must sit next to the exe (and the harness runs Wine
    // with that dir as cwd, where Windows looks first).
    let stage = root.join("target").join("wine-smoke");
    std::fs::create_dir_all(&stage)
        .with_context(|| format!("creating staging dir {}", stage.display()))?;
    let staged_dll = stage.join("hello_dll.dll");
    let staged_exe = stage.join("dll-smoke.exe");
    std::fs::copy(&dll, &staged_dll).context("staging hello_dll.dll")?;
    std::fs::copy(&exe, &staged_exe).context("staging dll-smoke.exe")?;

    let prefix = root.join("wine-env").join("prefix");
    let out = run_under_wine(&staged_exe, &[], &prefix, &[])
        .context("running dll-smoke.exe under Wine")?;

    let stdout = out.stdout.trim();
    println!("wine-smoke: dll-smoke.exe stdout={stdout:?} exit={}", out.status);

    if out.ok_with("5") {
        println!("wine-smoke: PASS");
        Ok(())
    } else {
        if !out.stderr.trim().is_empty() {
            eprintln!("wine-smoke: stderr:\n{}", out.stderr);
        }
        bail!("wine-smoke: FAIL (expected stdout to contain 5 and exit 0)");
    }
}

/// Phase 3 injection-vector spike (ADR-0006). Builds the carafe, the unmodified
/// `mock-cheat`, and the launcher; stages them next to each other; then drives the
/// two rungs that pass on Wine and asserts the marker interception:
///
///   * rung 1 (cooperative): `mock-cheat --cooperative` loads the carafe and calls
///     its installer itself → expect `INTERCEPTED`.
///   * baseline (control):   `mock-cheat` with no injection → expect `passthrough`.
///   * rung 2c (no coop):    `decant-launcher mock-cheat.exe` with
///     `DECANT_AUTOHOOK=1` injects the carafe by remote thread; the carafe's
///     `DllMain` installs the hooks into the *unmodified* tool → expect
///     `INTERCEPTED`.
///
/// This is the runnable proof behind ADR-0006; see `docs/DECISIONS.md` for the
/// rung-2a (`AppInit_DLLs`) finding (a no-op stub on Wine 11.11).
fn spike() -> Result<()> {
    let root = repo_root();

    let mut build = cargo();
    build.args([
        "build", "--target", WIN_TARGET, "-p", "decant-interpose", "-p", "mock-cheat",
        "-p", "decant-launcher",
    ]);
    run("cargo build carafe + mock-cheat + launcher", &mut build)?;

    setup()?;

    let out_dir = root.join("target").join(WIN_TARGET).join("debug");
    let stage = root.join("target").join("spike-stage");
    std::fs::create_dir_all(&stage)
        .with_context(|| format!("creating staging dir {}", stage.display()))?;
    for name in ["decant_interpose.dll", "mock-cheat.exe", "decant-launcher.exe"] {
        let src = out_dir.join(name);
        if !src.exists() {
            bail!("expected build artifact missing: {}", src.display());
        }
        std::fs::copy(&src, stage.join(name)).with_context(|| format!("staging {name}"))?;
    }

    let prefix = root.join("wine-env").join("prefix");
    let mock = stage.join("mock-cheat.exe");
    let launcher = stage.join("decant-launcher.exe");
    let autohook = [("DECANT_AUTOHOOK", "1")];

    // The spike uses mock-cheat's daemon-free `--spike` self-test: a synthetic-range
    // handle fed to CloseHandle returns TRUE only if the carafe is installed. This
    // proves the injection vector + IAT patch with no daemon (the full daemon path
    // is `cargo xtask phase3`).

    // Rung 1 — cooperative bootstrap.
    let r1 = run_under_wine(&mock, &["--cooperative", "--spike"], &prefix, &[])
        .context("running rung 1 (cooperative)")?;
    println!("spike rung 1 (cooperative): stdout={:?}", r1.stdout.trim());
    if !r1.ok_with("INTERCEPTED") {
        eprintln!("stderr:\n{}", r1.stderr);
        bail!("rung 1 FAIL: expected INTERCEPTED");
    }

    // Baseline control — no injection at all.
    let base = run_under_wine(&mock, &["--spike"], &prefix, &[]).context("running baseline")?;
    println!("spike baseline (no inject): stdout={:?}", base.stdout.trim());
    if !base.ok_with("passthrough") {
        bail!("baseline FAIL: expected passthrough (the test cannot discriminate!)");
    }

    // Rung 2c — launcher injects the carafe into the UNMODIFIED mock-cheat.
    let r2 = run_under_wine(&launcher, &["mock-cheat.exe", "--spike"], &prefix, &autohook)
        .context("running rung 2c (launcher injection)")?;
    println!("spike rung 2c (launcher): stdout={:?}", r2.stdout.trim());
    if !r2.ok_with("INTERCEPTED") {
        eprintln!("stderr:\n{}", r2.stderr);
        bail!("rung 2c FAIL: expected INTERCEPTED on the unmodified tool");
    }

    println!("spike: PASS (rung 1 + rung 2c both INTERCEPTED; baseline passthrough)");
    Ok(())
}

/// THE Phase 3 autonomous gate (no VM). Builds the carafe + launcher + full
/// `mock-cheat` (windows-gnu) and the host daemon/cli; starts the daemon on a
/// loopback port serving the deterministic demo guest (`--backend mock`); launches
/// the *unmodified* `mock-cheat` under Wine through `decant-launcher` with
/// `DECANT_AUTOHOOK=1` + `DECANT_ENDPOINT` so the carafe injects, self-installs, and
/// routes the tool's Win32 calls to the daemon; then asserts `mock-cheat: ALL PASS`.
///
/// Wine reaches the host daemon because `127.0.0.1` inside Wine is the host loopback
/// (ADR-0002).
fn phase3() -> Result<()> {
    let root = repo_root();

    // 1. Build the Windows crates and the host daemon/cli.
    let mut wbuild = cargo();
    wbuild.args([
        "build", "--target", WIN_TARGET, "-p", "decant-interpose", "-p", "mock-cheat", "-p",
        "decant-launcher",
    ]);
    run("cargo build carafe + mock-cheat + launcher", &mut wbuild)?;
    run(
        "cargo build daemon + cli",
        cargo().args(["build", "-p", "decant-daemon", "-p", "decant-cli"]),
    )?;

    setup()?;

    // Stage the three Windows artifacts next to each other (launcher injects the
    // sibling DLL; mock-cheat's stdout is inherited up through the launcher).
    let out_dir = root.join("target").join(WIN_TARGET).join("debug");
    let stage = root.join("target").join("phase3-stage");
    std::fs::create_dir_all(&stage)
        .with_context(|| format!("creating staging dir {}", stage.display()))?;
    for name in ["decant_interpose.dll", "mock-cheat.exe", "decant-launcher.exe"] {
        let src = out_dir.join(name);
        if !src.exists() {
            bail!("expected build artifact missing: {}", src.display());
        }
        std::fs::copy(&src, stage.join(name)).with_context(|| format!("staging {name}"))?;
    }

    // 2. Start the daemon on 127.0.0.1:0 and read back the chosen port.
    let daemon_bin = root.join("target").join("debug").join("decant-daemon");
    if !daemon_bin.exists() {
        bail!("daemon binary missing: {}", daemon_bin.display());
    }
    let mut daemon = Command::new(&daemon_bin)
        .args(["--backend", "mock", "--bind", "127.0.0.1:0"])
        .current_dir(&root)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("spawning decant-daemon")?;

    let endpoint = {
        let stdout = daemon
            .stdout
            .take()
            .ok_or_else(|| anyhow!("daemon stdout not captured"))?;
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .context("reading daemon listening line")?;
        // "decant-daemon listening on 127.0.0.1:PORT (backend: mock)"
        line.split("listening on ")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("could not parse daemon port from: {line:?}"))?
    };
    println!("phase3: daemon up, DECANT_ENDPOINT={endpoint}");

    // 3. Launch the UNMODIFIED mock-cheat under Wine via the launcher. Always kill
    //    the daemon afterward, success or failure.
    let launcher = stage.join("decant-launcher.exe");
    let prefix = root.join("wine-env").join("prefix");
    let run_result = run_under_wine(
        &launcher,
        &["mock-cheat.exe"],
        &prefix,
        &[("DECANT_AUTOHOOK", "1"), ("DECANT_ENDPOINT", &endpoint)],
    );
    let _ = daemon.kill();
    let _ = daemon.wait();

    let out = run_result.context("running mock-cheat under Wine via launcher")?;

    // 4. Echo the tool's per-check lines and assert ALL PASS.
    println!("--- mock-cheat output ---");
    for l in out.stdout.lines() {
        println!("{l}");
    }
    if !out.stderr.trim().is_empty() {
        eprintln!("--- mock-cheat stderr ---\n{}", out.stderr.trim());
    }
    println!("-------------------------");

    if out.status == 0 && out.stdout.contains("mock-cheat: ALL PASS") {
        println!("phase3: PASS");
        Ok(())
    } else {
        bail!(
            "phase3: FAIL (exit={}, missing 'mock-cheat: ALL PASS'). See check lines above.",
            out.status
        );
    }
}

fn demo() -> Result<()> {
    let script = repo_root().join("scripts/demo.sh");
    if script.exists() {
        return run("scripts/demo.sh", Command::new("bash").arg(&script));
    }
    println!(
        "demo: no scripts/demo.sh yet. The end-to-end demo (cheat tool under Wine \
         editing a live VM's memory through the daemon) lands in a later phase; for \
         now `cargo xtask wine-smoke` is the runnable proof."
    );
    Ok(())
}
