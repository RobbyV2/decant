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
//!   demo         scripts/demo.sh if present, else explain
//!
//! Std-only arg parsing; no clap. The repo root is resolved from this crate's
//! manifest dir so the tool works from any cwd.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{bail, Context, Result};
use decant_wine_harness::run_under_wine;

/// The single cross-compile target for every Windows-side crate.
const WIN_TARGET: &str = "x86_64-pc-windows-gnu";

/// Crates that build ONLY for `WIN_TARGET`: the interposer plus the testbins.
const WIN_CRATES: &[&str] = &[
    "decant-interpose",
    "guest-target",
    "mock-cheat",
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
        "usage: cargo xtask <setup|build-native|build-dll|test|test-live|wine-smoke|demo>"
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
