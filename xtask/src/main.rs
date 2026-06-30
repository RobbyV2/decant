use std::env;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use decant_wine_harness::run_under_wine;

const WIN_TARGET: &str = "x86_64-pc-windows-gnu";

const WIN_CRATES: &[&str] = &[
    "decant-interpose",
    "guest-target",
    "sample-tool",
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
        "inject-test" => inject_test(),
        "e2e" => e2e(),
        "dynamic" => dynamic(),
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
         <setup|build-native|build-dll|test|test-live|wine-smoke|inject-test|e2e|dynamic|demo>"
    );
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask manifest dir always has a parent")
        .to_path_buf()
}

fn cargo() -> Command {
    let bin = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut c = Command::new(bin);
    c.current_dir(repo_root());
    c
}

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
        "test-live: skipped. VM tests drive a real Windows VM through memflow and \
         only run with DECANT_LIVE=1 plus a reachable guest. With no VM present \
         there is nothing to do here."
    );
    Ok(())
}

fn wine_smoke() -> Result<()> {
    let root = repo_root();

    let mut build = cargo();
    build.args([
        "build",
        "--target",
        WIN_TARGET,
        "-p",
        "hello-dll",
        "-p",
        "dll-smoke",
    ]);
    run("cargo build hello-dll + dll-smoke", &mut build)?;

    setup()?;

    let out_dir = root.join("target").join(WIN_TARGET).join("debug");
    let dll = out_dir.join("hello_dll.dll");
    let exe = out_dir.join("dll-smoke.exe");
    for artifact in [&dll, &exe] {
        if !artifact.exists() {
            bail!("expected build artifact missing: {}", artifact.display());
        }
    }

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
    println!(
        "wine-smoke: dll-smoke.exe stdout={stdout:?} exit={}",
        out.status
    );

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

fn inject_test() -> Result<()> {
    let root = repo_root();

    let mut build = cargo();
    build.args([
        "build",
        "--target",
        WIN_TARGET,
        "-p",
        "decant-interpose",
        "-p",
        "sample-tool",
        "-p",
        "decant-launcher",
    ]);
    run("cargo build carafe + sample-tool + launcher", &mut build)?;

    setup()?;

    let out_dir = root.join("target").join(WIN_TARGET).join("debug");
    let stage = root.join("target").join("inject-test-stage");
    std::fs::create_dir_all(&stage)
        .with_context(|| format!("creating staging dir {}", stage.display()))?;
    for name in [
        "decant_interpose.dll",
        "sample-tool.exe",
        "decant-launcher.exe",
    ] {
        let src = out_dir.join(name);
        if !src.exists() {
            bail!("expected build artifact missing: {}", src.display());
        }
        std::fs::copy(&src, stage.join(name)).with_context(|| format!("staging {name}"))?;
    }

    let prefix = root.join("wine-env").join("prefix");
    let mock = stage.join("sample-tool.exe");
    let launcher = stage.join("decant-launcher.exe");
    let autohook = [("DECANT_AUTOHOOK", "1")];

    let r1 = run_under_wine(&mock, &["--cooperative", "--inject-test"], &prefix, &[])
        .context("running cooperative bootstrap")?;
    println!(
        "inject-test cooperative bootstrap: stdout={:?}",
        r1.stdout.trim()
    );
    if !r1.ok_with("INTERCEPTED") {
        eprintln!("stderr:\n{}", r1.stderr);
        bail!("cooperative bootstrap FAIL: expected INTERCEPTED");
    }

    let base =
        run_under_wine(&mock, &["--inject-test"], &prefix, &[]).context("running baseline")?;
    println!(
        "inject-test baseline (no inject): stdout={:?}",
        base.stdout.trim()
    );
    if !base.ok_with("passthrough") {
        bail!("baseline FAIL: expected passthrough (the test cannot discriminate!)");
    }

    let r2 = run_under_wine(
        &launcher,
        &["sample-tool.exe", "--inject-test"],
        &prefix,
        &autohook,
    )
    .context("running launcher injection")?;
    println!(
        "inject-test launcher injection: stdout={:?}",
        r2.stdout.trim()
    );
    if !r2.ok_with("INTERCEPTED") {
        eprintln!("stderr:\n{}", r2.stderr);
        bail!("launcher injection FAIL: expected INTERCEPTED on the unmodified tool");
    }

    println!(
        "inject-test: PASS (cooperative bootstrap + launcher injection both INTERCEPTED; baseline passthrough)"
    );
    Ok(())
}

fn build_and_stage(root: &Path, stage_name: &str) -> Result<PathBuf> {
    let out_dir = root.join("target").join(WIN_TARGET).join("debug");
    let stage = root.join("target").join(stage_name);
    std::fs::create_dir_all(&stage)
        .with_context(|| format!("creating staging dir {}", stage.display()))?;
    for name in [
        "decant_interpose.dll",
        "sample-tool.exe",
        "decant-launcher.exe",
    ] {
        let src = out_dir.join(name);
        if !src.exists() {
            bail!("expected build artifact missing: {}", src.display());
        }
        std::fs::copy(&src, stage.join(name)).with_context(|| format!("staging {name}"))?;
    }
    Ok(stage)
}

fn spawn_mock_daemon(root: &Path) -> Result<(std::process::Child, String)> {
    let daemon_bin = root.join("target").join("debug").join("decant-daemon");
    if !daemon_bin.exists() {
        bail!("daemon binary missing: {}", daemon_bin.display());
    }
    let mut daemon = Command::new(&daemon_bin)
        .args(["--backend", "mock", "--bind", "127.0.0.1:0"])
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("spawning decant-daemon")?;
    let stdout = daemon
        .stdout
        .take()
        .ok_or_else(|| anyhow!("daemon stdout not captured"))?;
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("reading daemon listening line")?;
    let endpoint = line
        .split("listening on ")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("could not parse daemon port from: {line:?}"))?;
    Ok((daemon, endpoint))
}

fn e2e() -> Result<()> {
    let root = repo_root();

    let mut wbuild = cargo();
    wbuild.args([
        "build",
        "--target",
        WIN_TARGET,
        "-p",
        "decant-interpose",
        "-p",
        "sample-tool",
        "-p",
        "decant-launcher",
    ]);
    run("cargo build carafe + sample-tool + launcher", &mut wbuild)?;
    run(
        "cargo build daemon + cli",
        cargo().args(["build", "-p", "decant-daemon", "-p", "decant-cli"]),
    )?;

    setup()?;

    let stage = build_and_stage(&root, "e2e-stage")?;

    let (mut daemon, endpoint) = spawn_mock_daemon(&root)?;
    println!("e2e: daemon up, DECANT_ENDPOINT={endpoint}");

    let launcher = stage.join("decant-launcher.exe");
    let prefix = root.join("wine-env").join("prefix");
    let run_result = run_under_wine(
        &launcher,
        &["sample-tool.exe"],
        &prefix,
        &[("DECANT_AUTOHOOK", "1"), ("DECANT_ENDPOINT", &endpoint)],
    );

    let diag = decant_client::Client::new(&endpoint)
        .diagnostics()
        .context("querying daemon diagnostics");

    let _ = daemon.kill();
    let _ = daemon.wait();

    let out = run_result.context("running sample-tool under Wine via launcher")?;

    println!("sample-tool output");
    for l in out.stdout.lines() {
        println!("{l}");
    }
    if !out.stderr.trim().is_empty() {
        eprintln!("sample-tool stderr\n{}", out.stderr.trim());
    }

    if out.status != 0 || !out.stdout.contains("sample-tool: ALL PASS") {
        bail!(
            "e2e: FAIL (exit={}, missing 'sample-tool: ALL PASS'). See check lines above.",
            out.status
        );
    }

    let diag = diag?;
    println!(
        "e2e: daemon reports unsupported_ops={}",
        diag.unsupported_ops
    );
    if diag.unsupported_ops < 1 {
        bail!("e2e: FAIL (expected unsupported_ops >= 1 after the refused VirtualAllocEx)");
    }

    println!("e2e: PASS");
    Ok(())
}

fn dynamic() -> Result<()> {
    let root = repo_root();

    let mut wbuild = cargo();
    wbuild.args([
        "build",
        "--target",
        WIN_TARGET,
        "-p",
        "decant-interpose",
        "-p",
        "sample-tool",
        "-p",
        "decant-launcher",
    ]);
    run("cargo build carafe + sample-tool + launcher", &mut wbuild)?;
    run(
        "cargo build daemon",
        cargo().args(["build", "-p", "decant-daemon"]),
    )?;

    setup()?;

    let stage = build_and_stage(&root, "dynamic-stage")?;

    let (mut daemon, endpoint) = spawn_mock_daemon(&root)?;
    println!("dynamic: daemon up, DECANT_ENDPOINT={endpoint}");

    let launcher = stage.join("decant-launcher.exe");
    let prefix = root.join("wine-env").join("prefix");
    let run_result = run_under_wine(
        &launcher,
        &["sample-tool.exe", "--dynamic"],
        &prefix,
        &[("DECANT_AUTOHOOK", "1"), ("DECANT_ENDPOINT", &endpoint)],
    );

    let _ = daemon.kill();
    let _ = daemon.wait();

    let out = run_result.context("running sample-tool --dynamic under Wine via launcher")?;
    for l in out.stdout.lines() {
        println!("{l}");
    }
    if !out.stderr.trim().is_empty() {
        eprintln!("sample-tool stderr\n{}", out.stderr.trim());
    }
    if out.status != 0 || !out.stdout.contains("sample-tool dynamic: ALL PASS") {
        bail!(
            "dynamic: FAIL (exit={}, missing 'sample-tool dynamic: ALL PASS')",
            out.status
        );
    }
    println!("dynamic: PASS");
    Ok(())
}

fn demo() -> Result<()> {
    let script = repo_root().join("scripts/demo.sh");
    if script.exists() {
        return run("scripts/demo.sh", Command::new("bash").arg(&script));
    }
    println!(
        "demo: no scripts/demo.sh yet. The end-to-end demo (cheat tool under Wine \
         editing a VM's memory through the daemon) is not wired up here; for \
         now `cargo xtask wine-smoke` is the runnable proof."
    );
    Ok(())
}
