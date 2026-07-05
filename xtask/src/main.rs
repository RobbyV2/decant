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
    "decant-plugin-standard",
    "decant-external-standard",
    "dll-smoke",
    "hello-dll",
    "guest-inject-fixture",
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
        "guest-inject-fixture" => guest_inject_fixture(),
        "inject-test" => inject_test(),
        "e2e" => e2e(),
        "dynamic" => dynamic(),
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
         <setup|build-native|build-dll|test|test-live|wine-smoke|guest-inject-fixture|inject-test|e2e|dynamic>"
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

fn guest_inject_fixture() -> Result<()> {
    let root = repo_root();

    let mut build = cargo();
    build.args([
        "build",
        "--target",
        WIN_TARGET,
        "-p",
        "guest-inject-fixture",
    ]);
    run("cargo build guest-inject-fixture", &mut build)?;

    setup()?;

    let out_dir = root.join("target").join(WIN_TARGET).join("debug");
    let dll = out_dir.join("guest_inject_probe.dll");
    let exe = out_dir.join("guest-inject-target.exe");
    for artifact in [&dll, &exe] {
        if !artifact.exists() {
            bail!("expected build artifact missing: {}", artifact.display());
        }
    }

    let stage = root.join("target").join("guest-inject-fixture");
    std::fs::create_dir_all(&stage)
        .with_context(|| format!("creating staging dir {}", stage.display()))?;
    std::fs::copy(&dll, stage.join("guest_inject_probe.dll"))
        .context("staging guest_inject_probe.dll")?;
    std::fs::copy(&exe, stage.join("guest-inject-target.exe"))
        .context("staging guest-inject-target.exe")?;

    let prefix = root.join("wine-env").join("prefix");
    let out = run_under_wine(
        &stage.join("guest-inject-target.exe"),
        &["--self-load", "guest_inject_probe.dll"],
        &prefix,
        &[],
    )
    .context("running guest-inject fixture under Wine")?;

    println!(
        "guest-inject-fixture: stdout={:?} exit={}",
        out.stdout.trim(),
        out.status
    );
    if out.ok_with("guest-inject-target: self-load PASS") {
        println!("guest-inject-fixture: PASS");
        println!("guest-inject-fixture: exe={}", exe.display());
        println!("guest-inject-fixture: dll={}", dll.display());
        Ok(())
    } else {
        if !out.stderr.trim().is_empty() {
            eprintln!("guest-inject-fixture: stderr:\n{}", out.stderr);
        }
        bail!("guest-inject-fixture: FAIL");
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
        "-p",
        "decant-plugin-standard",
        "-p",
        "decant-external-standard",
    ]);
    run(
        "cargo build carafe + sample-tool + launcher + plugin + external",
        &mut build,
    )?;

    setup()?;

    let out_dir = root.join("target").join(WIN_TARGET).join("debug");
    let stage = root.join("target").join("inject-test-stage");
    std::fs::create_dir_all(&stage)
        .with_context(|| format!("creating staging dir {}", stage.display()))?;
    for name in [
        "decant_interpose.dll",
        "sample-tool.exe",
        "decant-launcher.exe",
        "decant_plugin_standard.dll",
        "decant-external-standard.exe",
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

    std::fs::write(stage.join("fault.toml"), "[injection]\ntimeout_ms = 500\n")
        .context("writing fault config")?;
    std::fs::write(
        stage.join("plugin.toml"),
        "[injection]\nmethod = \"plugin\"\nplugin_path = \"decant_plugin_standard.dll\"\n",
    )
    .context("writing plugin config")?;
    let plugin_env = [("DECANT_AUTOHOOK", "1"), ("DECANT_CONFIG", "plugin.toml")];
    let r_plugin = run_under_wine(
        &launcher,
        &["sample-tool.exe", "--inject-test"],
        &prefix,
        &plugin_env,
    )
    .context("running plugin injection")?;
    println!(
        "inject-test plugin injection: stdout={:?}",
        r_plugin.stdout.trim()
    );
    if !r_plugin.ok_with("INTERCEPTED") {
        eprintln!("stderr:\n{}", r_plugin.stderr);
        bail!("plugin injection FAIL: expected INTERCEPTED via the cdylib plugin");
    }

    std::fs::write(
        stage.join("manual_map.toml"),
        "[injection]\nmethod = \"manual-map\"\n",
    )
    .context("writing manual-map config")?;
    let manual_map_env = [
        ("DECANT_AUTOHOOK", "1"),
        ("DECANT_CONFIG", "manual_map.toml"),
    ];
    let r_manual_map = run_under_wine(
        &launcher,
        &["sample-tool.exe", "--inject-test"],
        &prefix,
        &manual_map_env,
    )
    .context("running manual-map injection")?;
    println!(
        "inject-test manual-map injection: stdout={:?}",
        r_manual_map.stdout.trim()
    );
    if !r_manual_map.ok_with("INTERCEPTED") {
        eprintln!("stderr:\n{}", r_manual_map.stderr);
        bail!("manual-map injection FAIL: expected INTERCEPTED via the mapped image");
    }

    std::fs::write(
        stage.join("thread_hijack.toml"),
        "[injection]\nmethod = \"thread-hijack\"\n",
    )
    .context("writing thread-hijack config")?;
    let thread_hijack_env = [
        ("DECANT_AUTOHOOK", "1"),
        ("DECANT_CONFIG", "thread_hijack.toml"),
    ];
    let r_thread_hijack = run_under_wine(
        &launcher,
        &["sample-tool.exe", "--inject-test"],
        &prefix,
        &thread_hijack_env,
    )
    .context("running thread-hijack injection")?;
    println!(
        "inject-test thread-hijack injection: stdout={:?}",
        r_thread_hijack.stdout.trim()
    );
    if !r_thread_hijack.ok_with("INTERCEPTED") {
        eprintln!("stderr:\n{}", r_thread_hijack.stderr);
        bail!("thread-hijack injection FAIL: expected INTERCEPTED via the hijacked main thread");
    }

    std::fs::write(
        stage.join("plugin_bad.toml"),
        "[injection]\nmethod = \"plugin\"\nplugin_path = \"decant_interpose.dll\"\n",
    )
    .context("writing bad-plugin config")?;
    let bad_env = [
        ("DECANT_AUTOHOOK", "1"),
        ("DECANT_CONFIG", "plugin_bad.toml"),
    ];
    let r_bad = run_under_wine(
        &launcher,
        &["sample-tool.exe", "--inject-test"],
        &prefix,
        &bad_env,
    )
    .context("running plugin missing-export")?;
    println!(
        "inject-test plugin missing-export: status={} stderr={:?}",
        r_bad.status,
        r_bad.stderr.trim()
    );
    if r_bad.status != 10 || !r_bad.stderr.contains("missing export") {
        bail!(
            "plugin missing-export FAIL: expected exit 10 with a clear error, got exit {}",
            r_bad.status
        );
    }

    std::fs::write(
        stage.join("external.toml"),
        "[injection]\nmethod = \"external\"\nexternal_command = [\"decant-external-standard.exe\"]\n",
    )
    .context("writing external config")?;
    let external_env = [("DECANT_AUTOHOOK", "1"), ("DECANT_CONFIG", "external.toml")];
    let r_external = run_under_wine(
        &launcher,
        &["sample-tool.exe", "--inject-test"],
        &prefix,
        &external_env,
    )
    .context("running external injection")?;
    println!(
        "inject-test external injection: stdout={:?}",
        r_external.stdout.trim()
    );
    if !r_external.ok_with("INTERCEPTED") {
        eprintln!("stderr:\n{}", r_external.stderr);
        bail!("external injection FAIL: expected INTERCEPTED via the external command");
    }

    std::fs::write(
        stage.join("external_bad.toml"),
        "[injection]\nmethod = \"external\"\n",
    )
    .context("writing bad-external config")?;
    let external_bad_env = [
        ("DECANT_AUTOHOOK", "1"),
        ("DECANT_CONFIG", "external_bad.toml"),
    ];
    let r_external_bad = run_under_wine(
        &launcher,
        &["sample-tool.exe", "--inject-test"],
        &prefix,
        &external_bad_env,
    )
    .context("running external missing-command")?;
    println!(
        "inject-test external missing-command: status={} stderr={:?}",
        r_external_bad.status,
        r_external_bad.stderr.trim()
    );
    if r_external_bad.status != 11 || !r_external_bad.stderr.contains("external_command") {
        bail!(
            "external missing-command FAIL: expected exit 11 with a clear error, got exit {}",
            r_external_bad.status
        );
    }

    let fault = [
        ("DECANT_AUTOHOOK", "1"),
        ("DECANT_FAULT", "nohooks"),
        ("DECANT_CONFIG", "fault.toml"),
    ];
    let r3 = run_under_wine(
        &launcher,
        &["sample-tool.exe", "--inject-test"],
        &prefix,
        &fault,
    )
    .context("running broken-carafe timeout")?;
    println!(
        "inject-test broken carafe: status={} stderr={:?}",
        r3.status,
        r3.stderr.trim()
    );
    if r3.status != 8 {
        bail!(
            "broken-carafe FAIL: expected the harness to time out (exit 8), got exit {}",
            r3.status
        );
    }

    println!(
        "inject-test: PASS (standard + plugin + manual-map + thread-hijack + external injection INTERCEPTED via the ready signal; broken carafe times out; baseline passthrough)"
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
