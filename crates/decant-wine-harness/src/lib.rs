//! # decant-wine-harness (Phase 3, scaffold usable in Phase 0)
//!
//! Programmatically launch a Windows exe under the isolated `WINEPREFIX` with the
//! interposer override + daemon endpoint wired, capturing stdout/exit so Wine-side
//! tests are `cargo test`-drivable (spec §4, Phase 3).
//!
//! Phase 0 provides a minimal [`run_under_wine`] used by `xtask wine-smoke`; Phase 3
//! extends it with the interposer override and mock/live daemon wiring (the
//! `extra_env` parameter already carries those without an API change).

#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, Context, Result};

/// Captured result of one Wine invocation.
///
/// `status` is the process exit code. A process killed by a signal (no code) is
/// surfaced as an error from [`run_under_wine`] rather than a sentinel here, so a
/// successful return always carries a real exit code.
#[derive(Debug, Clone)]
pub struct WineOutput {
    pub stdout: String,
    pub stderr: String,
    pub status: i32,
}

impl WineOutput {
    /// Convenience for the common assertion `exit 0 && stdout contains needle`.
    pub fn ok_with(&self, needle: &str) -> bool {
        self.status == 0 && self.stdout.contains(needle)
    }
}

/// Run a Windows `exe` under Wine inside the repo-local `prefix`, returning its
/// captured stdout/stderr and exit code.
///
/// The working directory is set to the exe's own directory. That is what makes a
/// co-located DLL resolvable by a bare `LoadLibraryA("name.dll")`: Windows searches
/// the executable's directory and the cwd, and here they are the same. `xtask
/// wine-smoke` relies on this to find `hello_dll.dll` next to `dll-smoke.exe`.
///
/// Base environment mirrors `wine-env/run.sh`: `WINEPREFIX`, `WINEDEBUG=-all`, and
/// `WINEDLLOVERRIDES="mscoree=;mshtml="` to suppress the gecko/mono install prompts
/// and keep output clean. `extra_env` is applied last, so a caller can append the
/// future `decant_interpose` override or a `DECANT_ENDPOINT` value (Phase 3) without
/// any change to this signature.
pub fn run_under_wine(
    exe: &Path,
    args: &[&str],
    prefix: &Path,
    extra_env: &[(&str, &str)],
) -> Result<WineOutput> {
    let workdir = exe
        .parent()
        .ok_or_else(|| anyhow!("exe path has no parent directory: {}", exe.display()))?;

    let mut cmd = Command::new("wine");
    cmd.arg(exe)
        .args(args)
        .current_dir(workdir)
        .env("WINEPREFIX", prefix)
        .env("WINEDEBUG", "-all")
        .env("WINEDLLOVERRIDES", "mscoree=;mshtml=");

    for (key, val) in extra_env {
        cmd.env(key, val);
    }

    let out = cmd
        .output()
        .with_context(|| format!("failed to spawn wine for {}", exe.display()))?;

    let status = out.status.code().ok_or_else(|| {
        anyhow!(
            "wine for {} terminated without an exit code (killed by signal)",
            exe.display()
        )
    })?;

    Ok(WineOutput {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        status,
    })
}
