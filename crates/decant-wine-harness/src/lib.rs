#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, anyhow};

#[derive(Debug, Clone)]
pub struct WineOutput {
    pub stdout: String,
    pub stderr: String,
    pub status: i32,
}

impl WineOutput {
    pub fn ok_with(&self, needle: &str) -> bool {
        self.status == 0 && self.stdout.contains(needle)
    }
}

// cwd is the exe dir so a co-located DLL resolves via bare LoadLibraryA
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
