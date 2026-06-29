//! # decant-interpose — "the carafe" (Phase 3)
//!
//! The Windows DLL injected into an unmodified tool under Wine. It implements the
//! handful of Win32/NT memory/introspection exports Decant cares about, marshals
//! them to the daemon ("the cellar") over [`decant_protocol`], and forwards
//! everything else to the real Wine builtin. Binds only to the public Win32/NT
//! export ABI + the frozen PE format — never a Wine internal (rule #4,
//! `docs/VERSIONING.md`; vector in ADR-0006).
//!
//! ## Module map
//!
//! * [`handle_table`] — the synthetic handle table ("mine vs forward-to-Wine") and
//!   its **platform-agnostic, host-unit-tested core** (the red-team in `cargo test`).
//! * [`rpc`] — the panic-free daemon client (cached `TcpStream`, `DECANT_ENDPOINT`).
//! * `iat` *(windows)* — the IAT-patch engine from the spike (ADR-0006).
//! * `originals` *(windows)* — saved real exports for the forwarder.
//! * `hooks` *(windows)* — the daemon-marshaling `extern "system"` replacements
//!   (`OpenProcess`, `ReadProcessMemory`/`WriteProcessMemory`,
//!   `Nt{Read,Write}VirtualMemory`, `CloseHandle`/`NtClose`, toolhelp snapshots +
//!   `Process32*`/`Module32*`, `EnumProcesses`/`EnumProcessModules`,
//!   `GetModuleBaseName/FileNameEx`, `VirtualProtectEx` no-op) + the installer.
//!
//! ## Loading (the two rungs the spike proved, ADR-0006)
//!
//! * **Rung 1 (cooperative):** the tool calls [`decant_install_hooks`] itself.
//! * **Rung 2 (no cooperation):** [`DllMain`] self-installs on `DLL_PROCESS_ATTACH`
//!   when `DECANT_AUTOHOOK=1`, so an unmodified tool injected by `decant-launcher`
//!   is patched the instant the carafe is mapped.
//!
//! The pure/std modules ([`handle_table`], [`rpc`]) build on the host too, so the
//! crate's unit tests run under `cargo test` with no Wine; the `#[cfg(windows)]`
//! modules carry the Win32-binding code.

#![allow(clippy::missing_safety_doc)]

pub mod handle_table;
pub mod rpc;

#[cfg(windows)]
mod hooks;
#[cfg(windows)]
mod iat;
#[cfg(windows)]
mod originals;

#[cfg(windows)]
mod platform {
    use core::ffi::c_void;

    /// `DLL_PROCESS_ATTACH` — the `DllMain` reason fired when we are mapped.
    const DLL_PROCESS_ATTACH: u32 = 1;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetEnvironmentVariableA(name: *const u8, buf: *mut u8, size: u32) -> u32;
    }

    /// Install every carafe hook into the current process; returns the number of
    /// IAT slots rewritten. Idempotent (re-running re-points the same slots).
    pub unsafe fn install_hooks() -> u32 {
        crate::hooks::install_all()
    }

    /// Exported installer — the **rung-1 (cooperative)** entry point. Returns the
    /// count of patched slots (≥1 ⇒ the engine found and rewrote targets).
    #[no_mangle]
    pub extern "system" fn decant_install_hooks() -> i32 {
        unsafe { install_hooks() as i32 }
    }

    /// DLL entry point — the **rung-2 (no-cooperation)** path. On
    /// `DLL_PROCESS_ATTACH`, if `DECANT_AUTOHOOK=1`, install the hooks. Never blocks
    /// the load (always returns TRUE); hooking is best-effort.
    #[no_mangle]
    pub extern "system" fn DllMain(_hinst: *mut c_void, reason: u32, _reserved: *mut c_void) -> i32 {
        if reason == DLL_PROCESS_ATTACH && autohook_enabled() {
            unsafe {
                let _ = install_hooks();
            }
        }
        1
    }

    /// Read `DECANT_AUTOHOOK` and report whether it is `1`.
    fn autohook_enabled() -> bool {
        let mut buf = [0u8; 8];
        let n = unsafe {
            GetEnvironmentVariableA(b"DECANT_AUTOHOOK\0".as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
        };
        n >= 1 && buf[0] == b'1'
    }
}
