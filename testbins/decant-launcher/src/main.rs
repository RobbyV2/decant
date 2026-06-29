//! # decant-launcher (Phase 3 spike, rung 2c) — runs UNDER WINE
//!
//! The **no-cooperation injector**: it loads the carafe into a *completely
//! unmodified* target exe by classic remote-thread DLL injection, then lets the
//! target run. This is the rung-2 path that actually works on Wine 11.11 (the
//! `AppInit_DLLs` path is a no-op stub there — see ADR-0006).
//!
//! Flow (all steps are public Win32 exports — spec rule #4, no Wine internals):
//!
//!   1. `CreateProcessW(target, CREATE_SUSPENDED)` — the target exists but no
//!      user code has run; its initial thread is parked.
//!   2. `VirtualAllocEx` + `WriteProcessMemory` — copy the carafe's DLL path into
//!      the target's address space.
//!   3. `CreateRemoteThread` at `kernel32!LoadLibraryA` with that path — the
//!      target loads our DLL itself. (kernel32 is a KnownDLL mapped at the same
//!      base in every process, so `LoadLibraryA`'s address resolved here is valid
//!      in the target — no cross-process symbol games.)
//!   4. Wait for that thread: when it returns, the carafe's `DllMain` has run and
//!      (with `DECANT_AUTOHOOK=1`, inherited by the child) installed the IAT hooks.
//!   5. `ResumeThread` the main thread — the target now runs with its
//!      `ReadProcessMemory` IAT slot already pointing at the carafe.
//!
//! stdout of the child is inherited, so the target's `INTERCEPTED`/`passthrough`
//! line surfaces on this launcher's stdout for the harness to assert.
//!
//! Usage: `decant-launcher <target.exe> [args...]`. The DLL is taken from
//! `DECANT_DLL` (a Windows path) or defaults to `decant_interpose.dll` next to
//! the target. Win32 entry points are declared by hand (like `dll-smoke`).

use std::ffi::c_void;
use std::process::ExitCode;

type Handle = *mut c_void;

#[repr(C)]
struct ProcessInformation {
    h_process: Handle,
    h_thread: Handle,
    dw_process_id: u32,
    dw_thread_id: u32,
}

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    _pad0: u32,
    lp_reserved: *mut u16,
    lp_desktop: *mut u16,
    lp_title: *mut u16,
    dw_x: u32,
    dw_y: u32,
    dw_x_size: u32,
    dw_y_size: u32,
    dw_x_count_chars: u32,
    dw_y_count_chars: u32,
    dw_fill_attribute: u32,
    dw_flags: u32,
    w_show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: *mut u8,
    h_std_input: Handle,
    h_std_output: Handle,
    h_std_error: Handle,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateProcessW(
        application_name: *const u16,
        command_line: *mut u16,
        process_attributes: *const c_void,
        thread_attributes: *const c_void,
        inherit_handles: i32,
        creation_flags: u32,
        environment: *const c_void,
        current_directory: *const u16,
        startup_info: *const StartupInfoW,
        process_information: *mut ProcessInformation,
    ) -> i32;
    fn VirtualAllocEx(
        process: Handle,
        address: *mut c_void,
        size: usize,
        allocation_type: u32,
        protect: u32,
    ) -> *mut c_void;
    fn WriteProcessMemory(
        process: Handle,
        base_address: *mut c_void,
        buffer: *const c_void,
        size: usize,
        written: *mut usize,
    ) -> i32;
    fn CreateRemoteThread(
        process: Handle,
        thread_attributes: *const c_void,
        stack_size: usize,
        start_address: *mut c_void,
        parameter: *mut c_void,
        creation_flags: u32,
        thread_id: *mut u32,
    ) -> Handle;
    fn GetModuleHandleA(module_name: *const u8) -> Handle;
    fn GetProcAddress(module: Handle, proc_name: *const u8) -> *mut c_void;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn ResumeThread(thread: Handle) -> u32;
    fn GetExitCodeProcess(process: Handle, exit_code: *mut u32) -> i32;
    fn GetStdHandle(std_handle: i32) -> Handle;
    fn CloseHandle(object: Handle) -> i32;
    fn GetLastError() -> u32;
}

const CREATE_SUSPENDED: u32 = 0x0000_0004;
const MEM_COMMIT_RESERVE: u32 = 0x0000_1000 | 0x0000_2000;
const PAGE_READWRITE: u32 = 0x04;
const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
const STD_INPUT: i32 = -10;
const STD_OUTPUT: i32 = -11;
const STD_ERROR: i32 = -12;
const INFINITE: u32 = 0xFFFF_FFFF;

/// Convert a Rust string to a NUL-terminated UTF-16 buffer.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let target = match args.next() {
        Some(t) => t,
        None => {
            eprintln!("usage: decant-launcher <target.exe> [args...]");
            return ExitCode::from(64);
        }
    };
    let rest: Vec<String> = args.collect();

    // DLL to inject: explicit DECANT_DLL (Windows path) or sibling of the target.
    let dll_path = std::env::var("DECANT_DLL").unwrap_or_else(|_| {
        match std::path::Path::new(&target).parent() {
            Some(dir) if !dir.as_os_str().is_empty() => {
                dir.join("decant_interpose.dll").to_string_lossy().into_owned()
            }
            _ => "decant_interpose.dll".to_string(),
        }
    });

    // Build the child command line: "target" arg1 arg2 ...
    let mut cmd = format!("\"{target}\"");
    for a in &rest {
        cmd.push(' ');
        cmd.push_str(a);
    }
    let app_w = wide(&target);
    let mut cmd_w = wide(&cmd);
    let dll_bytes = {
        let mut b = dll_path.into_bytes();
        b.push(0);
        b
    };

    unsafe {
        // STARTUPINFOW with inherited std handles so the child's stdout reaches us.
        let mut si: StartupInfoW = std::mem::zeroed();
        si.cb = std::mem::size_of::<StartupInfoW>() as u32;
        si.dw_flags = STARTF_USESTDHANDLES;
        si.h_std_input = GetStdHandle(STD_INPUT);
        si.h_std_output = GetStdHandle(STD_OUTPUT);
        si.h_std_error = GetStdHandle(STD_ERROR);
        let mut pi: ProcessInformation = std::mem::zeroed();

        // 1. Create the target SUSPENDED, inheriting our handles (env inherited too,
        //    carrying DECANT_AUTOHOOK to the carafe's DllMain).
        let ok = CreateProcessW(
            app_w.as_ptr(),
            cmd_w.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1, // bInheritHandles = TRUE
            CREATE_SUSPENDED,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        );
        if ok == 0 {
            eprintln!("launcher: CreateProcessW failed (err={})", GetLastError());
            return ExitCode::from(2);
        }

        // 2. Allocate + write the DLL path in the target.
        let remote = VirtualAllocEx(
            pi.h_process,
            std::ptr::null_mut(),
            dll_bytes.len(),
            MEM_COMMIT_RESERVE,
            PAGE_READWRITE,
        );
        if remote.is_null() {
            eprintln!("launcher: VirtualAllocEx failed (err={})", GetLastError());
            return ExitCode::from(3);
        }
        let mut written = 0usize;
        if WriteProcessMemory(
            pi.h_process,
            remote,
            dll_bytes.as_ptr() as *const c_void,
            dll_bytes.len(),
            &mut written,
        ) == 0
        {
            eprintln!("launcher: WriteProcessMemory failed (err={})", GetLastError());
            return ExitCode::from(4);
        }

        // 3. kernel32!LoadLibraryA — same address in the target (KnownDLL base).
        let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        let load_library = GetProcAddress(kernel32, b"LoadLibraryA\0".as_ptr());
        if load_library.is_null() {
            eprintln!("launcher: GetProcAddress(LoadLibraryA) failed");
            return ExitCode::from(5);
        }

        // 4. Run LoadLibraryA(dll_path) in the target and wait for it to finish —
        //    DllMain installs the hooks before we let the main thread go.
        let thread = CreateRemoteThread(
            pi.h_process,
            std::ptr::null(),
            0,
            load_library,
            remote,
            0,
            std::ptr::null_mut(),
        );
        if thread.is_null() {
            eprintln!("launcher: CreateRemoteThread failed (err={})", GetLastError());
            return ExitCode::from(6);
        }
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);

        // 5. Resume the target's main thread; it runs with hooks already installed.
        if ResumeThread(pi.h_thread) == u32::MAX {
            eprintln!("launcher: ResumeThread failed (err={})", GetLastError());
            return ExitCode::from(7);
        }

        // Wait for the child and propagate its exit code.
        WaitForSingleObject(pi.h_process, INFINITE);
        let mut code: u32 = 0;
        GetExitCodeProcess(pi.h_process, &mut code);
        CloseHandle(pi.h_thread);
        CloseHandle(pi.h_process);

        ExitCode::from(code as u8)
    }
}
