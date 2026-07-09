#![allow(clippy::manual_c_str_literals)]

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::path::Path;
use std::process::ExitCode;

#[cfg(windows)]
use decant_inject::{
    InjectError, InjectionConfig, InjectionRequest, Method, ProcessHandle, ReadyToken,
    ThreadHandle, thread_hijack_release_event_name,
};

#[cfg(windows)]
type Handle = *mut c_void;

#[cfg(windows)]
#[repr(C)]
struct ProcessInformation {
    h_process: Handle,
    h_thread: Handle,
    dw_process_id: u32,
    dw_thread_id: u32,
}

#[cfg(windows)]
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

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
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
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn ResumeThread(thread: Handle) -> u32;
    fn GetExitCodeProcess(process: Handle, exit_code: *mut u32) -> i32;
    fn GetStdHandle(std_handle: i32) -> Handle;
    fn CloseHandle(object: Handle) -> i32;
    fn GetLastError() -> u32;
    fn CreateEventA(
        attributes: *const c_void,
        manual_reset: i32,
        initial_state: i32,
        name: *const u8,
    ) -> Handle;
    fn SetEvent(handle: Handle) -> i32;
    fn SetEnvironmentVariableA(name: *const u8, value: *const u8) -> i32;
    fn TerminateProcess(process: Handle, exit_code: u32) -> i32;
}

#[cfg(windows)]
const CREATE_SUSPENDED: u32 = 0x0000_0004;
#[cfg(windows)]
const WAIT_OBJECT_0: u32 = 0;
#[cfg(windows)]
const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
#[cfg(windows)]
const STD_INPUT: i32 = -10;
#[cfg(windows)]
const STD_OUTPUT: i32 = -11;
#[cfg(windows)]
const STD_ERROR: i32 = -12;
#[cfg(windows)]
const INFINITE: u32 = 0xFFFF_FFFF;

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn exit_code_for(e: &InjectError) -> u8 {
    match e {
        InjectError::RemoteAlloc(_) => 3,
        InjectError::RemoteRead(_) => 13,
        InjectError::RemoteWrite(_) => 4,
        InjectError::RemoteProtect(_) => 14,
        InjectError::ResolveLoadLibrary => 5,
        InjectError::RemoteThread(_) => 6,
        InjectError::Timeout => 8,
        InjectError::Unsupported(_) => 9,
        InjectError::ManualMap(_) => 15,
        InjectError::ThreadHijack(_) => 16,
        InjectError::Plugin(_) => 10,
        InjectError::Config(_) => 11,
        InjectError::External(_) => 12,
    }
}

#[cfg(windows)]
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

    let dll_path =
        std::env::var("DECANT_DLL").unwrap_or_else(|_| match Path::new(&target).parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir
                .join("decant_interpose.dll")
                .to_string_lossy()
                .into_owned(),
            _ => "decant_interpose.dll".to_string(),
        });

    let mut cmd = format!("\"{target}\"");
    for a in &rest {
        cmd.push(' ');
        cmd.push_str(a);
    }
    let app_w = wide(&target);
    let mut cmd_w = wide(&cmd);

    let cfg = match std::env::var("DECANT_CONFIG") {
        Ok(p) => match InjectionConfig::load(Path::new(&p)) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("launcher: {e}");
                return ExitCode::from(exit_code_for(&e));
            }
        },
        Err(_) => InjectionConfig::default(),
    };
    let injector = match cfg.injector() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("launcher: {e}");
            return ExitCode::from(exit_code_for(&e));
        }
    };
    eprintln!(
        "launcher: injecting via method '{}' ({})",
        injector.name(),
        injector.portability().label()
    );
    if !injector.portability().upholds_export_guarantee() {
        eprintln!(
            "launcher: method '{}' binds below the public export ABI; the cross-version \
             portability guarantee does not apply to this run",
            injector.name()
        );
    }

    let carafe_image = match std::fs::read(&dll_path) {
        Ok(image) => image,
        Err(e) => {
            eprintln!("launcher: reading {dll_path}: {e}");
            return ExitCode::from(2);
        }
    };

    let token = format!("decant_ready_{}", std::process::id());
    let mut token_c = token.clone().into_bytes();
    token_c.push(0);

    unsafe {
        let ready = CreateEventA(std::ptr::null(), 1, 0, token_c.as_ptr());
        if ready.is_null() {
            eprintln!("launcher: CreateEventA failed (err={})", GetLastError());
            return ExitCode::from(2);
        }
        SetEnvironmentVariableA(b"DECANT_READY_EVENT\0".as_ptr(), token_c.as_ptr());
        let release = match cfg.method {
            Method::ThreadHijack => {
                let mut release_c = thread_hijack_release_event_name(&token).into_bytes();
                release_c.push(0);
                let h = CreateEventA(std::ptr::null(), 1, 0, release_c.as_ptr());
                if h.is_null() {
                    eprintln!(
                        "launcher: CreateEventA(thread-hijack release) failed (err={})",
                        GetLastError()
                    );
                    CloseHandle(ready);
                    return ExitCode::from(2);
                }
                h
            }
            _ => std::ptr::null_mut(),
        };

        let mut si: StartupInfoW = std::mem::zeroed();
        si.cb = std::mem::size_of::<StartupInfoW>() as u32;
        si.dw_flags = STARTF_USESTDHANDLES;
        si.h_std_input = GetStdHandle(STD_INPUT);
        si.h_std_output = GetStdHandle(STD_OUTPUT);
        si.h_std_error = GetStdHandle(STD_ERROR);
        let mut pi: ProcessInformation = std::mem::zeroed();

        let ok = CreateProcessW(
            app_w.as_ptr(),
            cmd_w.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
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

        let req = InjectionRequest {
            target: ProcessHandle(pi.h_process),
            main_thread: ThreadHandle(pi.h_thread),
            target_pid: pi.dw_process_id,
            carafe_path: Path::new(&dll_path),
            carafe_image: &carafe_image,
            ready: ReadyToken::new(&token),
        };

        match injector.inject(&req) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("launcher: injection failed: {e}");
                TerminateProcess(pi.h_process, 1);
                if !release.is_null() {
                    CloseHandle(release);
                }
                return ExitCode::from(exit_code_for(&e));
            }
        }

        if cfg.method == Method::ThreadHijack && ResumeThread(pi.h_thread) == u32::MAX {
            eprintln!(
                "launcher: ResumeThread(thread-hijack loader) failed (err={})",
                GetLastError()
            );
            TerminateProcess(pi.h_process, 1);
            CloseHandle(ready);
            if !release.is_null() {
                CloseHandle(release);
            }
            CloseHandle(pi.h_thread);
            CloseHandle(pi.h_process);
            return ExitCode::from(7);
        }

        if WaitForSingleObject(ready, cfg.timeout_ms) != WAIT_OBJECT_0 {
            let e = InjectError::Timeout;
            eprintln!("launcher: {e}");
            TerminateProcess(pi.h_process, 1);
            CloseHandle(ready);
            if !release.is_null() {
                CloseHandle(release);
            }
            CloseHandle(pi.h_thread);
            CloseHandle(pi.h_process);
            return ExitCode::from(exit_code_for(&e));
        }
        CloseHandle(ready);

        match cfg.method {
            Method::ThreadHijack => {
                if SetEvent(release) == 0 {
                    eprintln!(
                        "launcher: SetEvent(thread-hijack release) failed (err={})",
                        GetLastError()
                    );
                    TerminateProcess(pi.h_process, 1);
                    CloseHandle(release);
                    CloseHandle(pi.h_thread);
                    CloseHandle(pi.h_process);
                    return ExitCode::from(7);
                }
                CloseHandle(release);
            }
            _ => {
                if ResumeThread(pi.h_thread) == u32::MAX {
                    eprintln!("launcher: ResumeThread failed (err={})", GetLastError());
                    return ExitCode::from(7);
                }
            }
        }

        WaitForSingleObject(pi.h_process, INFINITE);
        let mut code: u32 = 0;
        GetExitCodeProcess(pi.h_process, &mut code);
        CloseHandle(pi.h_thread);
        CloseHandle(pi.h_process);

        ExitCode::from(code as u8)
    }
}

#[cfg(not(windows))]
fn main() -> ExitCode {
    eprintln!("decant-launcher is a Windows/PE-side helper");
    ExitCode::from(64)
}
