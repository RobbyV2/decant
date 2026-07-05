use std::ffi::c_void;
use std::path::Path;
use std::process::ExitCode;

use decant_inject::{
    InjectError, InjectionConfig, InjectionRequest, ProcessHandle, ReadyToken, ThreadHandle,
};

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
}

const CREATE_SUSPENDED: u32 = 0x0000_0004;
const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
const STD_INPUT: i32 = -10;
const STD_OUTPUT: i32 = -11;
const STD_ERROR: i32 = -12;
const INFINITE: u32 = 0xFFFF_FFFF;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn exit_code_for(e: &InjectError) -> u8 {
    match e {
        InjectError::RemoteAlloc(_) => 3,
        InjectError::RemoteWrite(_) => 4,
        InjectError::ResolveLoadLibrary => 5,
        InjectError::RemoteThread(_) => 6,
        InjectError::Timeout => 8,
        InjectError::Unsupported(_) => 9,
        InjectError::Plugin(_) => 10,
        InjectError::Config(_) => 11,
    }
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

    unsafe {
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
            carafe_path: Path::new(&dll_path),
            carafe_image: &[],
            ready: ReadyToken::none(),
        };

        match injector.inject(&req) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("launcher: injection failed: {e}");
                return ExitCode::from(exit_code_for(&e));
            }
        }

        if ResumeThread(pi.h_thread) == u32::MAX {
            eprintln!("launcher: ResumeThread failed (err={})", GetLastError());
            return ExitCode::from(7);
        }

        WaitForSingleObject(pi.h_process, INFINITE);
        let mut code: u32 = 0;
        GetExitCodeProcess(pi.h_process, &mut code);
        CloseHandle(pi.h_thread);
        CloseHandle(pi.h_process);

        ExitCode::from(code as u8)
    }
}
