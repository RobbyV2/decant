use std::process::ExitCode;

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::path::Path;

#[cfg(windows)]
use decant_inject::external::read_request;
#[cfg(windows)]
use decant_inject::{
    InjectionRequest, Injector, ProcessHandle, ReadyToken, StandardInjector, ThreadHandle,
};

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(desired_access: u32, inherit: i32, pid: u32) -> *mut c_void;
    fn GetLastError() -> u32;
}

#[cfg(windows)]
const PROCESS_ALL_ACCESS: u32 = 0x001F_0FFF;

#[cfg(windows)]
fn main() -> ExitCode {
    let payload = match read_request(&mut std::io::stdin().lock()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("external: reading protocol frame: {e}");
            return ExitCode::from(2);
        }
    };

    let proc = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, payload.pid) };
    if proc.is_null() {
        eprintln!(
            "external: OpenProcess({}) failed (err={})",
            payload.pid,
            unsafe { GetLastError() }
        );
        return ExitCode::from(3);
    }

    let req = InjectionRequest {
        target: ProcessHandle(proc),
        main_thread: ThreadHandle(std::ptr::null_mut()),
        target_pid: payload.pid,
        carafe_path: Path::new(&payload.carafe_path),
        carafe_image: &payload.carafe_image,
        ready: ReadyToken::new(payload.ready_token),
    };

    match StandardInjector.inject(&req) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("external: {e}");
            ExitCode::from(4)
        }
    }
}

#[cfg(not(windows))]
fn main() -> ExitCode {
    eprintln!("decant-external-standard is a Windows/PE-side helper");
    ExitCode::from(64)
}
