use std::process::ExitCode;

#[cfg(windows)]
use std::ffi::c_void;

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryA(lp_lib_file_name: *const u8) -> *mut c_void;
    fn GetProcAddress(h_module: *mut c_void, lp_proc_name: *const u8) -> *mut c_void;
}

#[cfg(windows)]
fn main() -> ExitCode {
    let dll = b"hello_dll.dll\0";
    let sym = b"add\0";

    unsafe {
        let module = LoadLibraryA(dll.as_ptr());
        if module.is_null() {
            eprintln!("LoadLibraryA(hello_dll.dll) failed");
            return ExitCode::from(2);
        }

        let proc = GetProcAddress(module, sym.as_ptr());
        if proc.is_null() {
            eprintln!("GetProcAddress(add) failed");
            return ExitCode::from(3);
        }

        let add: extern "C" fn(i32, i32) -> i32 = std::mem::transmute(proc);
        let result = add(2, 3);
        println!("{result}");

        if result == 5 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(4)
        }
    }
}

#[cfg(not(windows))]
fn main() -> ExitCode {
    eprintln!("dll-smoke is a Windows/PE-side test binary");
    ExitCode::from(64)
}
