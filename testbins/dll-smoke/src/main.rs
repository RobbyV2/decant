//! Phase 0 toolchain proof — the smoke-test exe.
//!
//! `LoadLibraryA("hello_dll.dll")`, `GetProcAddress("add")`, call `add(2, 3)`,
//! print the result. Under the isolated Wine prefix this prints `5`, which
//! `xtask wine-smoke` asserts on.
//!
//! We declare the two kernel32 entry points by hand rather than pulling in a
//! `windows`/`windows-sys` dependency: it keeps the cross-compile trivial and,
//! fittingly, exercises the exact public export ABI Decant is built around
//! (spec operating rule #4 — bind only to documented Win32 exports).

use std::ffi::c_void;
use std::process::ExitCode;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(lp_lib_file_name: *const u8) -> *mut c_void;
    fn GetProcAddress(h_module: *mut c_void, lp_proc_name: *const u8) -> *mut c_void;
}

fn main() -> ExitCode {
    // NUL-terminated, as the ANSI Win32 entry points require.
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

        // x86_64: one calling convention; extern "C" matches the DLL's export.
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
