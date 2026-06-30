use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

use decant_protocol::{Request, Response};

use crate::handle_table;
use crate::hooks::{put_ansi_counted, put_wide_counted};
use crate::iat;
use crate::rpc;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(module_name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, proc_name: *const u8) -> *mut c_void;
}

const TRUE: i32 = 1;
const STILL_ACTIVE: u32 = 259;

static GET_PROCESS_IMAGE_FILE_NAME_A_ORIG: AtomicUsize = AtomicUsize::new(0);
static GET_PROCESS_IMAGE_FILE_NAME_W_ORIG: AtomicUsize = AtomicUsize::new(0);
static QUERY_FULL_PROCESS_IMAGE_NAME_A_ORIG: AtomicUsize = AtomicUsize::new(0);
static QUERY_FULL_PROCESS_IMAGE_NAME_W_ORIG: AtomicUsize = AtomicUsize::new(0);
static IS_WOW64_PROCESS_ORIG: AtomicUsize = AtomicUsize::new(0);
static GET_PROCESS_ID_ORIG: AtomicUsize = AtomicUsize::new(0);
static GET_EXIT_CODE_PROCESS_ORIG: AtomicUsize = AtomicUsize::new(0);

type ImgNameAFn = unsafe extern "system" fn(*mut c_void, *mut u8, u32) -> u32;
type ImgNameWFn = unsafe extern "system" fn(*mut c_void, *mut u16, u32) -> u32;
type QueryNameAFn = unsafe extern "system" fn(*mut c_void, u32, *mut u8, *mut u32) -> i32;
type QueryNameWFn = unsafe extern "system" fn(*mut c_void, u32, *mut u16, *mut u32) -> i32;
type IsWow64Fn = unsafe extern "system" fn(*mut c_void, *mut i32) -> i32;
type GetPidFn = unsafe extern "system" fn(*mut c_void) -> u32;
type ExitCodeFn = unsafe extern "system" fn(*mut c_void, *mut u32) -> i32;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

unsafe fn resolve(module_w: &[u16], name: &[u8]) -> usize {
    unsafe {
        let h = GetModuleHandleW(module_w.as_ptr());
        if h.is_null() {
            return 0;
        }
        GetProcAddress(h, name.as_ptr()) as usize
    }
}

unsafe fn process_name(handle: usize) -> Option<String> {
    let pid = handle_table::pid_for(handle)?;
    match rpc::request(Request::ProcessByPid(pid)) {
        Some(Response::Process(info)) => Some(info.name),
        _ => None,
    }
}

pub unsafe extern "system" fn get_process_image_file_name_a(
    process: *mut c_void,
    filename: *mut u8,
    size: u32,
) -> u32 {
    unsafe {
        let h = process as usize;
        if handle_table::is_synthetic(h) {
            return match process_name(h) {
                Some(name) => put_ansi_counted(filename, size, &name),
                None => 0,
            };
        }
        let p = GET_PROCESS_IMAGE_FILE_NAME_A_ORIG.load(Ordering::SeqCst);
        if p != 0 {
            let f: ImgNameAFn = core::mem::transmute(p);
            return f(process, filename, size);
        }
        0
    }
}

pub unsafe extern "system" fn get_process_image_file_name_w(
    process: *mut c_void,
    filename: *mut u16,
    size: u32,
) -> u32 {
    unsafe {
        let h = process as usize;
        if handle_table::is_synthetic(h) {
            return match process_name(h) {
                Some(name) => put_wide_counted(filename, size, &name),
                None => 0,
            };
        }
        let p = GET_PROCESS_IMAGE_FILE_NAME_W_ORIG.load(Ordering::SeqCst);
        if p != 0 {
            let f: ImgNameWFn = core::mem::transmute(p);
            return f(process, filename, size);
        }
        0
    }
}

pub unsafe extern "system" fn query_full_process_image_name_a(
    process: *mut c_void,
    flags: u32,
    exe_name: *mut u8,
    size: *mut u32,
) -> i32 {
    unsafe {
        let h = process as usize;
        if handle_table::is_synthetic(h) {
            return match process_name(h) {
                Some(name) => {
                    let cap = if size.is_null() { 0 } else { *size };
                    let written = put_ansi_counted(exe_name, cap, &name);
                    if !size.is_null() {
                        *size = written;
                    }
                    TRUE
                }
                None => 0,
            };
        }
        let p = QUERY_FULL_PROCESS_IMAGE_NAME_A_ORIG.load(Ordering::SeqCst);
        if p != 0 {
            let f: QueryNameAFn = core::mem::transmute(p);
            return f(process, flags, exe_name, size);
        }
        0
    }
}

pub unsafe extern "system" fn query_full_process_image_name_w(
    process: *mut c_void,
    flags: u32,
    exe_name: *mut u16,
    size: *mut u32,
) -> i32 {
    unsafe {
        let h = process as usize;
        if handle_table::is_synthetic(h) {
            return match process_name(h) {
                Some(name) => {
                    let cap = if size.is_null() { 0 } else { *size };
                    let written = put_wide_counted(exe_name, cap, &name);
                    if !size.is_null() {
                        *size = written;
                    }
                    TRUE
                }
                None => 0,
            };
        }
        let p = QUERY_FULL_PROCESS_IMAGE_NAME_W_ORIG.load(Ordering::SeqCst);
        if p != 0 {
            let f: QueryNameWFn = core::mem::transmute(p);
            return f(process, flags, exe_name, size);
        }
        0
    }
}

pub unsafe extern "system" fn is_wow64_process(process: *mut c_void, wow64: *mut i32) -> i32 {
    unsafe {
        let h = process as usize;
        if handle_table::is_synthetic(h) {
            if !wow64.is_null() {
                *wow64 = 0;
            }
            return TRUE;
        }
        let p = IS_WOW64_PROCESS_ORIG.load(Ordering::SeqCst);
        if p != 0 {
            let f: IsWow64Fn = core::mem::transmute(p);
            return f(process, wow64);
        }
        0
    }
}

pub unsafe extern "system" fn get_process_id(process: *mut c_void) -> u32 {
    unsafe {
        let h = process as usize;
        if handle_table::is_synthetic(h) {
            return match handle_table::pid_for(h) {
                Some(pid) => pid.0,
                None => 0,
            };
        }
        let p = GET_PROCESS_ID_ORIG.load(Ordering::SeqCst);
        if p != 0 {
            let f: GetPidFn = core::mem::transmute(p);
            return f(process);
        }
        0
    }
}

pub unsafe extern "system" fn get_exit_code_process(process: *mut c_void, code: *mut u32) -> i32 {
    unsafe {
        let h = process as usize;
        if handle_table::is_synthetic(h) {
            if !code.is_null() {
                *code = STILL_ACTIVE;
            }
            return TRUE;
        }
        let p = GET_EXIT_CODE_PROCESS_ORIG.load(Ordering::SeqCst);
        if p != 0 {
            let f: ExitCodeFn = core::mem::transmute(p);
            return f(process, code);
        }
        0
    }
}

pub(crate) unsafe fn redirect(name: *const u8) -> *mut c_void {
    unsafe {
        if iat::cstr_eq(name, b"GetProcessImageFileNameA") {
            return get_process_image_file_name_a as *mut c_void;
        }
        if iat::cstr_eq(name, b"K32GetProcessImageFileNameA") {
            return get_process_image_file_name_a as *mut c_void;
        }
        if iat::cstr_eq(name, b"GetProcessImageFileNameW") {
            return get_process_image_file_name_w as *mut c_void;
        }
        if iat::cstr_eq(name, b"K32GetProcessImageFileNameW") {
            return get_process_image_file_name_w as *mut c_void;
        }
        if iat::cstr_eq(name, b"QueryFullProcessImageNameA") {
            return query_full_process_image_name_a as *mut c_void;
        }
        if iat::cstr_eq(name, b"QueryFullProcessImageNameW") {
            return query_full_process_image_name_w as *mut c_void;
        }
        if iat::cstr_eq(name, b"IsWow64Process") {
            return is_wow64_process as *mut c_void;
        }
        if iat::cstr_eq(name, b"GetProcessId") {
            return get_process_id as *mut c_void;
        }
        if iat::cstr_eq(name, b"GetExitCodeProcess") {
            return get_exit_code_process as *mut c_void;
        }
        core::ptr::null_mut()
    }
}

pub unsafe fn install() -> u32 {
    unsafe {
        let k32 = wide("kernel32.dll");
        let psapi = wide("psapi.dll");

        let store = |slot: &AtomicUsize, v: usize| slot.store(v, Ordering::SeqCst);

        let img_a = {
            let p = resolve(&psapi, b"GetProcessImageFileNameA\0");
            if p != 0 {
                p
            } else {
                resolve(&k32, b"K32GetProcessImageFileNameA\0")
            }
        };
        store(&GET_PROCESS_IMAGE_FILE_NAME_A_ORIG, img_a);
        let img_w = {
            let p = resolve(&psapi, b"GetProcessImageFileNameW\0");
            if p != 0 {
                p
            } else {
                resolve(&k32, b"K32GetProcessImageFileNameW\0")
            }
        };
        store(&GET_PROCESS_IMAGE_FILE_NAME_W_ORIG, img_w);
        store(
            &QUERY_FULL_PROCESS_IMAGE_NAME_A_ORIG,
            resolve(&k32, b"QueryFullProcessImageNameA\0"),
        );
        store(
            &QUERY_FULL_PROCESS_IMAGE_NAME_W_ORIG,
            resolve(&k32, b"QueryFullProcessImageNameW\0"),
        );
        store(&IS_WOW64_PROCESS_ORIG, resolve(&k32, b"IsWow64Process\0"));
        store(&GET_PROCESS_ID_ORIG, resolve(&k32, b"GetProcessId\0"));
        store(
            &GET_EXIT_CODE_PROCESS_ORIG,
            resolve(&k32, b"GetExitCodeProcess\0"),
        );

        let mut total = 0u32;
        total += iat::patch_all_modules(
            None,
            b"GetProcessImageFileNameA",
            get_process_image_file_name_a as *mut c_void,
        );
        total += iat::patch_all_modules(
            None,
            b"K32GetProcessImageFileNameA",
            get_process_image_file_name_a as *mut c_void,
        );
        total += iat::patch_all_modules(
            None,
            b"GetProcessImageFileNameW",
            get_process_image_file_name_w as *mut c_void,
        );
        total += iat::patch_all_modules(
            None,
            b"K32GetProcessImageFileNameW",
            get_process_image_file_name_w as *mut c_void,
        );
        total += iat::patch_all_modules(
            None,
            b"QueryFullProcessImageNameA",
            query_full_process_image_name_a as *mut c_void,
        );
        total += iat::patch_all_modules(
            None,
            b"QueryFullProcessImageNameW",
            query_full_process_image_name_w as *mut c_void,
        );
        total += iat::patch_all_modules(None, b"IsWow64Process", is_wow64_process as *mut c_void);
        total += iat::patch_all_modules(None, b"GetProcessId", get_process_id as *mut c_void);
        total += iat::patch_all_modules(
            None,
            b"GetExitCodeProcess",
            get_exit_code_process as *mut c_void,
        );
        total
    }
}
