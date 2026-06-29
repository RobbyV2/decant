use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

use decant_protocol::{Request, Response};

use crate::handle_table;
use crate::hooks::{put_ansi_counted, put_wide_counted, MemoryBasicInformation};
use crate::iat;
use crate::rpc;

const TRUE: i32 = 1;
const FALSE: i32 = 0;
const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const MEM_COMMIT: u32 = 0x1000;
const MEM_PRIVATE: u32 = 0x20000;
const MEMORY_BASIC_INFORMATION_CLASS: u32 = 0;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(module_name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, proc_name: *const u8) -> *mut c_void;
}

#[repr(C)]
pub struct ModuleInformation {
    lp_base_of_dll: *mut c_void,
    size_of_image: u32,
    entry_point: *mut c_void,
}

static GET_MODULE_INFORMATION_ORIG: AtomicUsize = AtomicUsize::new(0);
static ENUM_PROCESS_MODULES_EX_ORIG: AtomicUsize = AtomicUsize::new(0);
static GET_MAPPED_FILE_NAME_A_ORIG: AtomicUsize = AtomicUsize::new(0);
static GET_MAPPED_FILE_NAME_W_ORIG: AtomicUsize = AtomicUsize::new(0);
static NT_QUERY_VIRTUAL_MEMORY_ORIG: AtomicUsize = AtomicUsize::new(0);

type GetModInfoFn = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut ModuleInformation, u32) -> i32;
type EnumModsExFn = unsafe extern "system" fn(*mut c_void, *mut *mut c_void, u32, *mut u32, u32) -> i32;
type MappedAFn = unsafe extern "system" fn(*mut c_void, *const c_void, *mut u8, u32) -> u32;
type MappedWFn = unsafe extern "system" fn(*mut c_void, *const c_void, *mut u16, u32) -> u32;
type NtQvmFn = unsafe extern "system" fn(*mut c_void, *const c_void, u32, *mut c_void, usize, *mut usize) -> i32;

fn protect_of(readable: bool, writable: bool, executable: bool) -> u32 {
    match (readable, writable, executable) {
        (_, true, true) => 0x40,
        (_, true, false) => 0x04,
        (true, false, true) => 0x20,
        (true, false, false) => 0x02,
        _ => 0x01,
    }
}

unsafe fn name_containing(handle: usize, addr: u64) -> Option<String> {
    let pid = handle_table::pid_for(handle)?;
    match rpc::request(Request::ModuleList(pid)) {
        Some(Response::Modules(list)) => list
            .iter()
            .find(|m| addr >= m.base && addr < m.base + m.size)
            .map(|m| m.name.clone()),
        _ => None,
    }
}

pub unsafe extern "system" fn get_module_information(
    process: *mut c_void,
    module: *mut c_void,
    mi: *mut ModuleInformation,
    cb: u32,
) -> i32 { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        let pid = match handle_table::pid_for(h) {
            Some(p) => p,
            None => return FALSE,
        };
        if mi.is_null() {
            return FALSE;
        }
        let base = module as u64;
        match rpc::request(Request::ModuleList(pid)) {
            Some(Response::Modules(list)) => match list.iter().find(|m| m.base == base) {
                Some(m) => {
                    *mi = ModuleInformation {
                        lp_base_of_dll: m.base as *mut c_void,
                        size_of_image: m.size as u32,
                        entry_point: m.base as *mut c_void,
                    };
                    TRUE
                }
                None => FALSE,
            },
            _ => FALSE,
        }
    } else {
        let p = GET_MODULE_INFORMATION_ORIG.load(Ordering::SeqCst);
        match p {
            0 => FALSE,
            _ => {
                let f: GetModInfoFn = core::mem::transmute(p);
                f(process, module, mi, cb)
            }
        }
    }
}}

pub unsafe extern "system" fn enum_process_modules_ex(
    process: *mut c_void,
    modules: *mut *mut c_void,
    cb: u32,
    needed: *mut u32,
    filter: u32,
) -> i32 { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        let pid = match handle_table::pid_for(h) {
            Some(p) => p,
            None => return FALSE,
        };
        match rpc::request(Request::ModuleList(pid)) {
            Some(Response::Modules(list)) => {
                let cap = (cb as usize) / core::mem::size_of::<*mut c_void>();
                let n = list.len().min(cap);
                if !modules.is_null() {
                    for (i, m) in list.iter().take(n).enumerate() {
                        *modules.add(i) = m.base as *mut c_void;
                    }
                }
                if !needed.is_null() {
                    *needed = (list.len() * core::mem::size_of::<*mut c_void>()) as u32;
                }
                TRUE
            }
            _ => FALSE,
        }
    } else {
        let p = ENUM_PROCESS_MODULES_EX_ORIG.load(Ordering::SeqCst);
        match p {
            0 => FALSE,
            _ => {
                let f: EnumModsExFn = core::mem::transmute(p);
                f(process, modules, cb, needed, filter)
            }
        }
    }
}}

pub unsafe extern "system" fn get_mapped_file_name_a(
    process: *mut c_void,
    addr: *const c_void,
    file_name: *mut u8,
    size: u32,
) -> u32 { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        match name_containing(h, addr as u64) {
            Some(name) => put_ansi_counted(file_name, size, &name),
            None => 0,
        }
    } else {
        let p = GET_MAPPED_FILE_NAME_A_ORIG.load(Ordering::SeqCst);
        match p {
            0 => 0,
            _ => {
                let f: MappedAFn = core::mem::transmute(p);
                f(process, addr, file_name, size)
            }
        }
    }
}}

pub unsafe extern "system" fn get_mapped_file_name_w(
    process: *mut c_void,
    addr: *const c_void,
    file_name: *mut u16,
    size: u32,
) -> u32 { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        match name_containing(h, addr as u64) {
            Some(name) => put_wide_counted(file_name, size, &name),
            None => 0,
        }
    } else {
        let p = GET_MAPPED_FILE_NAME_W_ORIG.load(Ordering::SeqCst);
        match p {
            0 => 0,
            _ => {
                let f: MappedWFn = core::mem::transmute(p);
                f(process, addr, file_name, size)
            }
        }
    }
}}

pub unsafe extern "system" fn nt_query_virtual_memory(
    process: *mut c_void,
    base_address: *const c_void,
    info_class: u32,
    info: *mut c_void,
    len: usize,
    ret: *mut usize,
) -> i32 { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        let pid = match handle_table::pid_for(h) {
            Some(p) => p,
            None => return STATUS_INVALID_PARAMETER,
        };
        if info_class != MEMORY_BASIC_INFORMATION_CLASS
            || info.is_null()
            || len < core::mem::size_of::<MemoryBasicInformation>()
        {
            return STATUS_INVALID_PARAMETER;
        }
        let addr = base_address as u64;
        match rpc::request(Request::MemoryMap(pid)) {
            Some(Response::MemoryMap(regions)) => {
                match regions.iter().find(|r| addr >= r.base && addr < r.base + r.size) {
                    Some(r) => {
                        let protect = protect_of(r.readable, r.writable, r.executable);
                        *(info as *mut MemoryBasicInformation) = MemoryBasicInformation {
                            base_address: r.base as usize,
                            allocation_base: r.base as usize,
                            allocation_protect: protect,
                            __align1: 0,
                            region_size: r.size as usize,
                            state: MEM_COMMIT,
                            protect,
                            type_: MEM_PRIVATE,
                            __align2: 0,
                        };
                        if !ret.is_null() {
                            *ret = core::mem::size_of::<MemoryBasicInformation>();
                        }
                        STATUS_SUCCESS
                    }
                    None => STATUS_INVALID_PARAMETER,
                }
            }
            _ => STATUS_INVALID_PARAMETER,
        }
    } else {
        let p = NT_QUERY_VIRTUAL_MEMORY_ORIG.load(Ordering::SeqCst);
        match p {
            0 => STATUS_INVALID_PARAMETER,
            _ => {
                let f: NtQvmFn = core::mem::transmute(p);
                f(process, base_address, info_class, info, len, ret)
            }
        }
    }
}}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

unsafe fn resolve(module_w: &[u16], name: &[u8]) -> usize { unsafe {
    let h = GetModuleHandleW(module_w.as_ptr());
    match h.is_null() {
        true => 0,
        false => GetProcAddress(h, name.as_ptr()) as usize,
    }
}}

pub(crate) unsafe fn redirect(name: *const u8) -> *mut c_void { unsafe {
    if iat::cstr_eq(name, b"GetModuleInformation") { return get_module_information as *mut c_void; }
    if iat::cstr_eq(name, b"K32GetModuleInformation") { return get_module_information as *mut c_void; }
    if iat::cstr_eq(name, b"EnumProcessModulesEx") { return enum_process_modules_ex as *mut c_void; }
    if iat::cstr_eq(name, b"K32EnumProcessModulesEx") { return enum_process_modules_ex as *mut c_void; }
    if iat::cstr_eq(name, b"GetMappedFileNameA") { return get_mapped_file_name_a as *mut c_void; }
    if iat::cstr_eq(name, b"K32GetMappedFileNameA") { return get_mapped_file_name_a as *mut c_void; }
    if iat::cstr_eq(name, b"GetMappedFileNameW") { return get_mapped_file_name_w as *mut c_void; }
    if iat::cstr_eq(name, b"K32GetMappedFileNameW") { return get_mapped_file_name_w as *mut c_void; }
    if iat::cstr_eq(name, b"NtQueryVirtualMemory") { return nt_query_virtual_memory as *mut c_void; }
    core::ptr::null_mut()
}}

// the mapped-file name is the module name; the protection is coarse
pub unsafe fn install() -> u32 { unsafe {
    let k32 = wide("kernel32.dll");
    let ntdll = wide("ntdll.dll");
    let psapi = wide("psapi.dll");

    let first = |a: usize, b: usize| match a {
        0 => b,
        _ => a,
    };

    GET_MODULE_INFORMATION_ORIG.store(
        first(resolve(&psapi, b"GetModuleInformation\0"), resolve(&k32, b"K32GetModuleInformation\0")),
        Ordering::SeqCst,
    );
    ENUM_PROCESS_MODULES_EX_ORIG.store(
        first(resolve(&psapi, b"EnumProcessModulesEx\0"), resolve(&k32, b"K32EnumProcessModulesEx\0")),
        Ordering::SeqCst,
    );
    GET_MAPPED_FILE_NAME_A_ORIG.store(
        first(resolve(&psapi, b"GetMappedFileNameA\0"), resolve(&k32, b"K32GetMappedFileNameA\0")),
        Ordering::SeqCst,
    );
    GET_MAPPED_FILE_NAME_W_ORIG.store(
        first(resolve(&psapi, b"GetMappedFileNameW\0"), resolve(&k32, b"K32GetMappedFileNameW\0")),
        Ordering::SeqCst,
    );
    NT_QUERY_VIRTUAL_MEMORY_ORIG.store(resolve(&ntdll, b"NtQueryVirtualMemory\0"), Ordering::SeqCst);

    let mut total = 0u32;
    macro_rules! patch {
        ($name:expr_2021, $hook:expr_2021) => {
            total += iat::patch_all_modules(None, $name, $hook as *mut c_void);
        };
    }

    patch!(b"GetModuleInformation", get_module_information);
    patch!(b"K32GetModuleInformation", get_module_information);
    patch!(b"EnumProcessModulesEx", enum_process_modules_ex);
    patch!(b"K32EnumProcessModulesEx", enum_process_modules_ex);
    patch!(b"GetMappedFileNameA", get_mapped_file_name_a);
    patch!(b"K32GetMappedFileNameA", get_mapped_file_name_a);
    patch!(b"GetMappedFileNameW", get_mapped_file_name_w);
    patch!(b"K32GetMappedFileNameW", get_mapped_file_name_w);
    patch!(b"NtQueryVirtualMemory", nt_query_virtual_memory);

    total
}}
