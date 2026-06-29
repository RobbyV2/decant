use core::ffi::c_void;
use core::sync::atomic::Ordering;
use std::sync::Mutex;

use decant_protocol::{MemRegion, Pid, Request, Response};

use crate::handle_table;
use crate::iat;
use crate::originals::{self, ORIGINALS};
use crate::rpc;

const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
const TH32CS_SNAPMODULE: u32 = 0x0000_0008;
const TH32CS_SNAPMODULE32: u32 = 0x0000_0010;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const MEM_COMMIT: u32 = 0x1000;
const MEM_FREE: u32 = 0x10000;
const MEM_PRIVATE: u32 = 0x20000;
const STATUS_SUCCESS: i32 = 0;
const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001u32 as i32;
const STATUS_NOT_SUPPORTED: i32 = 0xC000_00BBu32 as i32;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const STATUS_NO_MORE_ENTRIES: i32 = 0x8000_001Au32 as i32;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const SYSTEM_PROCESS_INFORMATION: u32 = 5;
const SPI_STRIDE: usize = 0x100;
const PROCESS_IMAGE_FILE_NAME: u32 = 27;
const PROCESS_WOW64_INFORMATION: u32 = 26;

macro_rules! interpose_exports {
    ($apply:ident) => {
        $apply! {
            b"GetProcAddress" => get_proc_address,
            b"OpenProcess" => open_process,
            b"ReadProcessMemory" => read_process_memory,
            b"WriteProcessMemory" => write_process_memory,
            b"NtReadVirtualMemory" => nt_read_virtual_memory,
            b"NtWriteVirtualMemory" => nt_write_virtual_memory,
            b"CloseHandle" => close_handle,
            b"NtClose" => nt_close,
            b"CreateToolhelp32Snapshot" => create_toolhelp32_snapshot,
            b"Process32First" => process32_first,
            b"Process32Next" => process32_next,
            b"Process32FirstW" => process32_first_w,
            b"Process32NextW" => process32_next_w,
            b"Module32First" => module32_first,
            b"Module32Next" => module32_next,
            b"Module32FirstW" => module32_first_w,
            b"Module32NextW" => module32_next_w,
            b"EnumProcesses" => enum_processes,
            b"K32EnumProcesses" => enum_processes,
            b"EnumProcessModules" => enum_process_modules,
            b"K32EnumProcessModules" => enum_process_modules,
            b"GetModuleBaseNameA" => get_module_base_name_a,
            b"K32GetModuleBaseNameA" => get_module_base_name_a,
            b"GetModuleBaseNameW" => get_module_base_name_w,
            b"K32GetModuleBaseNameW" => get_module_base_name_w,
            b"GetModuleFileNameExA" => get_module_file_name_ex_a,
            b"K32GetModuleFileNameExA" => get_module_file_name_ex_a,
            b"GetModuleFileNameExW" => get_module_file_name_ex_w,
            b"K32GetModuleFileNameExW" => get_module_file_name_ex_w,
            b"VirtualProtectEx" => virtual_protect_ex,
            b"VirtualQueryEx" => virtual_query_ex,
            b"VirtualAllocEx" => virtual_alloc_ex,
            b"VirtualFreeEx" => virtual_free_ex,
            b"NtAllocateVirtualMemory" => nt_allocate_virtual_memory,
            b"NtFreeVirtualMemory" => nt_free_virtual_memory,
            b"CreateRemoteThread" => create_remote_thread,
            b"CreateRemoteThreadEx" => create_remote_thread_ex,
            b"NtCreateThreadEx" => nt_create_thread_ex,
            b"NtQuerySystemInformation" => nt_query_system_information,
            b"NtOpenProcess" => nt_open_process,
            b"NtGetNextProcess" => nt_get_next_process,
            b"Toolhelp32ReadProcessMemory" => toolhelp32_read_process_memory,
            b"NtQueryInformationProcess" => nt_query_information_process,
        }
    };
}

macro_rules! do_install {
    ($($n:expr => $f:ident),* $(,)?) => {{
        let mut t = 0u32;
        $( t += iat::patch_all_modules(None, $n, $f as *mut c_void); )*
        t
    }};
}

macro_rules! do_redirect {
    ($($n:expr => $f:ident),* $(,)?) => {
        pub(crate) unsafe fn redirect(name: *const u8) -> *mut c_void { unsafe {
            $( if iat::cstr_eq(name, $n) { return $f as *mut c_void; } )*
            core::ptr::null_mut()
        }}
    };
}

interpose_exports!(do_redirect);

#[repr(C)]
pub(crate) struct ClientId {
    pub unique_process: usize,
    pub unique_thread: usize,
}

#[repr(C)]
pub struct MemoryBasicInformation {
    pub base_address: usize,
    pub allocation_base: usize,
    pub allocation_protect: u32,
    pub __align1: u32,
    pub region_size: usize,
    pub state: u32,
    pub protect: u32,
    pub type_: u32,
    pub __align2: u32,
}

#[inline]
fn invalid_handle() -> *mut c_void {
    usize::MAX as *mut c_void
}

fn report_unsupported(op: &str) {
    let _ = rpc::request(Request::ReportUnsupported { op: op.to_string() });
    eprintln!("decant: refused unsupported operation {op}; the guest cannot execute code through the handle model");
}

fn protect_flags(readable: bool, writable: bool, executable: bool) -> u32 {
    match (readable, writable, executable) {
        (_, true, true) => PAGE_EXECUTE_READWRITE,
        (_, true, false) => PAGE_READWRITE,
        (_, false, true) => PAGE_EXECUTE_READ,
        (true, false, false) => PAGE_READONLY,
        _ => PAGE_NOACCESS,
    }
}

struct RegionCache {
    pid: Pid,
    regions: Vec<MemRegion>,
}

static REGION_CACHE: Mutex<Option<RegionCache>> = Mutex::new(None);

// A region walker queries upward from a low address; report committed regions and
// span the gaps as free so the caller advances instead of stalling at the first hole.
// The map is fetched once per walk (cached by pid, refreshed when the walk restarts at 0)
// to avoid one daemon round trip per query.
pub(crate) fn region_for(pid: Pid, addr: u64) -> Option<MemoryBasicInformation> {
    let mut guard = REGION_CACHE.lock().ok()?;
    let refresh = match guard.as_ref() {
        Some(c) => c.pid != pid || addr == 0,
        None => true,
    };
    if refresh {
        let mut regions = match rpc::request(Request::MemoryMap(pid)) {
            Some(Response::MemoryMap(r)) => r,
            _ => return None,
        };
        regions.sort_by_key(|r| r.base);
        *guard = Some(RegionCache { pid, regions });
    }
    let regions = &guard.as_ref()?.regions;

    if let Some(r) = regions.iter().find(|r| addr >= r.base && addr < r.base + r.size) {
        let p = protect_flags(r.readable, r.writable, r.executable);
        return Some(MemoryBasicInformation {
            base_address: r.base as usize,
            allocation_base: r.base as usize,
            allocation_protect: p,
            __align1: 0,
            region_size: r.size as usize,
            state: MEM_COMMIT,
            protect: p,
            type_: MEM_PRIVATE,
            __align2: 0,
        });
    }

    let next = regions.iter().filter(|r| r.base > addr).map(|r| r.base).min()?;
    Some(MemoryBasicInformation {
        base_address: addr as usize,
        allocation_base: 0,
        allocation_protect: 0,
        __align1: 0,
        region_size: (next - addr) as usize,
        state: MEM_FREE,
        protect: PAGE_NOACCESS,
        type_: 0,
        __align2: 0,
    })
}

type RpmFn = unsafe extern "system" fn(*mut c_void, *const c_void, *mut c_void, usize, *mut usize) -> i32;
type WpmFn = unsafe extern "system" fn(*mut c_void, *mut c_void, *const c_void, usize, *mut usize) -> i32;
type NtRwFn = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void, usize, *mut usize) -> i32;
type CloseFn = unsafe extern "system" fn(*mut c_void) -> i32;
type EnumModsFn = unsafe extern "system" fn(*mut c_void, *mut *mut c_void, u32, *mut u32) -> i32;
type GetNameAFn = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut u8, u32) -> u32;
type GetNameWFn = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut u16, u32) -> u32;

#[repr(C)]
pub struct ProcessEntry32 {
    pub dw_size: u32,
    pub cnt_usage: u32,
    pub th32_process_id: u32,
    pub th32_default_heap_id: usize,
    pub th32_module_id: u32,
    pub cnt_threads: u32,
    pub th32_parent_process_id: u32,
    pub pc_pri_class_base: i32,
    pub dw_flags: u32,
    pub sz_exe_file: [u8; 260],
}

#[repr(C)]
pub struct ProcessEntry32W {
    pub dw_size: u32,
    pub cnt_usage: u32,
    pub th32_process_id: u32,
    pub th32_default_heap_id: usize,
    pub th32_module_id: u32,
    pub cnt_threads: u32,
    pub th32_parent_process_id: u32,
    pub pc_pri_class_base: i32,
    pub dw_flags: u32,
    pub sz_exe_file: [u16; 260],
}

#[repr(C)]
pub struct ModuleEntry32 {
    pub dw_size: u32,
    pub th32_module_id: u32,
    pub th32_process_id: u32,
    pub glblcnt_usage: u32,
    pub proccnt_usage: u32,
    pub mod_base_addr: usize,
    pub mod_base_size: u32,
    pub h_module: usize,
    pub sz_module: [u8; 256],
    pub sz_exe_path: [u8; 260],
}

#[repr(C)]
pub struct ModuleEntry32W {
    pub dw_size: u32,
    pub th32_module_id: u32,
    pub th32_process_id: u32,
    pub glblcnt_usage: u32,
    pub proccnt_usage: u32,
    pub mod_base_addr: usize,
    pub mod_base_size: u32,
    pub h_module: usize,
    pub sz_module: [u16; 256],
    pub sz_exe_path: [u16; 260],
}

fn put_ansi(buf: &mut [u8], s: &str) {
    let bytes = s.as_bytes();
    let n = bytes.len().min(buf.len().saturating_sub(1));
    buf[..n].copy_from_slice(&bytes[..n]);
    buf[n] = 0;
}

fn put_wide(buf: &mut [u16], s: &str) {
    let mut i = 0usize;
    for u in s.encode_utf16() {
        if i + 1 >= buf.len() {
            break;
        }
        buf[i] = u;
        i += 1;
    }
    buf[i] = 0;
}

pub(crate) unsafe fn put_ansi_counted(ptr: *mut u8, size: u32, s: &str) -> u32 { unsafe {
    if ptr.is_null() || size == 0 {
        return 0;
    }
    let bytes = s.as_bytes();
    let n = bytes.len().min((size as usize) - 1);
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, n);
    *ptr.add(n) = 0;
    n as u32
}}

pub(crate) unsafe fn put_wide_counted(ptr: *mut u16, size: u32, s: &str) -> u32 { unsafe {
    if ptr.is_null() || size == 0 {
        return 0;
    }
    let mut i = 0usize;
    for u in s.encode_utf16() {
        if i + 1 >= size as usize {
            break;
        }
        *ptr.add(i) = u;
        i += 1;
    }
    *ptr.add(i) = 0;
    i as u32
}}

pub unsafe extern "system" fn open_process(_access: u32, _inherit: i32, pid: u32) -> *mut c_void {
    match rpc::request(Request::ProcessByPid(Pid(pid))) {
        Some(Response::Process(_)) => handle_table::open_process(Pid(pid)) as *mut c_void,
        _ => core::ptr::null_mut(),
    }
}

unsafe fn synth_read(
    handle: usize,
    addr: u64,
    buffer: *mut c_void,
    size: usize,
    bytes_read: *mut usize,
) -> usize { unsafe {
    if !bytes_read.is_null() {
        *bytes_read = 0;
    }
    let pid = match handle_table::pid_for(handle) {
        Some(p) => p,
        None => return 0,
    };
    if buffer.is_null() || size == 0 {
        return 0;
    }
    match rpc::request(Request::Read { pid, addr, len: size as u64 }) {
        Some(Response::Data(data)) => {
            let n = data.len().min(size);
            if n == 0 {
                return 0;
            }
            core::ptr::copy_nonoverlapping(data.as_ptr(), buffer as *mut u8, n);
            if !bytes_read.is_null() {
                *bytes_read = n;
            }
            n
        }
        _ => 0,
    }
}}

unsafe fn synth_write(
    handle: usize,
    addr: u64,
    buffer: *const c_void,
    size: usize,
    bytes_written: *mut usize,
) -> usize { unsafe {
    if !bytes_written.is_null() {
        *bytes_written = 0;
    }
    let pid = match handle_table::pid_for(handle) {
        Some(p) => p,
        None => return 0,
    };
    if buffer.is_null() || size == 0 {
        return 0;
    }
    let data = core::slice::from_raw_parts(buffer as *const u8, size).to_vec();
    match rpc::request(Request::Write { pid, addr, data }) {
        Some(Response::Written(n)) => {
            let n = (n as usize).min(size);
            if !bytes_written.is_null() {
                *bytes_written = n;
            }
            n
        }
        _ => 0,
    }
}}

pub unsafe extern "system" fn read_process_memory(
    process: *mut c_void,
    base_address: *const c_void,
    buffer: *mut c_void,
    size: usize,
    bytes_read: *mut usize,
) -> i32 { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        let n = synth_read(h, base_address as u64, buffer, size, bytes_read);
        return (n == size && size > 0) as i32;
    }
    let p = ORIGINALS.read_process_memory.load(Ordering::SeqCst);
    if p != 0 {
        let f: RpmFn = core::mem::transmute(p);
        return f(process, base_address, buffer, size, bytes_read);
    }
    if !bytes_read.is_null() {
        *bytes_read = 0;
    }
    0
}}

pub unsafe extern "system" fn write_process_memory(
    process: *mut c_void,
    base_address: *mut c_void,
    buffer: *const c_void,
    size: usize,
    bytes_written: *mut usize,
) -> i32 { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        let n = synth_write(h, base_address as u64, buffer, size, bytes_written);
        return (n == size && size > 0) as i32;
    }
    let p = ORIGINALS.write_process_memory.load(Ordering::SeqCst);
    if p != 0 {
        let f: WpmFn = core::mem::transmute(p);
        return f(process, base_address, buffer, size, bytes_written);
    }
    if !bytes_written.is_null() {
        *bytes_written = 0;
    }
    0
}}

pub unsafe extern "system" fn nt_read_virtual_memory(
    process: *mut c_void,
    base_address: *mut c_void,
    buffer: *mut c_void,
    size: usize,
    bytes_read: *mut usize,
) -> i32 { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        let n = synth_read(h, base_address as u64, buffer, size, bytes_read);
        return if n == size && size > 0 { STATUS_SUCCESS } else { STATUS_UNSUCCESSFUL };
    }
    let p = ORIGINALS.nt_read_virtual_memory.load(Ordering::SeqCst);
    if p != 0 {
        let f: NtRwFn = core::mem::transmute(p);
        return f(process, base_address, buffer, size, bytes_read);
    }
    STATUS_UNSUCCESSFUL
}}

pub unsafe extern "system" fn nt_write_virtual_memory(
    process: *mut c_void,
    base_address: *mut c_void,
    buffer: *mut c_void,
    size: usize,
    bytes_written: *mut usize,
) -> i32 { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        let n = synth_write(h, base_address as u64, buffer, size, bytes_written);
        return if n == size && size > 0 { STATUS_SUCCESS } else { STATUS_UNSUCCESSFUL };
    }
    let p = ORIGINALS.nt_write_virtual_memory.load(Ordering::SeqCst);
    if p != 0 {
        let f: NtRwFn = core::mem::transmute(p);
        return f(process, base_address, buffer, size, bytes_written);
    }
    STATUS_UNSUCCESSFUL
}}

pub unsafe extern "system" fn close_handle(handle: *mut c_void) -> i32 { unsafe {
    let h = handle as usize;
    if handle_table::is_synthetic(h) {
        handle_table::free(h);
        return 1;
    }
    let p = ORIGINALS.close_handle.load(Ordering::SeqCst);
    if p != 0 {
        let f: CloseFn = core::mem::transmute(p);
        return f(handle);
    }
    1
}}

pub unsafe extern "system" fn nt_close(handle: *mut c_void) -> i32 { unsafe {
    let h = handle as usize;
    if handle_table::is_synthetic(h) {
        handle_table::free(h);
        return STATUS_SUCCESS;
    }
    let p = ORIGINALS.nt_close.load(Ordering::SeqCst);
    if p != 0 {
        let f: CloseFn = core::mem::transmute(p);
        return f(handle);
    }
    STATUS_SUCCESS
}}

pub unsafe extern "system" fn create_toolhelp32_snapshot(flags: u32, pid: u32) -> *mut c_void {
    if flags & TH32CS_SNAPPROCESS != 0 {
        if let Some(Response::Processes(list)) = rpc::request(Request::ListProcesses) {
            let h = handle_table::new_process_snapshot(list);
            if h != 0 {
                return h as *mut c_void;
            }
        }
        return invalid_handle();
    }
    if flags & (TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32) != 0 {
        if let Some(Response::Modules(list)) = rpc::request(Request::ModuleList(Pid(pid))) {
            let h = handle_table::new_module_snapshot(list);
            if h != 0 {
                return h as *mut c_void;
            }
        }
        return invalid_handle();
    }
    invalid_handle()
}

unsafe fn fill_process_ansi(handle: usize, entry: *mut ProcessEntry32, reset: bool) -> i32 { unsafe {
    if entry.is_null() {
        return 0;
    }
    match handle_table::snapshot_next_process(handle, reset) {
        Some(pi) => {
            let e = &mut *entry;
            e.cnt_usage = 1;
            e.th32_process_id = pi.pid.0;
            e.cnt_threads = 1;
            put_ansi(&mut e.sz_exe_file, &pi.name);
            1
        }
        None => 0,
    }
}}

unsafe fn fill_process_wide(handle: usize, entry: *mut ProcessEntry32W, reset: bool) -> i32 { unsafe {
    if entry.is_null() {
        return 0;
    }
    match handle_table::snapshot_next_process(handle, reset) {
        Some(pi) => {
            let e = &mut *entry;
            e.cnt_usage = 1;
            e.th32_process_id = pi.pid.0;
            e.cnt_threads = 1;
            put_wide(&mut e.sz_exe_file, &pi.name);
            1
        }
        None => 0,
    }
}}

pub unsafe extern "system" fn process32_first(snapshot: *mut c_void, entry: *mut ProcessEntry32) -> i32 { unsafe {
    fill_process_ansi(snapshot as usize, entry, true)
}}
pub unsafe extern "system" fn process32_next(snapshot: *mut c_void, entry: *mut ProcessEntry32) -> i32 { unsafe {
    fill_process_ansi(snapshot as usize, entry, false)
}}
pub unsafe extern "system" fn process32_first_w(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32 { unsafe {
    fill_process_wide(snapshot as usize, entry, true)
}}
pub unsafe extern "system" fn process32_next_w(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32 { unsafe {
    fill_process_wide(snapshot as usize, entry, false)
}}

unsafe fn fill_module_ansi(handle: usize, entry: *mut ModuleEntry32, reset: bool) -> i32 { unsafe {
    if entry.is_null() {
        return 0;
    }
    match handle_table::snapshot_next_module(handle, reset) {
        Some(mi) => {
            let e = &mut *entry;
            e.th32_module_id = 1;
            e.mod_base_addr = mi.base as usize;
            e.mod_base_size = mi.size as u32;
            e.h_module = mi.base as usize;
            put_ansi(&mut e.sz_module, &mi.name);
            put_ansi(&mut e.sz_exe_path, &mi.name);
            1
        }
        None => 0,
    }
}}

unsafe fn fill_module_wide(handle: usize, entry: *mut ModuleEntry32W, reset: bool) -> i32 { unsafe {
    if entry.is_null() {
        return 0;
    }
    match handle_table::snapshot_next_module(handle, reset) {
        Some(mi) => {
            let e = &mut *entry;
            e.th32_module_id = 1;
            e.mod_base_addr = mi.base as usize;
            e.mod_base_size = mi.size as u32;
            e.h_module = mi.base as usize;
            put_wide(&mut e.sz_module, &mi.name);
            put_wide(&mut e.sz_exe_path, &mi.name);
            1
        }
        None => 0,
    }
}}

pub unsafe extern "system" fn module32_first(snapshot: *mut c_void, entry: *mut ModuleEntry32) -> i32 { unsafe {
    fill_module_ansi(snapshot as usize, entry, true)
}}
pub unsafe extern "system" fn module32_next(snapshot: *mut c_void, entry: *mut ModuleEntry32) -> i32 { unsafe {
    fill_module_ansi(snapshot as usize, entry, false)
}}
pub unsafe extern "system" fn module32_first_w(snapshot: *mut c_void, entry: *mut ModuleEntry32W) -> i32 { unsafe {
    fill_module_wide(snapshot as usize, entry, true)
}}
pub unsafe extern "system" fn module32_next_w(snapshot: *mut c_void, entry: *mut ModuleEntry32W) -> i32 { unsafe {
    fill_module_wide(snapshot as usize, entry, false)
}}

pub unsafe extern "system" fn enum_processes(pids: *mut u32, cb: u32, needed: *mut u32) -> i32 { unsafe {
    if let Some(Response::Processes(list)) = rpc::request(Request::ListProcesses) {
        let cap = (cb as usize) / core::mem::size_of::<u32>();
        let n = list.len().min(cap);
        if !pids.is_null() {
            for (i, p) in list.iter().take(n).enumerate() {
                *pids.add(i) = p.pid.0;
            }
        }
        if !needed.is_null() {
            *needed = (n * core::mem::size_of::<u32>()) as u32;
        }
        return 1;
    }
    0
}}

pub unsafe extern "system" fn enum_process_modules(
    process: *mut c_void,
    modules: *mut *mut c_void,
    cb: u32,
    needed: *mut u32,
) -> i32 { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        let pid = match handle_table::pid_for(h) {
            Some(p) => p,
            None => return 0,
        };
        if let Some(Response::Modules(list)) = rpc::request(Request::ModuleList(pid)) {
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
            return 1;
        }
        return 0;
    }
    let p = ORIGINALS.enum_process_modules.load(Ordering::SeqCst);
    if p != 0 {
        let f: EnumModsFn = core::mem::transmute(p);
        return f(process, modules, cb, needed);
    }
    0
}}

unsafe fn module_name_for(handle: usize, module: *mut c_void) -> Option<String> {
    let pid = handle_table::pid_for(handle)?;
    if let Some(Response::Modules(list)) = rpc::request(Request::ModuleList(pid)) {
        let target = module as u64;
        if let Some(mi) = list.iter().find(|m| m.base == target) {
            return Some(mi.name.clone());
        }
        if module.is_null() {
            return list.first().map(|m| m.name.clone());
        }
    }
    None
}

pub unsafe extern "system" fn get_module_base_name_a(
    process: *mut c_void,
    module: *mut c_void,
    base_name: *mut u8,
    size: u32,
) -> u32 { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        return match module_name_for(h, module) {
            Some(name) => put_ansi_counted(base_name, size, &name),
            None => 0,
        };
    }
    let p = ORIGINALS.get_module_base_name_a.load(Ordering::SeqCst);
    if p != 0 {
        let f: GetNameAFn = core::mem::transmute(p);
        return f(process, module, base_name, size);
    }
    0
}}

pub unsafe extern "system" fn get_module_base_name_w(
    process: *mut c_void,
    module: *mut c_void,
    base_name: *mut u16,
    size: u32,
) -> u32 { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        return match module_name_for(h, module) {
            Some(name) => put_wide_counted(base_name, size, &name),
            None => 0,
        };
    }
    let p = ORIGINALS.get_module_base_name_w.load(Ordering::SeqCst);
    if p != 0 {
        let f: GetNameWFn = core::mem::transmute(p);
        return f(process, module, base_name, size);
    }
    0
}}

pub unsafe extern "system" fn get_module_file_name_ex_a(
    process: *mut c_void,
    module: *mut c_void,
    file_name: *mut u8,
    size: u32,
) -> u32 { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        return match module_name_for(h, module) {
            Some(name) => put_ansi_counted(file_name, size, &name),
            None => 0,
        };
    }
    let p = ORIGINALS.get_module_file_name_ex_a.load(Ordering::SeqCst);
    if p != 0 {
        let f: GetNameAFn = core::mem::transmute(p);
        return f(process, module, file_name, size);
    }
    0
}}

pub unsafe extern "system" fn get_module_file_name_ex_w(
    process: *mut c_void,
    module: *mut c_void,
    file_name: *mut u16,
    size: u32,
) -> u32 { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        return match module_name_for(h, module) {
            Some(name) => put_wide_counted(file_name, size, &name),
            None => 0,
        };
    }
    let p = ORIGINALS.get_module_file_name_ex_w.load(Ordering::SeqCst);
    if p != 0 {
        let f: GetNameWFn = core::mem::transmute(p);
        return f(process, module, file_name, size);
    }
    0
}}

pub unsafe extern "system" fn virtual_protect_ex(
    _process: *mut c_void,
    _address: *mut c_void,
    _size: usize,
    _new_protect: u32,
    old_protect: *mut u32,
) -> i32 { unsafe {
    if !old_protect.is_null() {
        *old_protect = PAGE_READWRITE;
    }
    1
}}

type VqExFn = unsafe extern "system" fn(*mut c_void, *const c_void, *mut MemoryBasicInformation, usize) -> usize;
type VAllocExFn = unsafe extern "system" fn(*mut c_void, *mut c_void, usize, u32, u32) -> *mut c_void;
type VFreeExFn = unsafe extern "system" fn(*mut c_void, *mut c_void, usize, u32) -> i32;
type NtAllocFn = unsafe extern "system" fn(*mut c_void, *mut *mut c_void, usize, *mut usize, u32, u32) -> i32;
type NtFreeFn = unsafe extern "system" fn(*mut c_void, *mut *mut c_void, *mut usize, u32) -> i32;
type CrtFn = unsafe extern "system" fn(*mut c_void, *mut c_void, usize, *mut c_void, *mut c_void, u32, *mut u32) -> *mut c_void;
type CrtExFn = unsafe extern "system" fn(*mut c_void, *mut c_void, usize, *mut c_void, *mut c_void, u32, *mut u32, *mut c_void) -> *mut c_void;
type NtCreateThreadExFn = unsafe extern "system" fn(*mut *mut c_void, u32, *mut c_void, *mut c_void, *mut c_void, *mut c_void, u32, usize, usize, usize, *mut c_void) -> i32;

pub unsafe extern "system" fn virtual_query_ex(
    process: *mut c_void,
    address: *const c_void,
    mbi: *mut MemoryBasicInformation,
    length: usize,
) -> usize { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        let pid = match handle_table::pid_for(h) {
            Some(p) => p,
            None => return 0,
        };
        if mbi.is_null() || length < core::mem::size_of::<MemoryBasicInformation>() {
            return 0;
        }
        match region_for(pid, address as u64) {
            Some(info) => {
                *mbi = info;
                return core::mem::size_of::<MemoryBasicInformation>();
            }
            None => return 0,
        }
    }
    let p = ORIGINALS.virtual_query_ex.load(Ordering::SeqCst);
    if p != 0 {
        let f: VqExFn = core::mem::transmute(p);
        return f(process, address, mbi, length);
    }
    0
}}

pub unsafe extern "system" fn virtual_alloc_ex(
    process: *mut c_void,
    address: *mut c_void,
    size: usize,
    alloc_type: u32,
    protect: u32,
) -> *mut c_void { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        report_unsupported("VirtualAllocEx");
        return core::ptr::null_mut();
    }
    let p = ORIGINALS.virtual_alloc_ex.load(Ordering::SeqCst);
    if p != 0 {
        let f: VAllocExFn = core::mem::transmute(p);
        return f(process, address, size, alloc_type, protect);
    }
    core::ptr::null_mut()
}}

pub unsafe extern "system" fn virtual_free_ex(
    process: *mut c_void,
    address: *mut c_void,
    size: usize,
    free_type: u32,
) -> i32 { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        report_unsupported("VirtualFreeEx");
        return 0;
    }
    let p = ORIGINALS.virtual_free_ex.load(Ordering::SeqCst);
    if p != 0 {
        let f: VFreeExFn = core::mem::transmute(p);
        return f(process, address, size, free_type);
    }
    0
}}

pub unsafe extern "system" fn nt_allocate_virtual_memory(
    process: *mut c_void,
    base: *mut *mut c_void,
    zerobits: usize,
    size: *mut usize,
    alloc_type: u32,
    protect: u32,
) -> i32 { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        report_unsupported("NtAllocateVirtualMemory");
        return STATUS_NOT_SUPPORTED;
    }
    let p = ORIGINALS.nt_allocate_virtual_memory.load(Ordering::SeqCst);
    if p != 0 {
        let f: NtAllocFn = core::mem::transmute(p);
        return f(process, base, zerobits, size, alloc_type, protect);
    }
    STATUS_NOT_SUPPORTED
}}

pub unsafe extern "system" fn nt_free_virtual_memory(
    process: *mut c_void,
    base: *mut *mut c_void,
    size: *mut usize,
    free_type: u32,
) -> i32 { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        report_unsupported("NtFreeVirtualMemory");
        return STATUS_NOT_SUPPORTED;
    }
    let p = ORIGINALS.nt_free_virtual_memory.load(Ordering::SeqCst);
    if p != 0 {
        let f: NtFreeFn = core::mem::transmute(p);
        return f(process, base, size, free_type);
    }
    STATUS_NOT_SUPPORTED
}}

pub unsafe extern "system" fn create_remote_thread(
    process: *mut c_void,
    attrs: *mut c_void,
    stack: usize,
    start: *mut c_void,
    param: *mut c_void,
    flags: u32,
    tid: *mut u32,
) -> *mut c_void { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        report_unsupported("CreateRemoteThread");
        return core::ptr::null_mut();
    }
    let p = ORIGINALS.create_remote_thread.load(Ordering::SeqCst);
    if p != 0 {
        let f: CrtFn = core::mem::transmute(p);
        return f(process, attrs, stack, start, param, flags, tid);
    }
    core::ptr::null_mut()
}}

pub unsafe extern "system" fn create_remote_thread_ex(
    process: *mut c_void,
    attrs: *mut c_void,
    stack: usize,
    start: *mut c_void,
    param: *mut c_void,
    flags: u32,
    tid: *mut u32,
    attr_list: *mut c_void,
) -> *mut c_void { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        report_unsupported("CreateRemoteThreadEx");
        return core::ptr::null_mut();
    }
    let p = ORIGINALS.create_remote_thread_ex.load(Ordering::SeqCst);
    if p != 0 {
        let f: CrtExFn = core::mem::transmute(p);
        return f(process, attrs, stack, start, param, flags, tid, attr_list);
    }
    core::ptr::null_mut()
}}

pub unsafe extern "system" fn nt_create_thread_ex(
    thread: *mut *mut c_void,
    access: u32,
    objattrs: *mut c_void,
    process: *mut c_void,
    start: *mut c_void,
    param: *mut c_void,
    flags: u32,
    zerobits: usize,
    stacksize: usize,
    maxstack: usize,
    attrlist: *mut c_void,
) -> i32 { unsafe {
    let h = process as usize;
    if handle_table::is_synthetic(h) {
        report_unsupported("NtCreateThreadEx");
        return STATUS_NOT_SUPPORTED;
    }
    let p = ORIGINALS.nt_create_thread_ex.load(Ordering::SeqCst);
    if p != 0 {
        let f: NtCreateThreadExFn = core::mem::transmute(p);
        return f(
            thread, access, objattrs, process, start, param, flags, zerobits, stacksize, maxstack,
            attrlist,
        );
    }
    STATUS_NOT_SUPPORTED
}}

pub unsafe extern "system" fn get_proc_address(module: *mut c_void, name: *const u8) -> *mut c_void { unsafe {
    if (name as usize) >> 16 != 0 {
        let r = redirect(name);
        if !r.is_null() {
            return r;
        }
        let r = crate::process_hooks::redirect(name);
        if !r.is_null() {
            return r;
        }
        let r = crate::module_hooks::redirect(name);
        if !r.is_null() {
            return r;
        }
    }
    let orig = ORIGINALS.get_proc_address.load(Ordering::SeqCst);
    if orig == 0 {
        return core::ptr::null_mut();
    }
    let f: unsafe extern "system" fn(*mut c_void, *const u8) -> *mut c_void = core::mem::transmute(orig);
    f(module, name)
}}

pub unsafe extern "system" fn nt_query_system_information(
    class: u32,
    info: *mut c_void,
    len: u32,
    ret_len: *mut u32,
) -> i32 { unsafe {
    if class != SYSTEM_PROCESS_INFORMATION {
        let orig = ORIGINALS.nt_query_system_information.load(Ordering::SeqCst);
        if orig == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let f: unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32 =
            core::mem::transmute(orig);
        return f(class, info, len, ret_len);
    }

    let list = match rpc::request(Request::ListProcesses) {
        Some(Response::Processes(l)) => l,
        _ => return STATUS_UNSUCCESSFUL,
    };

    let entry_size = |nb: usize| SPI_STRIDE + ((nb + 7) & !7);
    let required: usize = list.iter().map(|p| entry_size(p.name.encode_utf16().count() * 2)).sum();

    if !ret_len.is_null() {
        *ret_len = required as u32;
    }
    if info.is_null() || (len as usize) < required {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    let base = info as *mut u8;
    core::ptr::write_bytes(base, 0, required);
    let mut off = 0usize;
    for (i, p) in list.iter().enumerate() {
        let entry = base.add(off);
        let nb = p.name.encode_utf16().count() * 2;
        let stride = entry_size(nb);
        let next = if i + 1 == list.len() { 0u32 } else { stride as u32 };

        (entry as *mut u32).write_unaligned(next);
        (entry.add(0x04) as *mut u32).write_unaligned(0);
        (entry.add(0x38) as *mut u16).write_unaligned(nb as u16);
        (entry.add(0x3A) as *mut u16).write_unaligned(nb as u16);
        let name_ptr = entry.add(SPI_STRIDE);
        (entry.add(0x40) as *mut u64).write_unaligned(name_ptr as u64);
        (entry.add(0x50) as *mut u64).write_unaligned(p.pid.0 as u64);

        let mut w = name_ptr as *mut u16;
        for u in p.name.encode_utf16() {
            w.write_unaligned(u);
            w = w.add(1);
        }
        off += stride;
    }
    STATUS_SUCCESS
}}

pub unsafe extern "system" fn nt_open_process(
    handle: *mut *mut c_void,
    _access: u32,
    _obj_attr: *mut c_void,
    client_id: *const ClientId,
) -> i32 { unsafe {
    if handle.is_null() || client_id.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let pid = (*client_id).unique_process as u32;
    match rpc::request(Request::ProcessByPid(Pid(pid))) {
        Some(Response::Process(_)) => {
            *handle = handle_table::open_process(Pid(pid)) as *mut c_void;
            STATUS_SUCCESS
        }
        _ => STATUS_INVALID_PARAMETER,
    }
}}

pub unsafe extern "system" fn nt_get_next_process(
    process: *mut c_void,
    _access: u32,
    _attrs: u32,
    _flags: u32,
    new_process: *mut *mut c_void,
) -> i32 { unsafe {
    if new_process.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let list = match rpc::request(Request::ListProcesses) {
        Some(Response::Processes(l)) => l,
        _ => return STATUS_UNSUCCESSFUL,
    };
    let start = match handle_table::pid_for(process as usize) {
        Some(cur) => list.iter().position(|p| p.pid == cur).map_or(0, |i| i + 1),
        None => 0,
    };
    match list.get(start) {
        Some(p) => {
            *new_process = handle_table::open_process(p.pid) as *mut c_void;
            STATUS_SUCCESS
        }
        None => STATUS_NO_MORE_ENTRIES,
    }
}}

pub unsafe extern "system" fn toolhelp32_read_process_memory(
    pid: u32,
    base: *const c_void,
    buffer: *mut c_void,
    size: usize,
    bytes_read: *mut usize,
) -> i32 { unsafe {
    if !bytes_read.is_null() {
        *bytes_read = 0;
    }
    if buffer.is_null() || size == 0 {
        return 0;
    }
    match rpc::request(Request::Read { pid: Pid(pid), addr: base as u64, len: size as u64 }) {
        Some(Response::Data(data)) => {
            let n = data.len().min(size);
            if n == 0 {
                return 0;
            }
            core::ptr::copy_nonoverlapping(data.as_ptr(), buffer as *mut u8, n);
            if !bytes_read.is_null() {
                *bytes_read = n;
            }
            1
        }
        _ => 0,
    }
}}

pub unsafe extern "system" fn nt_query_information_process(
    process: *mut c_void,
    class: u32,
    info: *mut c_void,
    len: u32,
    ret_len: *mut u32,
) -> i32 { unsafe {
    if !handle_table::is_synthetic(process as usize) {
        let orig = ORIGINALS.nt_query_information_process.load(Ordering::SeqCst);
        if orig == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let f: unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32, *mut u32) -> i32 =
            core::mem::transmute(orig);
        return f(process, class, info, len, ret_len);
    }
    let pid = match handle_table::pid_for(process as usize) {
        Some(p) => p,
        None => return STATUS_INVALID_PARAMETER,
    };
    match class {
        PROCESS_WOW64_INFORMATION => {
            if info.is_null() || (len as usize) < 8 {
                if !ret_len.is_null() {
                    *ret_len = 8;
                }
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            (info as *mut u64).write_unaligned(0);
            if !ret_len.is_null() {
                *ret_len = 8;
            }
            STATUS_SUCCESS
        }
        PROCESS_IMAGE_FILE_NAME => {
            let name = match rpc::request(Request::ProcessByPid(pid)) {
                Some(Response::Process(p)) => p.name,
                _ => return STATUS_INVALID_PARAMETER,
            };
            let nb = name.encode_utf16().count() * 2;
            let total = 0x10 + nb;
            if info.is_null() || (len as usize) < total {
                if !ret_len.is_null() {
                    *ret_len = total as u32;
                }
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            let base = info as *mut u8;
            let buf = base.add(0x10);
            (base as *mut u16).write_unaligned(nb as u16);
            (base.add(0x02) as *mut u16).write_unaligned(nb as u16);
            (base.add(0x08) as *mut u64).write_unaligned(buf as u64);
            let mut w = buf as *mut u16;
            for u in name.encode_utf16() {
                w.write_unaligned(u);
                w = w.add(1);
            }
            if !ret_len.is_null() {
                *ret_len = total as u32;
            }
            STATUS_SUCCESS
        }
        _ => STATUS_INVALID_PARAMETER,
    }
}}

pub unsafe fn install_all() -> u32 { unsafe {
    originals::capture();
    let mut total = interpose_exports!(do_install);
    total += crate::process_hooks::install();
    total += crate::module_hooks::install();
    total
}}
