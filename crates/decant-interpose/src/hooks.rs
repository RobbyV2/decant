//! # hooks — the daemon-marshaling Win32/NT replacements
//!
//! The real export bodies the carafe installs over the tool's IAT. Each one splits
//! on the handle: a **synthetic** handle (minted by [`crate::handle_table`]) is
//! serviced by marshaling to the daemon over [`crate::rpc`]; a **real** handle is
//! forwarded to the saved original (`crate::originals`), so Wine handles the tool
//! genuinely owns are untouched (spec Phase 3, ADR-0006). Snapshots are built from
//! daemon data, never wineserver (spec rule #6).
//!
//! Every body is `extern "system"` with the exact public ABI of the export it
//! shadows (one x64 convention, ADR-0004) and is panic-free: a dead daemon yields a
//! Win32 `FALSE` / `NTSTATUS` failure, never a crash of the host tool.

use core::ffi::c_void;
use core::sync::atomic::Ordering;

use decant_protocol::{Pid, Request, Response};

use crate::handle_table;
use crate::iat;
use crate::originals::{self, ORIGINALS};
use crate::rpc;

// --- Win32/NT constants (all public) --------------------------------------
const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
const TH32CS_SNAPMODULE: u32 = 0x0000_0008;
const TH32CS_SNAPMODULE32: u32 = 0x0000_0010;
const PAGE_READWRITE: u32 = 0x04;
const STATUS_SUCCESS: i32 = 0;
const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001u32 as i32;

/// `INVALID_HANDLE_VALUE` (`(HANDLE)-1`), returned by a failed snapshot.
#[inline]
fn invalid_handle() -> *mut c_void {
    usize::MAX as *mut c_void
}

// --- Forwardable original function pointer types --------------------------
type RpmFn = unsafe extern "system" fn(*mut c_void, *const c_void, *mut c_void, usize, *mut usize) -> i32;
type WpmFn = unsafe extern "system" fn(*mut c_void, *mut c_void, *const c_void, usize, *mut usize) -> i32;
type NtRwFn = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void, usize, *mut usize) -> i32;
type CloseFn = unsafe extern "system" fn(*mut c_void) -> i32;
type EnumModsFn = unsafe extern "system" fn(*mut c_void, *mut *mut c_void, u32, *mut u32) -> i32;
type GetNameAFn = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut u8, u32) -> u32;
type GetNameWFn = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut u16, u32) -> u32;

// ---------------------------------------------------------------------------
// Toolhelp / psapi structures (public, frozen layouts — rule #4).
// ---------------------------------------------------------------------------

/// `PROCESSENTRY32` (ANSI). `th32DefaultHeapID` is `ULONG_PTR` (8 bytes on x64),
/// so `#[repr(C)]` inserts the 4 bytes of padding Windows also has after the three
/// leading `DWORD`s.
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

/// `PROCESSENTRY32W` (wide).
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

/// `MODULEENTRY32` (ANSI). `modBaseAddr`/`hModule` are pointers (8 bytes), so the
/// repr matches the documented padded layout.
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

/// `MODULEENTRY32W` (wide).
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

// --- small string helpers --------------------------------------------------

/// Write `s` (NUL-terminated, truncated) into a fixed ANSI buffer.
fn put_ansi(buf: &mut [u8], s: &str) {
    let bytes = s.as_bytes();
    let n = bytes.len().min(buf.len().saturating_sub(1));
    buf[..n].copy_from_slice(&bytes[..n]);
    buf[n] = 0;
}

/// Write `s` (NUL-terminated, truncated) into a fixed wide buffer.
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

/// Write `s` into a caller-sized ANSI buffer; returns chars written (sans NUL).
unsafe fn put_ansi_counted(ptr: *mut u8, size: u32, s: &str) -> u32 {
    if ptr.is_null() || size == 0 {
        return 0;
    }
    let bytes = s.as_bytes();
    let n = bytes.len().min((size as usize) - 1);
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, n);
    *ptr.add(n) = 0;
    n as u32
}

/// Write `s` into a caller-sized wide buffer; returns chars written (sans NUL).
unsafe fn put_wide_counted(ptr: *mut u16, size: u32, s: &str) -> u32 {
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
}

// ---------------------------------------------------------------------------
// Memory: OpenProcess / Read / Write / Nt{Read,Write}VirtualMemory.
// ---------------------------------------------------------------------------

/// `OpenProcess` → a synthetic handle bound to the guest pid. We verify the pid
/// exists via the daemon (`ProcessByPid`); if it does not (or the daemon is down)
/// we return `NULL`, exactly as Windows fails an open of a non-existent process.
pub unsafe extern "system" fn open_process(_access: u32, _inherit: i32, pid: u32) -> *mut c_void {
    match rpc::request(Request::ProcessByPid(Pid(pid))) {
        Some(Response::Process(_)) => handle_table::open_process(Pid(pid)) as *mut c_void,
        _ => core::ptr::null_mut(),
    }
}

/// Shared synthetic read: daemon `Read`, fill `buffer`, set `bytes_read`. Returns
/// the bytes delivered (0 on failure).
unsafe fn synth_read(
    handle: usize,
    addr: u64,
    buffer: *mut c_void,
    size: usize,
    bytes_read: *mut usize,
) -> usize {
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
}

/// Shared synthetic write: daemon `Write`, set `bytes_written`. Returns bytes
/// written (0 on failure).
unsafe fn synth_write(
    handle: usize,
    addr: u64,
    buffer: *const c_void,
    size: usize,
    bytes_written: *mut usize,
) -> usize {
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
}

/// `ReadProcessMemory` — daemon for synthetic handles, forward otherwise.
pub unsafe extern "system" fn read_process_memory(
    process: *mut c_void,
    base_address: *const c_void,
    buffer: *mut c_void,
    size: usize,
    bytes_read: *mut usize,
) -> i32 {
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
}

/// `WriteProcessMemory` — daemon for synthetic handles, forward otherwise.
pub unsafe extern "system" fn write_process_memory(
    process: *mut c_void,
    base_address: *mut c_void,
    buffer: *const c_void,
    size: usize,
    bytes_written: *mut usize,
) -> i32 {
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
}

/// `NtReadVirtualMemory` — same daemon path, NTSTATUS return.
pub unsafe extern "system" fn nt_read_virtual_memory(
    process: *mut c_void,
    base_address: *mut c_void,
    buffer: *mut c_void,
    size: usize,
    bytes_read: *mut usize,
) -> i32 {
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
}

/// `NtWriteVirtualMemory` — same daemon path, NTSTATUS return.
pub unsafe extern "system" fn nt_write_virtual_memory(
    process: *mut c_void,
    base_address: *mut c_void,
    buffer: *mut c_void,
    size: usize,
    bytes_written: *mut usize,
) -> i32 {
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
}

// ---------------------------------------------------------------------------
// Handle lifetime: CloseHandle / NtClose.
// ---------------------------------------------------------------------------

/// `CloseHandle` — drop a synthetic handle (TRUE), forward a real one. Any handle
/// in the synthetic range is ours and returns TRUE even if already dropped, so a
/// synthetic handle never reaches the real `CloseHandle`.
pub unsafe extern "system" fn close_handle(handle: *mut c_void) -> i32 {
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
}

/// `NtClose` — same policy, NTSTATUS return.
pub unsafe extern "system" fn nt_close(handle: *mut c_void) -> i32 {
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
}

// ---------------------------------------------------------------------------
// Toolhelp snapshots (from daemon data — spec rule #6).
// ---------------------------------------------------------------------------

/// `CreateToolhelp32Snapshot` — capture the daemon's process or module list into a
/// synthetic snapshot handle. `INVALID_HANDLE_VALUE` if the daemon is unreachable.
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

unsafe fn fill_process_ansi(handle: usize, entry: *mut ProcessEntry32, reset: bool) -> i32 {
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
}

unsafe fn fill_process_wide(handle: usize, entry: *mut ProcessEntry32W, reset: bool) -> i32 {
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
}

/// `Process32First` — rewind the snapshot, return its first process.
pub unsafe extern "system" fn process32_first(snapshot: *mut c_void, entry: *mut ProcessEntry32) -> i32 {
    fill_process_ansi(snapshot as usize, entry, true)
}
/// `Process32Next` — return the next process in the snapshot.
pub unsafe extern "system" fn process32_next(snapshot: *mut c_void, entry: *mut ProcessEntry32) -> i32 {
    fill_process_ansi(snapshot as usize, entry, false)
}
/// `Process32FirstW`.
pub unsafe extern "system" fn process32_first_w(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32 {
    fill_process_wide(snapshot as usize, entry, true)
}
/// `Process32NextW`.
pub unsafe extern "system" fn process32_next_w(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32 {
    fill_process_wide(snapshot as usize, entry, false)
}

unsafe fn fill_module_ansi(handle: usize, entry: *mut ModuleEntry32, reset: bool) -> i32 {
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
}

unsafe fn fill_module_wide(handle: usize, entry: *mut ModuleEntry32W, reset: bool) -> i32 {
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
}

/// `Module32First`.
pub unsafe extern "system" fn module32_first(snapshot: *mut c_void, entry: *mut ModuleEntry32) -> i32 {
    fill_module_ansi(snapshot as usize, entry, true)
}
/// `Module32Next`.
pub unsafe extern "system" fn module32_next(snapshot: *mut c_void, entry: *mut ModuleEntry32) -> i32 {
    fill_module_ansi(snapshot as usize, entry, false)
}
/// `Module32FirstW`.
pub unsafe extern "system" fn module32_first_w(snapshot: *mut c_void, entry: *mut ModuleEntry32W) -> i32 {
    fill_module_wide(snapshot as usize, entry, true)
}
/// `Module32NextW`.
pub unsafe extern "system" fn module32_next_w(snapshot: *mut c_void, entry: *mut ModuleEntry32W) -> i32 {
    fill_module_wide(snapshot as usize, entry, false)
}

// ---------------------------------------------------------------------------
// psapi / K32 enumeration.
// ---------------------------------------------------------------------------

/// `EnumProcesses`/`K32EnumProcesses` — daemon process pids into the out array.
pub unsafe extern "system" fn enum_processes(pids: *mut u32, cb: u32, needed: *mut u32) -> i32 {
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
}

/// `EnumProcessModules`/`K32EnumProcessModules` — daemon module bases for a
/// synthetic process handle; forward a real handle.
pub unsafe extern "system" fn enum_process_modules(
    process: *mut c_void,
    modules: *mut *mut c_void,
    cb: u32,
    needed: *mut u32,
) -> i32 {
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
}

/// Find a module name by base in a synthetic process's daemon module list.
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

/// `GetModuleBaseNameA`/`K32…` — base name of a module in a synthetic process.
pub unsafe extern "system" fn get_module_base_name_a(
    process: *mut c_void,
    module: *mut c_void,
    base_name: *mut u8,
    size: u32,
) -> u32 {
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
}

/// `GetModuleBaseNameW`/`K32…`.
pub unsafe extern "system" fn get_module_base_name_w(
    process: *mut c_void,
    module: *mut c_void,
    base_name: *mut u16,
    size: u32,
) -> u32 {
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
}

/// `GetModuleFileNameExA`/`K32…` — best-effort: the daemon exposes only the module
/// name, which we return as the path (Decant has no guest filesystem view).
pub unsafe extern "system" fn get_module_file_name_ex_a(
    process: *mut c_void,
    module: *mut c_void,
    file_name: *mut u8,
    size: u32,
) -> u32 {
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
}

/// `GetModuleFileNameExW`/`K32…`.
pub unsafe extern "system" fn get_module_file_name_ex_w(
    process: *mut c_void,
    module: *mut c_void,
    file_name: *mut u16,
    size: u32,
) -> u32 {
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
}

// ---------------------------------------------------------------------------
// Protection: VirtualProtectEx no-op success (spec §9).
// ---------------------------------------------------------------------------

/// `VirtualProtectEx` — no-op success. Physical writes ignore virtual protection,
/// so flipping protection is meaningless to Decant; we report success and a
/// plausible prior protection rather than failing the tool (spec §9).
pub unsafe extern "system" fn virtual_protect_ex(
    _process: *mut c_void,
    _address: *mut c_void,
    _size: usize,
    _new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    if !old_protect.is_null() {
        *old_protect = PAGE_READWRITE;
    }
    1
}

// ---------------------------------------------------------------------------
// Installer: capture originals, then patch every target name across all modules.
// ---------------------------------------------------------------------------

/// Resolve and save the originals, then rewrite every targeted IAT slot in this
/// process to the matching hook. Returns the total number of slots patched.
///
/// Each name is matched in any descriptor (`None` filter) so a tool importing,
/// say, `EnumProcessModules` from either `psapi` or `kernel32` (`K32…`) is covered.
pub unsafe fn install_all() -> u32 {
    originals::capture();

    let mut total = 0u32;
    macro_rules! patch {
        ($name:expr, $hook:expr) => {
            total += iat::patch_all_modules(None, $name, $hook as *mut c_void);
        };
    }

    // Memory.
    patch!(b"OpenProcess", open_process);
    patch!(b"ReadProcessMemory", read_process_memory);
    patch!(b"WriteProcessMemory", write_process_memory);
    patch!(b"NtReadVirtualMemory", nt_read_virtual_memory);
    patch!(b"NtWriteVirtualMemory", nt_write_virtual_memory);

    // Handle lifetime.
    patch!(b"CloseHandle", close_handle);
    patch!(b"NtClose", nt_close);

    // Toolhelp.
    patch!(b"CreateToolhelp32Snapshot", create_toolhelp32_snapshot);
    patch!(b"Process32First", process32_first);
    patch!(b"Process32Next", process32_next);
    patch!(b"Process32FirstW", process32_first_w);
    patch!(b"Process32NextW", process32_next_w);
    patch!(b"Module32First", module32_first);
    patch!(b"Module32Next", module32_next);
    patch!(b"Module32FirstW", module32_first_w);
    patch!(b"Module32NextW", module32_next_w);

    // psapi / K32 enumeration.
    patch!(b"EnumProcesses", enum_processes);
    patch!(b"K32EnumProcesses", enum_processes);
    patch!(b"EnumProcessModules", enum_process_modules);
    patch!(b"K32EnumProcessModules", enum_process_modules);
    patch!(b"GetModuleBaseNameA", get_module_base_name_a);
    patch!(b"K32GetModuleBaseNameA", get_module_base_name_a);
    patch!(b"GetModuleBaseNameW", get_module_base_name_w);
    patch!(b"K32GetModuleBaseNameW", get_module_base_name_w);
    patch!(b"GetModuleFileNameExA", get_module_file_name_ex_a);
    patch!(b"K32GetModuleFileNameExA", get_module_file_name_ex_a);
    patch!(b"GetModuleFileNameExW", get_module_file_name_ex_w);
    patch!(b"K32GetModuleFileNameExW", get_module_file_name_ex_w);

    // Protection.
    patch!(b"VirtualProtectEx", virtual_protect_ex);

    total
}
