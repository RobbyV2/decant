use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(module_name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, proc_name: *const u8) -> *mut c_void;
    fn LoadLibraryA(lib_file_name: *const u8) -> *mut c_void;
}

pub struct Originals {
    pub read_process_memory: AtomicUsize,
    pub write_process_memory: AtomicUsize,
    pub nt_read_virtual_memory: AtomicUsize,
    pub nt_write_virtual_memory: AtomicUsize,
    pub close_handle: AtomicUsize,
    pub nt_close: AtomicUsize,
    pub enum_process_modules: AtomicUsize,
    pub get_module_base_name_a: AtomicUsize,
    pub get_module_base_name_w: AtomicUsize,
    pub get_module_file_name_ex_a: AtomicUsize,
    pub get_module_file_name_ex_w: AtomicUsize,
    pub virtual_query_ex: AtomicUsize,
    pub virtual_alloc_ex: AtomicUsize,
    pub virtual_free_ex: AtomicUsize,
    pub nt_allocate_virtual_memory: AtomicUsize,
    pub nt_free_virtual_memory: AtomicUsize,
    pub create_remote_thread: AtomicUsize,
    pub create_remote_thread_ex: AtomicUsize,
    pub nt_create_thread_ex: AtomicUsize,
}

impl Originals {
    const fn new() -> Self {
        Originals {
            read_process_memory: AtomicUsize::new(0),
            write_process_memory: AtomicUsize::new(0),
            nt_read_virtual_memory: AtomicUsize::new(0),
            nt_write_virtual_memory: AtomicUsize::new(0),
            close_handle: AtomicUsize::new(0),
            nt_close: AtomicUsize::new(0),
            enum_process_modules: AtomicUsize::new(0),
            get_module_base_name_a: AtomicUsize::new(0),
            get_module_base_name_w: AtomicUsize::new(0),
            get_module_file_name_ex_a: AtomicUsize::new(0),
            get_module_file_name_ex_w: AtomicUsize::new(0),
            virtual_query_ex: AtomicUsize::new(0),
            virtual_alloc_ex: AtomicUsize::new(0),
            virtual_free_ex: AtomicUsize::new(0),
            nt_allocate_virtual_memory: AtomicUsize::new(0),
            nt_free_virtual_memory: AtomicUsize::new(0),
            create_remote_thread: AtomicUsize::new(0),
            create_remote_thread_ex: AtomicUsize::new(0),
            nt_create_thread_ex: AtomicUsize::new(0),
        }
    }
}

pub static ORIGINALS: Originals = Originals::new();

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

unsafe fn resolve(module_w: &[u16], name: &[u8]) -> usize {
    let h = GetModuleHandleW(module_w.as_ptr());
    if h.is_null() {
        return 0;
    }
    GetProcAddress(h, name.as_ptr()) as usize
}

pub unsafe fn capture() {
    LoadLibraryA(b"psapi.dll\0".as_ptr());
    LoadLibraryA(b"ntdll.dll\0".as_ptr());

    let k32 = wide("kernel32.dll");
    let ntdll = wide("ntdll.dll");
    let psapi = wide("psapi.dll");

    let store = |slot: &AtomicUsize, v: usize| slot.store(v, Ordering::SeqCst);

    store(&ORIGINALS.read_process_memory, resolve(&k32, b"ReadProcessMemory\0"));
    store(&ORIGINALS.write_process_memory, resolve(&k32, b"WriteProcessMemory\0"));
    store(&ORIGINALS.nt_read_virtual_memory, resolve(&ntdll, b"NtReadVirtualMemory\0"));
    store(&ORIGINALS.nt_write_virtual_memory, resolve(&ntdll, b"NtWriteVirtualMemory\0"));
    store(&ORIGINALS.close_handle, resolve(&k32, b"CloseHandle\0"));
    store(&ORIGINALS.nt_close, resolve(&ntdll, b"NtClose\0"));

    let epm = {
        let p = resolve(&psapi, b"EnumProcessModules\0");
        if p != 0 { p } else { resolve(&k32, b"K32EnumProcessModules\0") }
    };
    store(&ORIGINALS.enum_process_modules, epm);

    let gmbn_a = {
        let p = resolve(&psapi, b"GetModuleBaseNameA\0");
        if p != 0 { p } else { resolve(&k32, b"K32GetModuleBaseNameA\0") }
    };
    store(&ORIGINALS.get_module_base_name_a, gmbn_a);
    let gmbn_w = {
        let p = resolve(&psapi, b"GetModuleBaseNameW\0");
        if p != 0 { p } else { resolve(&k32, b"K32GetModuleBaseNameW\0") }
    };
    store(&ORIGINALS.get_module_base_name_w, gmbn_w);
    let gmfn_a = {
        let p = resolve(&psapi, b"GetModuleFileNameExA\0");
        if p != 0 { p } else { resolve(&k32, b"K32GetModuleFileNameExA\0") }
    };
    store(&ORIGINALS.get_module_file_name_ex_a, gmfn_a);
    let gmfn_w = {
        let p = resolve(&psapi, b"GetModuleFileNameExW\0");
        if p != 0 { p } else { resolve(&k32, b"K32GetModuleFileNameExW\0") }
    };
    store(&ORIGINALS.get_module_file_name_ex_w, gmfn_w);

    store(&ORIGINALS.virtual_query_ex, resolve(&k32, b"VirtualQueryEx\0"));
    store(&ORIGINALS.virtual_alloc_ex, resolve(&k32, b"VirtualAllocEx\0"));
    store(&ORIGINALS.virtual_free_ex, resolve(&k32, b"VirtualFreeEx\0"));
    store(&ORIGINALS.nt_allocate_virtual_memory, resolve(&ntdll, b"NtAllocateVirtualMemory\0"));
    store(&ORIGINALS.nt_free_virtual_memory, resolve(&ntdll, b"NtFreeVirtualMemory\0"));
    store(&ORIGINALS.create_remote_thread, resolve(&k32, b"CreateRemoteThread\0"));
    store(&ORIGINALS.create_remote_thread_ex, resolve(&k32, b"CreateRemoteThreadEx\0"));
    store(&ORIGINALS.nt_create_thread_ex, resolve(&ntdll, b"NtCreateThreadEx\0"));
}
