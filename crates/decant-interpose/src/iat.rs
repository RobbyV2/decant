use core::ffi::c_void;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(module_name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, proc_name: *const u8) -> *mut c_void;
    fn VirtualProtect(address: *mut c_void, size: usize, new_protect: u32, old_protect: *mut u32) -> i32;
    fn LoadLibraryA(lib_file_name: *const u8) -> *mut c_void;
    fn GetCurrentProcess() -> *mut c_void;
}

const PAGE_READWRITE: u32 = 0x04;
const DIRECTORY_ENTRY_EXPORT: usize = 0;
const DIRECTORY_ENTRY_IMPORT: usize = 1;
const OPT_HDR_DATA_DIR_OFFSET: usize = 112;
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    _pad: [u8; 58],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct ImageImportDescriptor {
    original_first_thunk: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
}

#[inline]
unsafe fn rva<T>(base: *const u8, rva: u32) -> *mut T { unsafe {
    base.add(rva as usize) as *mut T
}}

unsafe fn cstr_eq_ignore_case(ptr: *const u8, want: &[u8]) -> bool { unsafe {
    let mut i = 0usize;
    loop {
        let c = *ptr.add(i);
        if i == want.len() {
            return c == 0;
        }
        if c == 0 || !c.eq_ignore_ascii_case(&want[i]) {
            return false;
        }
        i += 1;
    }
}}

unsafe fn cstr_eq(ptr: *const u8, want: &[u8]) -> bool { unsafe {
    let mut i = 0usize;
    loop {
        let c = *ptr.add(i);
        if i == want.len() {
            return c == 0;
        }
        if c == 0 || c != want[i] {
            return false;
        }
        i += 1;
    }
}}

unsafe fn write_iat_slot(slot: *mut c_void, value: u64) -> bool { unsafe {
    let mut old: u32 = 0;
    if VirtualProtect(slot, 8, PAGE_READWRITE, &mut old as *mut u32) == 0 {
        return false;
    }
    (slot as *mut u64).write_unaligned(value);
    let mut discard: u32 = 0;
    VirtualProtect(slot, 8, old, &mut discard as *mut u32);
    true
}}

// patching these reenters the exports we forward to and loops
const SYSTEM_DLLS: &[&[u8]] = &[
    b"ntdll.dll",
    b"kernel32.dll",
    b"kernelbase.dll",
    b"psapi.dll",
    b"sechost.dll",
    b"win32u.dll",
    b"kernel.appcore.dll",
    b"ucrtbase.dll",
    b"msvcrt.dll",
    b"decant_interpose.dll",
];

unsafe fn is_system_module(base: *mut c_void) -> bool { unsafe {
    if base.is_null() {
        return false;
    }
    let base = base as *const u8;
    let dos = &*(base as *const ImageDosHeader);
    if dos.e_magic != 0x5A4D {
        return false;
    }
    let nt = base.add(dos.e_lfanew as usize);
    if (nt as *const u32).read_unaligned() != 0x0000_4550 {
        return false;
    }
    let opt_hdr = nt.add(4 + core::mem::size_of::<ImageFileHeader>());
    let export_dir = opt_hdr
        .add(OPT_HDR_DATA_DIR_OFFSET + DIRECTORY_ENTRY_EXPORT * core::mem::size_of::<ImageDataDirectory>())
        as *const ImageDataDirectory;
    let export_rva = (*export_dir).virtual_address;
    if export_rva == 0 {
        return false;
    }
    let name_rva = (base.add(export_rva as usize + 12) as *const u32).read_unaligned();
    if name_rva == 0 {
        return false;
    }
    let name_ptr = base.add(name_rva as usize);
    SYSTEM_DLLS.iter().any(|s| cstr_eq_ignore_case(name_ptr, s))
}}

pub unsafe fn patch_module_iat(
    base: *mut c_void,
    module_filter: Option<&[u8]>,
    func_name: &[u8],
    replacement: *mut c_void,
) -> u32 { unsafe {
    if base.is_null() {
        return 0;
    }
    let base = base as *const u8;

    let dos = &*(base as *const ImageDosHeader);
    if dos.e_magic != 0x5A4D {
        return 0;
    }
    let nt = base.add(dos.e_lfanew as usize);
    if (nt as *const u32).read_unaligned() != 0x0000_4550 {
        return 0;
    }
    let _file_hdr = &*(nt.add(4) as *const ImageFileHeader);
    let opt_hdr = nt.add(4 + core::mem::size_of::<ImageFileHeader>());

    let import_dir = opt_hdr.add(
        OPT_HDR_DATA_DIR_OFFSET + DIRECTORY_ENTRY_IMPORT * core::mem::size_of::<ImageDataDirectory>(),
    ) as *const ImageDataDirectory;
    let import_rva = (*import_dir).virtual_address;
    if import_rva == 0 {
        return 0;
    }

    let mut patched = 0u32;
    let mut desc = rva::<ImageImportDescriptor>(base, import_rva);

    loop {
        let d = &*desc;
        if d.original_first_thunk == 0 && d.first_thunk == 0 && d.name == 0 {
            break;
        }

        let dll_name = rva::<u8>(base, d.name);
        let dll_matches = match module_filter {
            Some(want) => cstr_eq_ignore_case(dll_name, want),
            None => true,
        };

        if dll_matches {
            let int_rva = if d.original_first_thunk != 0 {
                d.original_first_thunk
            } else {
                d.first_thunk
            };
            let mut name_thunk = rva::<u64>(base, int_rva);
            let mut iat_thunk = rva::<u64>(base, d.first_thunk);

            loop {
                let name_val = name_thunk.read_unaligned();
                if name_val == 0 {
                    break;
                }
                if name_val & IMAGE_ORDINAL_FLAG64 == 0 {
                    let imp_name = rva::<u8>(base, name_val as u32).add(2);
                    if cstr_eq(imp_name, func_name)
                        && write_iat_slot(iat_thunk as *mut c_void, replacement as u64)
                    {
                        patched += 1;
                    }
                }
                name_thunk = name_thunk.add(1);
                iat_thunk = iat_thunk.add(1);
            }
        }

        desc = desc.add(1);
    }

    patched
}}

pub unsafe fn patch_all_modules(
    module_filter: Option<&[u8]>,
    func_name: &[u8],
    replacement: *mut c_void,
) -> u32 { unsafe {
    let mut total = 0u32;

    let main_base = GetModuleHandleW(core::ptr::null());
    total += patch_module_iat(main_base, module_filter, func_name, replacement);

    type EnumProcModules = unsafe extern "system" fn(
        process: *mut c_void,
        modules: *mut *mut c_void,
        cb: u32,
        needed: *mut u32,
    ) -> i32;

    let psapi = LoadLibraryA(b"psapi.dll\0".as_ptr());
    if !psapi.is_null() {
        let enum_proc = GetProcAddress(psapi, b"EnumProcessModules\0".as_ptr());
        if !enum_proc.is_null() {
            let enum_proc: EnumProcModules = core::mem::transmute(enum_proc);
            let mut mods: [*mut c_void; 256] = [core::ptr::null_mut(); 256];
            let mut needed: u32 = 0;
            let cb = (mods.len() * core::mem::size_of::<*mut c_void>()) as u32;
            if enum_proc(GetCurrentProcess(), mods.as_mut_ptr(), cb, &mut needed) != 0 {
                let count = (needed as usize / core::mem::size_of::<*mut c_void>()).min(mods.len());
                for &m in &mods[..count] {
                    if m == main_base || m.is_null() || is_system_module(m) {
                        continue;
                    }
                    total += patch_module_iat(m, module_filter, func_name, replacement);
                }
            }
        }
    }

    total
}}
