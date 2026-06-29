//! # iat — the Import Address Table patch engine (ADR-0006)
//!
//! Given an imported function name, walk a loaded module's PE import directory and
//! rewrite the matching IAT slot to point at the carafe's replacement. Uses only
//! public Win32 exports (`GetModuleHandleW`, `GetProcAddress`, `VirtualProtect`,
//! `psapi!EnumProcessModules`) and the documented, frozen PE image layout — never a
//! Wine internal (rule #4). The only image mutation is a pointer in a data table,
//! guarded by `VirtualProtect`; there is no inline prologue patching.
//!
//! This is the mechanism the Phase 3 spike proved (`docs/DECISIONS.md` ADR-0006);
//! Phase 3 proper points the patched slots at the daemon-marshaling hooks in
//! [`crate::hooks`].

use core::ffi::c_void;

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(module_name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, proc_name: *const u8) -> *mut c_void;
    fn VirtualProtect(address: *mut c_void, size: usize, new_protect: u32, old_protect: *mut u32) -> i32;
    fn LoadLibraryA(lib_file_name: *const u8) -> *mut c_void;
    fn GetCurrentProcess() -> *mut c_void;
}

/// `PAGE_READWRITE` — protection set on an IAT slot before overwriting it.
const PAGE_READWRITE: u32 = 0x04;
/// Index of the export directory in the optional header's data-directory array.
const DIRECTORY_ENTRY_EXPORT: usize = 0;
/// Index of the import directory in the optional header's data-directory array.
const DIRECTORY_ENTRY_IMPORT: usize = 1;
/// Byte offset of the data-directory array within `IMAGE_OPTIONAL_HEADER64`.
const OPT_HDR_DATA_DIR_OFFSET: usize = 112;
/// High bit of a thunk value: set ⇒ import-by-ordinal (skip — we match names).
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

/// Absolute pointer from a mapped module base + RVA.
#[inline]
unsafe fn rva<T>(base: *const u8, rva: u32) -> *mut T {
    base.add(rva as usize) as *mut T
}

/// ASCII-case-insensitive compare of a C string against a slice (DLL names).
unsafe fn cstr_eq_ignore_case(ptr: *const u8, want: &[u8]) -> bool {
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
}

/// Exact compare of a C string against a slice (function names are case-sensitive).
unsafe fn cstr_eq(ptr: *const u8, want: &[u8]) -> bool {
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
}

/// Overwrite one 8-byte IAT slot, flipping the page writable first and restoring
/// protection after. Mutates *data* (a pointer table), never code.
unsafe fn write_iat_slot(slot: *mut c_void, value: u64) -> bool {
    let mut old: u32 = 0;
    if VirtualProtect(slot, 8, PAGE_READWRITE, &mut old as *mut u32) == 0 {
        return false;
    }
    (slot as *mut u64).write_unaligned(value);
    let mut discard: u32 = 0;
    VirtualProtect(slot, 8, old, &mut discard as *mut u32);
    true
}

/// The core system / forwarding DLLs whose **own** IATs must never be patched.
///
/// Patching these poisons the internal plumbing of the very exports we forward to:
/// e.g. `psapi!EnumProcessModules` forwards to `kernelbase` and, if patched, would
/// re-enter our hook, which forwards back — an infinite loop (observed on Wine as
/// runaway `EnumProcessModulesEx`). The carafe itself is excluded for the same
/// reason. Interception only needs the *tool's* modules; system DLLs keep calling
/// the real functions. (The forwarder always calls saved originals via a direct
/// `GetProcAddress` pointer, so a non-system module being patched never loops.)
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

/// `true` if a mapped module's PE export name is one of [`SYSTEM_DLLS`]. A module
/// with no export directory (e.g. the main `.exe`) is *not* a system DLL and is
/// patched. Reads only the public PE export directory — no API call, no allocation,
/// so it is safe to run while we are mid-install.
unsafe fn is_system_module(base: *mut c_void) -> bool {
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
        return false; // no exports → not a system DLL (the tool's exe lands here).
    }
    // IMAGE_EXPORT_DIRECTORY.Name is a u32 RVA at offset 12 to the DLL's own name.
    let name_rva = (base.add(export_rva as usize + 12) as *const u32).read_unaligned();
    if name_rva == 0 {
        return false;
    }
    let name_ptr = base.add(name_rva as usize);
    SYSTEM_DLLS.iter().any(|s| cstr_eq_ignore_case(name_ptr, s))
}

/// Walk one module's import directory and patch every IAT slot whose import name is
/// `func_name`. `module_filter`, when `Some`, restricts the match to imports from a
/// DLL of that name; `None` matches the function regardless of source DLL (used so
/// a tool importing e.g. `EnumProcessModules` from either `psapi` or `kernel32`
/// (`K32…`) is covered). Returns the number of slots patched.
pub unsafe fn patch_module_iat(
    base: *mut c_void,
    module_filter: Option<&[u8]>,
    func_name: &[u8],
    replacement: *mut c_void,
) -> u32 {
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
}

/// Patch `func_name` in **every loaded module** of this process, returning the
/// total slots rewritten. The main exe is always covered via
/// `GetModuleHandleW(NULL)`; the rest are enumerated via `psapi!EnumProcessModules`.
/// `module_filter` is forwarded to [`patch_module_iat`] (`None` ⇒ match by function
/// name in any descriptor).
pub unsafe fn patch_all_modules(
    module_filter: Option<&[u8]>,
    func_name: &[u8],
    replacement: *mut c_void,
) -> u32 {
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
                        continue; // main already done; never patch core/forwarding DLLs.
                    }
                    total += patch_module_iat(m, module_filter, func_name, replacement);
                }
            }
        }
    }

    total
}
