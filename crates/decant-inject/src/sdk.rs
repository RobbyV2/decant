use std::ffi::c_void;

use crate::InjectError;

pub mod raw {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn VirtualAllocEx(
            process: *mut c_void,
            address: *mut c_void,
            size: usize,
            allocation_type: u32,
            protect: u32,
        ) -> *mut c_void;
        pub fn VirtualFreeEx(
            process: *mut c_void,
            address: *mut c_void,
            size: usize,
            free_type: u32,
        ) -> i32;
        pub fn VirtualProtectEx(
            process: *mut c_void,
            address: *mut c_void,
            size: usize,
            new_protect: u32,
            old_protect: *mut u32,
        ) -> i32;
        pub fn WriteProcessMemory(
            process: *mut c_void,
            base_address: *mut c_void,
            buffer: *const c_void,
            size: usize,
            written: *mut usize,
        ) -> i32;
        pub fn ReadProcessMemory(
            process: *mut c_void,
            base_address: *const c_void,
            buffer: *mut c_void,
            size: usize,
            read: *mut usize,
        ) -> i32;
        pub fn CreateRemoteThread(
            process: *mut c_void,
            thread_attributes: *const c_void,
            stack_size: usize,
            start_address: *mut c_void,
            parameter: *mut c_void,
            creation_flags: u32,
            thread_id: *mut u32,
        ) -> *mut c_void;
        pub fn GetThreadContext(thread: *mut c_void, context: *mut c_void) -> i32;
        pub fn SetThreadContext(thread: *mut c_void, context: *const c_void) -> i32;
        pub fn GetModuleHandleA(module_name: *const u8) -> *mut c_void;
        pub fn GetProcAddress(module: *mut c_void, proc_name: *const u8) -> *mut c_void;
        pub fn LoadLibraryA(file_name: *const u8) -> *mut c_void;
        pub fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
        pub fn CloseHandle(object: *mut c_void) -> i32;
        pub fn GetLastError() -> u32;
    }
}

pub const MEM_COMMIT_RESERVE: u32 = 0x0000_1000 | 0x0000_2000;
pub const MEM_RELEASE: u32 = 0x0000_8000;
pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const INFINITE: u32 = 0xFFFF_FFFF;

pub unsafe fn alloc(
    process: *mut c_void,
    size: usize,
    protect: u32,
) -> Result<*mut c_void, InjectError> {
    unsafe { alloc_at(process, std::ptr::null_mut(), size, protect) }
}

pub unsafe fn alloc_at(
    process: *mut c_void,
    address: *mut c_void,
    size: usize,
    protect: u32,
) -> Result<*mut c_void, InjectError> {
    let remote =
        unsafe { raw::VirtualAllocEx(process, address, size, MEM_COMMIT_RESERVE, protect) };
    match remote.is_null() {
        true => Err(InjectError::RemoteAlloc(unsafe { raw::GetLastError() })),
        false => Ok(remote),
    }
}

pub unsafe fn free(process: *mut c_void, address: *mut c_void) {
    let _ = unsafe { raw::VirtualFreeEx(process, address, 0, MEM_RELEASE) };
}

pub unsafe fn write(
    process: *mut c_void,
    remote: *mut c_void,
    bytes: &[u8],
) -> Result<(), InjectError> {
    let mut written = 0usize;
    let ok = unsafe {
        raw::WriteProcessMemory(
            process,
            remote,
            bytes.as_ptr() as *const c_void,
            bytes.len(),
            &mut written,
        )
    };
    match ok != 0 && written == bytes.len() {
        true => Ok(()),
        false => Err(InjectError::RemoteWrite(unsafe { raw::GetLastError() })),
    }
}

pub unsafe fn read_usize(
    process: *mut c_void,
    remote: *const c_void,
) -> Result<usize, InjectError> {
    let mut out = 0usize;
    let mut read = 0usize;
    let ok = unsafe {
        raw::ReadProcessMemory(
            process,
            remote,
            &mut out as *mut usize as *mut c_void,
            std::mem::size_of::<usize>(),
            &mut read,
        )
    };
    match ok != 0 && read == std::mem::size_of::<usize>() {
        true => Ok(out),
        false => Err(InjectError::RemoteRead(unsafe { raw::GetLastError() })),
    }
}

pub unsafe fn protect(
    process: *mut c_void,
    remote: *mut c_void,
    size: usize,
    protect: u32,
) -> Result<(), InjectError> {
    let mut old = 0u32;
    match unsafe { raw::VirtualProtectEx(process, remote, size, protect, &mut old) } {
        0 => Err(InjectError::RemoteProtect(unsafe { raw::GetLastError() })),
        _ => Ok(()),
    }
}

pub unsafe fn create_remote_thread_and_wait(
    process: *mut c_void,
    start: *mut c_void,
    param: *mut c_void,
) -> Result<(), InjectError> {
    let thread = unsafe {
        raw::CreateRemoteThread(
            process,
            std::ptr::null(),
            0,
            start,
            param,
            0,
            std::ptr::null_mut(),
        )
    };
    match thread.is_null() {
        true => Err(InjectError::RemoteThread(unsafe { raw::GetLastError() })),
        false => {
            unsafe {
                raw::WaitForSingleObject(thread, INFINITE);
                raw::CloseHandle(thread);
            }
            Ok(())
        }
    }
}

pub unsafe fn remote_call3(
    process: *mut c_void,
    function: usize,
    a0: usize,
    a1: usize,
    a2: usize,
) -> Result<usize, InjectError> {
    let block_size = 96usize;
    let result_offset = 80usize;
    let block = unsafe { alloc(process, block_size, PAGE_EXECUTE_READWRITE)? };
    let result = (block as usize + result_offset) as u64;
    let mut code = Vec::with_capacity(result_offset);
    code.extend_from_slice(&[0x48, 0xB9]);
    code.extend_from_slice(&(a0 as u64).to_le_bytes());
    code.extend_from_slice(&[0x48, 0xBA]);
    code.extend_from_slice(&(a1 as u64).to_le_bytes());
    code.extend_from_slice(&[0x49, 0xB8]);
    code.extend_from_slice(&(a2 as u64).to_le_bytes());
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&(function as u64).to_le_bytes());
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28, 0xFF, 0xD0, 0x48, 0xA3]);
    code.extend_from_slice(&result.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
    code.resize(result_offset, 0);
    unsafe {
        write(process, block, &code)?;
        create_remote_thread_and_wait(process, block, std::ptr::null_mut())?;
    }
    let out = unsafe { read_usize(process, result as *const c_void) };
    unsafe { free(process, block) };
    out
}

pub unsafe fn remote_load_library(
    process: *mut c_void,
    module: &[u8],
) -> Result<usize, InjectError> {
    let kernel32 = unsafe { raw::GetModuleHandleA(b"kernel32.dll\0".as_ptr()) };
    let load_library = unsafe { raw::GetProcAddress(kernel32, b"LoadLibraryA\0".as_ptr()) };
    match load_library.is_null() {
        true => Err(InjectError::ResolveLoadLibrary),
        false => {
            let remote_name = unsafe { remote_cstr(process, module)? };
            let out =
                unsafe { remote_call3(process, load_library as usize, remote_name as usize, 0, 0) };
            unsafe { free(process, remote_name) };
            match out? {
                0 => Err(InjectError::ManualMap(format!(
                    "LoadLibraryA({}) returned NULL",
                    String::from_utf8_lossy(module)
                ))),
                base => Ok(base),
            }
        }
    }
}

pub unsafe fn remote_get_proc_address_name(
    process: *mut c_void,
    module: usize,
    name: &[u8],
) -> Result<usize, InjectError> {
    let kernel32 = unsafe { raw::GetModuleHandleA(b"kernel32.dll\0".as_ptr()) };
    let get_proc = unsafe { raw::GetProcAddress(kernel32, b"GetProcAddress\0".as_ptr()) };
    match get_proc.is_null() {
        true => Err(InjectError::ResolveLoadLibrary),
        false => {
            let remote_name = unsafe { remote_cstr(process, name)? };
            let out = unsafe {
                remote_call3(process, get_proc as usize, module, remote_name as usize, 0)
            };
            unsafe { free(process, remote_name) };
            match out? {
                0 => Err(InjectError::ManualMap(format!(
                    "GetProcAddress({}) returned NULL",
                    String::from_utf8_lossy(name)
                ))),
                proc => Ok(proc),
            }
        }
    }
}

pub unsafe fn remote_get_proc_address_ordinal(
    process: *mut c_void,
    module: usize,
    ordinal: u16,
) -> Result<usize, InjectError> {
    let kernel32 = unsafe { raw::GetModuleHandleA(b"kernel32.dll\0".as_ptr()) };
    let get_proc = unsafe { raw::GetProcAddress(kernel32, b"GetProcAddress\0".as_ptr()) };
    match get_proc.is_null() {
        true => Err(InjectError::ResolveLoadLibrary),
        false => {
            match unsafe { remote_call3(process, get_proc as usize, module, ordinal as usize, 0)? }
            {
                0 => Err(InjectError::ManualMap(format!(
                    "GetProcAddress ordinal {ordinal} returned NULL"
                ))),
                proc => Ok(proc),
            }
        }
    }
}

unsafe fn remote_cstr(process: *mut c_void, bytes: &[u8]) -> Result<*mut c_void, InjectError> {
    let mut z = bytes.to_vec();
    z.push(0);
    let remote = unsafe { alloc(process, z.len(), PAGE_READWRITE)? };
    unsafe { write(process, remote, &z)? };
    Ok(remote)
}
