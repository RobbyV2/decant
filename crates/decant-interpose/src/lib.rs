//! Windows interposer DLL support code and host-testable handle table.

#![allow(clippy::missing_safety_doc)]

pub mod handle_table;
pub mod rpc;

#[cfg(windows)]
mod hooks;
#[cfg(windows)]
mod iat;
#[cfg(windows)]
mod module_hooks;
#[cfg(windows)]
mod originals;
#[cfg(windows)]
mod process_hooks;

#[cfg(windows)]
mod platform {
    use core::ffi::c_void;

    const DLL_PROCESS_ATTACH: u32 = 1;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetEnvironmentVariableA(name: *const u8, buf: *mut u8, size: u32) -> u32;
        fn OpenEventA(desired_access: u32, inherit: i32, name: *const u8) -> *mut c_void;
        fn SetEvent(handle: *mut c_void) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    const EVENT_MODIFY_STATE: u32 = 0x0002;

    pub unsafe fn install_hooks() -> u32 {
        unsafe { crate::hooks::install_all() }
    }

    fn read_env(name: *const u8, buf: &mut [u8]) -> usize {
        unsafe { GetEnvironmentVariableA(name, buf.as_mut_ptr(), buf.len() as u32) as usize }
    }

    // Open the harness's named event and set it, reporting that hooks are live.
    // Runs under loader lock, so it only touches kernel32 and a stack buffer.
    fn signal_ready() {
        let mut name = [0u8; 128];
        let n = read_env(b"DECANT_READY_EVENT\0".as_ptr(), &mut name);
        if n == 0 || n >= name.len() {
            return;
        }
        unsafe {
            let h = OpenEventA(EVENT_MODIFY_STATE, 0, name.as_ptr());
            if !h.is_null() {
                SetEvent(h);
                CloseHandle(h);
            }
        }
    }

    // Test fault: skip hook install and the ready signal so the harness times out.
    fn fault_nohooks() -> bool {
        let mut buf = [0u8; 16];
        let n = read_env(b"DECANT_FAULT\0".as_ptr(), &mut buf);
        n >= 7 && &buf[..7] == b"nohooks"
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn decant_install_hooks() -> i32 {
        unsafe { install_hooks() as i32 }
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn DllMain(
        _hinst: *mut c_void,
        reason: u32,
        _reserved: *mut c_void,
    ) -> i32 {
        if reason == DLL_PROCESS_ATTACH && autohook_enabled() {
            if fault_nohooks() {
                return 1;
            }
            unsafe {
                let _ = install_hooks();
            }
            signal_ready();
        }
        1
    }

    fn autohook_enabled() -> bool {
        let mut buf = [0u8; 8];
        let n = unsafe {
            GetEnvironmentVariableA(
                b"DECANT_AUTOHOOK\0".as_ptr(),
                buf.as_mut_ptr(),
                buf.len() as u32,
            )
        };
        n >= 1 && buf[0] == b'1'
    }
}
