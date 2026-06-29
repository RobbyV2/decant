#![allow(clippy::missing_safety_doc)]

pub mod handle_table;
pub mod rpc;

#[cfg(windows)]
mod hooks;
#[cfg(windows)]
mod iat;
#[cfg(windows)]
mod originals;

#[cfg(windows)]
mod platform {
    use core::ffi::c_void;

    const DLL_PROCESS_ATTACH: u32 = 1;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetEnvironmentVariableA(name: *const u8, buf: *mut u8, size: u32) -> u32;
    }

    pub unsafe fn install_hooks() -> u32 {
        crate::hooks::install_all()
    }

    #[no_mangle]
    pub extern "system" fn decant_install_hooks() -> i32 {
        unsafe { install_hooks() as i32 }
    }

    #[no_mangle]
    pub extern "system" fn DllMain(_hinst: *mut c_void, reason: u32, _reserved: *mut c_void) -> i32 {
        if reason == DLL_PROCESS_ATTACH && autohook_enabled() {
            unsafe {
                let _ = install_hooks();
            }
        }
        1
    }

    fn autohook_enabled() -> bool {
        let mut buf = [0u8; 8];
        let n = unsafe {
            GetEnvironmentVariableA(b"DECANT_AUTOHOOK\0".as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
        };
        n >= 1 && buf[0] == b'1'
    }
}
