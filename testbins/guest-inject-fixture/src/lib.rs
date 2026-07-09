//! Manifest crate for the tracked guest-injection fixture.
//!
//! `xtask guest-inject-fixture` builds both the CRT-free C fixture artifacts and
//! this Rust cdylib payload for `x86_64-pc-windows-gnu`.

pub const MAGIC_AOB: &str = "44 45 43 41 4E 54 3A 3A 47 55 45 53 54 49 4E 4A";
pub const FIXTURE_VERSION_AOB: &str = "44 45 43 41 4E 54 3A 3A 47 49 4E 4A 30 30 30 37";
pub const STUB_AOB: &str = "44 45 43 41 4E 54 3A 3A 53 54 55 42 30 30 30 34";
pub const RESULT_AOB: &str = "44 45 43 41 4E 54 3A 3A 52 45 53 55 4C 54 30 34";
pub const DLL_MARKER: u64 = 0xD11D_ECA7_600D_5107;

#[cfg(all(windows, target_arch = "x86_64"))]
mod windows_payload {
    use std::ffi::c_void;

    use super::DLL_MARKER;

    const DLL_PROCESS_ATTACH: u32 = 1;
    const MAGIC: [u8; 16] = *b"DECANT::GUESTINJ";
    const PAYLOAD: &[u8] = b"decant rust dll loaded";

    #[repr(C)]
    struct DecantProbe {
        magic: [u8; 16],
        tick: u64,
        dll_marker: u64,
        dll_count: u64,
        payload: [u8; 32],
    }

    unsafe extern "system" {
        fn GetEnvironmentVariableA(name: *const u8, buffer: *mut u8, size: u32) -> u32;
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn decant_guest_rust_marker() -> u64 {
        DLL_MARKER
    }

    #[used]
    #[unsafe(no_mangle)]
    pub static DECANT_GUEST_RUST_RELOC_ANCHOR: extern "system" fn() -> u64 =
        decant_guest_rust_marker;

    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn DllMain(
        _module: *mut c_void,
        reason: u32,
        _reserved: *mut c_void,
    ) -> i32 {
        if reason == DLL_PROCESS_ATTACH {
            unsafe { attach() };
        }
        1
    }

    unsafe fn attach() {
        let mut env = [0u8; 32];
        let n = unsafe {
            GetEnvironmentVariableA(
                c"DECANT_GUEST_PROBE_ADDR".as_ptr().cast(),
                env.as_mut_ptr(),
                env.len() as u32,
            )
        };
        if n != 16 {
            return;
        }
        let Some(addr) = parse_hex64(&env[..16]) else {
            return;
        };
        if addr == 0 {
            return;
        }
        let probe = addr as *mut DecantProbe;
        let ok = unsafe { (*probe).magic == MAGIC };
        if !ok {
            return;
        }
        unsafe {
            (*probe).dll_marker = DLL_MARKER;
            (*probe).dll_count = (*probe).dll_count.wrapping_add(1);
            for (idx, dst) in (*probe).payload.iter_mut().enumerate() {
                *dst = PAYLOAD.get(idx).copied().unwrap_or(0);
            }
        }
    }

    fn parse_hex64(bytes: &[u8]) -> Option<u64> {
        let mut out = 0u64;
        for &b in bytes {
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return None,
            };
            out = (out << 4) | u64::from(digit);
        }
        Some(out)
    }
}
