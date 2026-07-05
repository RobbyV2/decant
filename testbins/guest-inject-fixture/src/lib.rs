#![allow(clippy::missing_safety_doc)]

mod probe;

use core::ffi::{c_char, c_void};
use core::ptr;

use probe::{DLL_MARKER, MAGIC, PAYLOAD, Probe};

const DLL_PROCESS_ATTACH: u32 = 1;

#[unsafe(no_mangle)]
pub extern "C" fn decant_guest_inject_marker() -> u64 {
    DLL_MARKER
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetEnvironmentVariableA(name: *const c_char, buf: *mut c_char, size: u32) -> u32;
}

#[cfg(windows)]
#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_hinst: *mut c_void, reason: u32, _reserved: *mut c_void) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            attach();
        }
    }
    1
}

#[cfg(windows)]
unsafe fn attach() {
    let mut buf = [0u8; 32];
    let n = unsafe {
        GetEnvironmentVariableA(
            c"DECANT_GUEST_PROBE_ADDR".as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
        )
    };
    if n == 0 || n as usize >= buf.len() {
        return;
    }
    let Some(addr) = parse_hex(&buf[..n as usize]) else {
        return;
    };
    let probe = addr as *mut Probe;
    if probe.is_null() || !has_magic(probe) {
        return;
    }
    unsafe {
        ptr::write_volatile(ptr::addr_of_mut!((*probe).dll_marker), DLL_MARKER);
        let count = ptr::read_volatile(ptr::addr_of!((*probe).dll_count)).wrapping_add(1);
        ptr::write_volatile(ptr::addr_of_mut!((*probe).dll_count), count);
        let dst = ptr::addr_of_mut!((*probe).payload) as *mut u8;
        ptr::write_bytes(dst, 0, 32);
        ptr::copy_nonoverlapping(PAYLOAD.as_ptr(), dst, PAYLOAD.len().min(32));
    }
}

#[cfg(windows)]
fn has_magic(probe: *const Probe) -> bool {
    for (i, expected) in MAGIC.iter().enumerate() {
        let got = unsafe { ptr::read((ptr::addr_of!((*probe).magic) as *const u8).add(i)) };
        if got != *expected {
            return false;
        }
    }
    true
}

#[cfg(windows)]
fn parse_hex(bytes: &[u8]) -> Option<usize> {
    let mut out = 0usize;
    for b in bytes {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        out = out.checked_mul(16)?.checked_add(digit as usize)?;
    }
    Some(out)
}
