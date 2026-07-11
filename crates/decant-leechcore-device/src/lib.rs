//! LeechCore `decant` device plugin.
//!
//! Place the resulting dynamic library beside LeechCore and initialize
//! MemProcFS with `-device decant://127.0.0.1:7878`. LeechCore supplies the
//! plugin ABI shell in `leechcore_device.c`; this module owns the daemon client
//! and translates its batched physical-memory RPCs.

use std::ffi::{CStr, c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;

use decant_client::Client;
use decant_protocol::{PhysicalRead, PhysicalWrite};

const MEM_SCATTER_VERSION: u32 = 0xc0fe0002;
const MAX_RANGES_PER_RPC: usize = 2048;

#[repr(C)]
struct MemScatter {
    version: u32,
    success: u32,
    address: u64,
    buffer: *mut u8,
    length: u32,
    stack_index: u32,
    stack: [u64; 12],
}

struct DeviceState {
    client: Mutex<Client>,
    readonly: bool,
}

unsafe extern "C" {
    fn decant_lc_install(context: *mut c_void, error_info: *mut *mut c_void) -> u32;
}

fn endpoint_from_device(device: &str) -> String {
    let Some(value) = device.strip_prefix("decant://") else {
        return std::env::var("DECANT_ENDPOINT")
            .unwrap_or_else(|_| decant_client::DEFAULT_ENDPOINT.into());
    };
    let value = value.strip_prefix("endpoint=").unwrap_or(value);
    value
        .split_once(',')
        .map_or(value, |(endpoint, _)| endpoint)
        .to_string()
}

/// Entry point required by LeechCore external device plugins.
///
/// # Safety
///
/// `context` must point to a live LeechCore `LC_CONTEXT` with the version
/// checked by the C adapter. When non-null, `error_info` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn LcPluginCreate(context: *mut c_void, error_info: *mut *mut c_void) -> u32 {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        decant_lc_install(context, error_info)
    }))
    .unwrap_or(0)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn decant_device_open(
    device: *const c_char,
    max_address: *mut u64,
    readonly: *mut u32,
) -> *mut c_void {
    catch_unwind(AssertUnwindSafe(|| {
        if device.is_null() || max_address.is_null() || readonly.is_null() {
            return std::ptr::null_mut();
        }
        let device = unsafe { CStr::from_ptr(device) }.to_string_lossy();
        let endpoint = endpoint_from_device(&device);
        let mut client = Client::new(endpoint);
        if client.ping().is_err() {
            return std::ptr::null_mut();
        }
        let Ok(info) = client.physical_memory_info() else {
            return std::ptr::null_mut();
        };
        unsafe {
            *max_address = info.max_address;
            *readonly = u32::from(info.readonly);
        }
        Box::into_raw(Box::new(DeviceState {
            client: Mutex::new(client),
            readonly: info.readonly,
        }))
        .cast()
    }))
    .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
unsafe extern "C" fn decant_device_close(device: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !device.is_null() {
            drop(unsafe { Box::from_raw(device.cast::<DeviceState>()) });
        }
    }));
}

unsafe fn scatter_entries<'a>(count: u32, mems: *mut *mut c_void) -> &'a mut [*mut c_void] {
    if count == 0 || mems.is_null() {
        &mut []
    } else {
        unsafe { std::slice::from_raw_parts_mut(mems, count as usize) }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn decant_device_read_scatter(
    device: *mut c_void,
    count: u32,
    mems: *mut *mut c_void,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if device.is_null() {
            return;
        }
        let state = unsafe { &*device.cast::<DeviceState>() };
        let entries = unsafe { scatter_entries(count, mems) };
        let mut client = state.client.lock().unwrap();

        for chunk in entries.chunks_mut(MAX_RANGES_PER_RPC) {
            let mut ranges = Vec::with_capacity(chunk.len());
            let mut slots = Vec::with_capacity(chunk.len());
            for (index, slot) in chunk.iter_mut().enumerate() {
                let Some(mem) = (unsafe { slot.cast::<MemScatter>().as_mut() }) else {
                    continue;
                };
                if mem.version != MEM_SCATTER_VERSION
                    || mem.success != 0
                    || mem.address == u64::MAX
                    || mem.buffer.is_null()
                    || mem.length == 0
                    || mem.length > 0x1000
                {
                    continue;
                }
                ranges.push(PhysicalRead {
                    address: mem.address,
                    length: mem.length,
                });
                slots.push(index);
            }
            let Ok(results) = client.read_physical_scatter(ranges) else {
                continue;
            };
            for (index, result) in slots.into_iter().zip(results) {
                let mem = unsafe { &mut *chunk[index].cast::<MemScatter>() };
                let Some(data) = result.filter(|data| data.len() == mem.length as usize) else {
                    continue;
                };
                unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), mem.buffer, data.len()) };
                mem.success = 1;
            }
        }
    }));
}

#[unsafe(no_mangle)]
unsafe extern "C" fn decant_device_write_scatter(
    device: *mut c_void,
    count: u32,
    mems: *mut *mut c_void,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if device.is_null() {
            return;
        }
        let state = unsafe { &*device.cast::<DeviceState>() };
        if state.readonly {
            return;
        }
        let entries = unsafe { scatter_entries(count, mems) };
        let mut client = state.client.lock().unwrap();

        for chunk in entries.chunks_mut(MAX_RANGES_PER_RPC) {
            let mut ranges = Vec::with_capacity(chunk.len());
            let mut slots = Vec::with_capacity(chunk.len());
            for (index, slot) in chunk.iter_mut().enumerate() {
                let Some(mem) = (unsafe { slot.cast::<MemScatter>().as_mut() }) else {
                    continue;
                };
                if mem.version != MEM_SCATTER_VERSION
                    || mem.address == u64::MAX
                    || mem.buffer.is_null()
                    || mem.length == 0
                    || mem.length > 0x1000
                {
                    continue;
                }
                let data = unsafe {
                    std::slice::from_raw_parts(mem.buffer.cast_const(), mem.length as usize)
                };
                ranges.push(PhysicalWrite {
                    address: mem.address,
                    data: data.to_vec(),
                });
                slots.push(index);
            }
            let Ok(results) = client.write_physical_scatter(ranges) else {
                continue;
            };
            for (index, success) in slots.into_iter().zip(results) {
                if success {
                    let mem = unsafe { &mut *chunk[index].cast::<MemScatter>() };
                    mem.success = 1;
                }
            }
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_device_strings() {
        assert_eq!(
            endpoint_from_device("decant://10.0.0.2:7878"),
            "10.0.0.2:7878"
        );
        assert_eq!(
            endpoint_from_device("decant://endpoint=10.0.0.2:9000,cache=1"),
            "10.0.0.2:9000"
        );
    }

    #[test]
    fn scatter_layout_matches_leechcore() {
        assert_eq!(std::mem::size_of::<MemScatter>(), 128);
        assert_eq!(std::mem::align_of::<MemScatter>(), 8);
    }
}
