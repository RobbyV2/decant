//! Pointer-chain resolver.
//!
//! Convention (documented so it is unambiguous):
//! ```text
//! address = base
//! for off in offsets:
//!     address = deref_u64(address) + off
//! ```
//! i.e. `base` is dereferenced first, then each offset is added to the value and
//! the result dereferenced again — except the last offset, which is added but its
//! result is the final address (not dereferenced). With `offsets == []` the result
//! is simply `base`. Pointers are 8 bytes, little-endian (x86_64, spec rule #9).

use crate::{read_u64, Result};
use decant_backend::{MemoryBackend, Pid};

/// Resolve the chain and return the final address.
pub fn resolve(
    backend: &dyn MemoryBackend,
    pid: Pid,
    base: u64,
    offsets: &[u64],
) -> Result<u64> {
    let mut address = base;
    for &off in offsets {
        // deref then add; wrapping_add so a hostile/garbage pointer + offset can't
        // panic on overflow (it just yields an address that the next read rejects).
        address = read_u64(backend, pid, address)?.wrapping_add(off);
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use decant_backend::fixtures::{
        demo_backend, DEMO_CHAIN_HEAD, DEMO_CHAIN_NODE, DEMO_CHAIN_OFFSET, DEMO_CHAIN_VALUE,
        DEMO_TARGET_PID,
    };
    use decant_backend::{MockBackend, MockGuest, Pid};

    #[test]
    fn resolves_the_demo_chain_to_terminal_value() {
        let b = demo_backend();
        // HEAD -> NODE, then NODE + 0x10 is the terminal address.
        let addr = resolve(&b, DEMO_TARGET_PID, DEMO_CHAIN_HEAD, &[DEMO_CHAIN_OFFSET]).unwrap();
        assert_eq!(addr, DEMO_CHAIN_NODE + DEMO_CHAIN_OFFSET);
        let value = b.read(DEMO_TARGET_PID, addr, 4).unwrap();
        assert_eq!(u32::from_le_bytes(value.try_into().unwrap()), DEMO_CHAIN_VALUE);
    }

    #[test]
    fn empty_offsets_returns_base() {
        let b = demo_backend();
        assert_eq!(resolve(&b, DEMO_TARGET_PID, 0xdead, &[]).unwrap(), 0xdead);
    }

    #[test]
    fn multi_hop_chain() {
        // base -> A (deref), A+0x8 -> B (deref), B+0x4 = final.
        let base = 0x30000u64;
        let a = 0x30100u64;
        let b_node = 0x30200u64;
        let guest = MockGuest::builder()
            .process("t.exe", Pid(1))
            .region(0x30000, "rw-")
            .u64_at(base, a)
            .u64_at(a + 0x8, b_node)
            .done()
            .build();
        let back = MockBackend::new(guest);
        let addr = resolve(&back, Pid(1), base, &[0x8, 0x4]).unwrap();
        assert_eq!(addr, b_node + 0x4);
    }

    #[test]
    fn broken_link_errors_cleanly() {
        // A chain that dereferences through an unmapped pointer must error, not loop
        // or panic.
        let guest = MockGuest::builder()
            .process("t.exe", Pid(1))
            .region(0x40000, "rw-")
            .u64_at(0x40000, 0xffff_ffff_0000) // points into the void
            .done()
            .build();
        let back = MockBackend::new(guest);
        assert!(resolve(&back, Pid(1), 0x40000, &[0x0, 0x10]).is_err());
    }
}
