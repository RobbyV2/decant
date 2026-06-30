use crate::{Result, read_u64};
use decant_backend::{MemoryBackend, Pid};

pub fn resolve(backend: &dyn MemoryBackend, pid: Pid, base: u64, offsets: &[u64]) -> Result<u64> {
    let mut address = base;
    for &off in offsets {
        // wrapping_add so a garbage pointer + offset cannot panic on overflow
        address = read_u64(backend, pid, address)?.wrapping_add(off);
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use decant_backend::fixtures::{
        DEMO_CHAIN_HEAD, DEMO_CHAIN_NODE, DEMO_CHAIN_OFFSET, DEMO_CHAIN_VALUE, DEMO_TARGET_PID,
        demo_backend,
    };
    use decant_backend::{MockBackend, MockGuest, Pid};

    #[test]
    fn resolves_the_demo_chain_to_terminal_value() {
        let b = demo_backend();
        let addr = resolve(&b, DEMO_TARGET_PID, DEMO_CHAIN_HEAD, &[DEMO_CHAIN_OFFSET]).unwrap();
        assert_eq!(addr, DEMO_CHAIN_NODE + DEMO_CHAIN_OFFSET);
        let value = b.read(DEMO_TARGET_PID, addr, 4).unwrap();
        assert_eq!(
            u32::from_le_bytes(value.try_into().unwrap()),
            DEMO_CHAIN_VALUE
        );
    }

    #[test]
    fn empty_offsets_returns_base() {
        let b = demo_backend();
        assert_eq!(resolve(&b, DEMO_TARGET_PID, 0xdead, &[]).unwrap(), 0xdead);
    }

    #[test]
    fn multi_hop_chain() {
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
        let guest = MockGuest::builder()
            .process("t.exe", Pid(1))
            .region(0x40000, "rw-")
            .u64_at(0x40000, 0xffff_ffff_0000)
            .done()
            .build();
        let back = MockBackend::new(guest);
        assert!(resolve(&back, Pid(1), 0x40000, &[0x0, 0x10]).is_err());
    }
}
