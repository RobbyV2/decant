use crate::{MockBackend, MockGuest, Pid};

pub const DEMO_MAGIC: [u8; 16] = *b"DECANT::MAGIC\x00\xDE\xAD";

pub const DEMO_TARGET_PID: Pid = Pid(1234);
pub const DEMO_MODULE_BASE: u64 = 0x0001_4000_0000;
pub const DEMO_MAGIC_ADDR: u64 = 0x0001_4001_0100;
pub const DEMO_CHAIN_HEAD: u64 = 0x0001_4001_0200;
pub const DEMO_CHAIN_NODE: u64 = 0x0001_4001_0280;
pub const DEMO_CHAIN_OFFSET: u64 = 0x10;
pub const DEMO_CHAIN_VALUE: u32 = 1337;
pub const DEMO_SLOT_ADDR: u64 = 0x0001_4001_0400;

pub fn demo_guest() -> MockGuest {
    MockGuest::builder()
        .process("decant-target.exe", DEMO_TARGET_PID)
        .module("decant-target.exe", DEMO_MODULE_BASE, 0x40000)
        .module("kernel32.dll", 0x0007_FFE0_0000, 0xC0000)
        .export("kernel32.dll", "ReadProcessMemory", 0x0007_FFE0_1000)
        .export("kernel32.dll", "WriteProcessMemory", 0x0007_FFE0_2000)
        .region(0x0001_4001_0000, "rw-")
        .bytes_at(DEMO_MAGIC_ADDR, &DEMO_MAGIC)
        .u64_at(DEMO_CHAIN_HEAD, DEMO_CHAIN_NODE)
        .u32_at(DEMO_CHAIN_NODE + DEMO_CHAIN_OFFSET, DEMO_CHAIN_VALUE)
        .bytes_at(DEMO_SLOT_ADDR, &[0u8; 8])
        .done()
        .process("explorer.exe", Pid(4))
        .done()
        .build()
}

pub fn demo_backend() -> MockBackend {
    MockBackend::new(demo_guest())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryBackend;

    #[test]
    fn demo_guest_is_internally_consistent() {
        let b = demo_backend();
        assert_eq!(b.list_processes().unwrap().len(), 2);
        assert_eq!(
            b.process_by_name("decant-target.exe").unwrap().pid,
            DEMO_TARGET_PID
        );

        assert_eq!(
            b.read(DEMO_TARGET_PID, DEMO_MAGIC_ADDR, 16).unwrap(),
            DEMO_MAGIC
        );

        let head = b.read(DEMO_TARGET_PID, DEMO_CHAIN_HEAD, 8).unwrap();
        let node = u64::from_le_bytes(head.try_into().unwrap());
        assert_eq!(node, DEMO_CHAIN_NODE);
        let term = b
            .read(DEMO_TARGET_PID, node + DEMO_CHAIN_OFFSET, 4)
            .unwrap();
        assert_eq!(
            u32::from_le_bytes(term.try_into().unwrap()),
            DEMO_CHAIN_VALUE
        );

        b.write(DEMO_TARGET_PID, DEMO_SLOT_ADDR, &[9, 8, 7, 6, 5, 4, 3, 2])
            .unwrap();
        assert_eq!(
            b.read(DEMO_TARGET_PID, DEMO_SLOT_ADDR, 8).unwrap(),
            vec![9, 8, 7, 6, 5, 4, 3, 2]
        );

        let ex = b.module_exports(DEMO_TARGET_PID, "kernel32.dll").unwrap();
        assert_eq!(ex.len(), 2);
    }
}
