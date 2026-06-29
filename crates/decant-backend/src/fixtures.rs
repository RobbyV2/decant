//! Deterministic demo guest shared by the daemon's `--backend mock`, the CLI
//! integration tests, and (later) the Phase 2 scanner/resolver offline tests.
//!
//! Keeping one canonical fake guest in the library means every layer asserts
//! against the *same* scripted memory — the daemon serves it, a test drives the
//! CLI against the daemon, and both agree on exact byte values without copy-paste.

use crate::{MockBackend, MockGuest, Pid};

/// A unique 16-byte signature planted in the demo guest, findable by the Phase 2
/// AOB scanner without knowing its address. Chosen to be improbable in real data.
pub const DEMO_MAGIC: [u8; 16] = *b"DECANT::MAGIC\x00\xDE\xAD";

/// pid of the demo target process.
pub const DEMO_TARGET_PID: Pid = Pid(1234);
/// Base of the demo target's main module (`decant-target.exe`).
pub const DEMO_MODULE_BASE: u64 = 0x0001_4000_0000;
/// Absolute address of the planted [`DEMO_MAGIC`] header.
pub const DEMO_MAGIC_ADDR: u64 = 0x0001_4001_0100;
/// Pointer-chain head: holds a pointer to [`DEMO_CHAIN_NODE`].
pub const DEMO_CHAIN_HEAD: u64 = 0x0001_4001_0200;
/// Second node the head points at. `DEMO_CHAIN_NODE + 0x10` holds the terminal u32.
pub const DEMO_CHAIN_NODE: u64 = 0x0001_4001_0280;
/// Offset from [`DEMO_CHAIN_NODE`] to the terminal value.
pub const DEMO_CHAIN_OFFSET: u64 = 0x10;
/// The terminal value reached by resolving head -> node + offset.
pub const DEMO_CHAIN_VALUE: u32 = 1337;
/// A zeroed 8-byte writable slot. Write here and read it back to prove writes land
/// (the offline analogue of the Phase 1 live write gate).
pub const DEMO_SLOT_ADDR: u64 = 0x0001_4001_0400;

/// Build the canonical demo [`MockGuest`].
///
/// Layout (process `decant-target.exe`, pid 1234):
/// * module `decant-target.exe` @ `DEMO_MODULE_BASE`, plus a `kernel32.dll` module
///   with two exports so `module_exports` has something to return.
/// * one `rw-` region holding the magic header, a 2-hop pointer chain
///   (`HEAD -> NODE`, then `NODE + 0x10 -> 1337`), and a writable slot.
///
/// Plus a bare `explorer.exe` (pid 4) so process enumeration returns more than one.
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

/// The demo guest wrapped in a ready-to-serve [`MockBackend`].
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
        // Two processes, target findable by name and pid.
        assert_eq!(b.list_processes().unwrap().len(), 2);
        assert_eq!(b.process_by_name("decant-target.exe").unwrap().pid, DEMO_TARGET_PID);

        // Magic reads back exactly.
        assert_eq!(b.read(DEMO_TARGET_PID, DEMO_MAGIC_ADDR, 16).unwrap(), DEMO_MAGIC);

        // Pointer chain resolves head -> node + offset -> terminal value.
        let head = b.read(DEMO_TARGET_PID, DEMO_CHAIN_HEAD, 8).unwrap();
        let node = u64::from_le_bytes(head.try_into().unwrap());
        assert_eq!(node, DEMO_CHAIN_NODE);
        let term = b.read(DEMO_TARGET_PID, node + DEMO_CHAIN_OFFSET, 4).unwrap();
        assert_eq!(u32::from_le_bytes(term.try_into().unwrap()), DEMO_CHAIN_VALUE);

        // Writable slot round-trips.
        b.write(DEMO_TARGET_PID, DEMO_SLOT_ADDR, &[9, 8, 7, 6, 5, 4, 3, 2]).unwrap();
        assert_eq!(
            b.read(DEMO_TARGET_PID, DEMO_SLOT_ADDR, 8).unwrap(),
            vec![9, 8, 7, 6, 5, 4, 3, 2]
        );

        // Module exports present.
        let ex = b.module_exports(DEMO_TARGET_PID, "kernel32.dll").unwrap();
        assert_eq!(ex.len(), 2);
    }
}
