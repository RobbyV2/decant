//! # mock-cheat (Phase 3) — runs UNDER WINE
//!
//! A stand-in for an unmodified Cheat-Engine-style tool: opens the guest target
//! by pid, `ReadProcessMemory`s the magic, `WriteProcessMemory`s the slot, walks
//! a pointer chain, and enumerates processes/modules — all through the interposer,
//! printing results for assertion by `decant-wine-harness` (spec §Phase 3).
//!
//! Phase 0 stub so the cross-compile target is wired.

fn main() {
    println!("mock-cheat: not implemented yet (Phase 3).");
}
