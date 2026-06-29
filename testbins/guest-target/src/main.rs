//! # guest-target (Phase 2) — runs INSIDE the VM
//!
//! Allocates a struct holding: a unique magic AOB header (findable by the scanner
//! without knowing the address), a counter incremented ~every second (proves reads
//! see live state), and a writable "slot" (proves writes land). Prints its struct
//! address + magic for human confirmation. The automated assertion is host-side
//! (daemon writes the slot, reads it back changed), so this binary needs no I/O
//! channel of its own (spec §Phase 2).
//!
//! Phase 0 stub so the cross-compile target is wired.

fn main() {
    println!("guest-target: not implemented yet (Phase 2).");
}
