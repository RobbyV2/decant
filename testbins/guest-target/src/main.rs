//! # guest-target (Phase 2) — runs INSIDE the Windows VM
//!
//! A tiny, self-verifying memory target for the Phase 2 **live gate**. It exists so
//! the rest of the pipeline (memflow backend -> daemon -> CLI scanner/resolver) can
//! be exercised against a *real* Windows process whose layout we control, instead of
//! the offline `MockGuest`. It is the live analogue of `decant_backend::fixtures`.
//!
//! ## What it plants in memory
//!
//! One heap-allocated [`Target`] struct, leaked so it stays resident at a stable
//! address for the lifetime of the process. Laid out contiguously (`#[repr(C)]`):
//!
//! | field     | type      | purpose                                                  |
//! |-----------|-----------|----------------------------------------------------------|
//! | `magic`   | `[u8; 16]`| unique AOB header — lets the scanner *find* the struct   |
//! |           |           | without being told its address                           |
//! | `counter` | `u64`     | bumped ~once a second — proves a reader sees *live* state |
//! | `slot`    | `u64`     | host-writable cell, starts 0 — proves writes *land*      |
//!
//! ## How it's used during the live gate
//!
//! 1. Run this binary inside the VM. It prints the struct/counter/slot addresses and
//!    the [`MAGIC`] header as a space-separated hex AOB string.
//! 2. Find it from the host without prior knowledge of the address:
//!    `decant-cli scan <PID> "<that magic string>"` — the match points at the struct
//!    base; `+0x10` is the counter, `+0x18` is the slot.
//! 3. Read the counter twice ~a second apart: it must have changed (live reads work).
//! 4. **The actual automated assertion is host-side**: the daemon writes [`SENTINEL`]
//!    into the slot and reads it back to confirm the write took. This binary's only
//!    job there is to keep the memory resident and mutating; the lines it prints
//!    (including "slot hit") are for *human eyes* watching the console during the
//!    gate, not the pass/fail signal.
//!
//! std-only, no dependencies — it must cross-compile cleanly for
//! `x86_64-pc-windows-gnu` without pulling anything into the lockfile.

use std::io::Write;
use std::ptr;
use std::thread;
use std::time::Duration;

/// Unique 16-byte signature planted at the head of [`Target`]. Chosen to be
/// improbable in real process memory so an AOB scan for it yields exactly one hit.
/// This is the byte string the human pastes (in hex) into `decant-cli scan`.
///
/// Sibling of `decant_backend::fixtures::DEMO_MAGIC`, but deliberately a *different*
/// 16 bytes so an offline-vs-live mix-up can't accidentally match.
const MAGIC: [u8; 16] = *b"DECANT::LIVE\x00\xCA\xFE\x55";

/// The value the host daemon writes into [`Target::slot`] to prove a write landed.
/// When the loop observes the slot holding this, it prints a confirmation line for
/// the human. Distinctive so it can't be confused with the zero-initialised slot.
const SENTINEL: u64 = 0xDECA_F1ED_5107_C0DE;

/// The resident target struct. `#[repr(C)]` pins the field order and offsets so the
/// host knows the counter is at `base + 0x10` and the slot at `base + 0x18`
/// (16-byte magic, then two 8-byte-aligned `u64`s).
#[repr(C)]
struct Target {
    /// AOB header the scanner searches for.
    magic: [u8; 16],
    /// Monotonic heartbeat, bumped each loop iteration.
    counter: u64,
    /// Zeroed cell the host writes [`SENTINEL`] into.
    slot: u64,
}

/// Render bytes as an uppercase, space-separated hex AOB string,
/// e.g. `[0x44, 0x45]` -> `"44 45"`. This is exactly the format
/// `decant_core::Pattern::parse` accepts, so the output is paste-ready.
fn aob_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn main() {
    // Allocate the struct on the heap and *leak* it: we hand the allocation to
    // `mem::forget` so its destructor never runs and the backing memory is never
    // freed. That keeps `magic`/`counter`/`slot` at one fixed address for the whole
    // run, which is what the scanner and resolver need to lock onto.
    let mut boxed = Box::new(Target {
        magic: MAGIC,
        counter: 0,
        slot: 0,
    });

    // Grab a raw pointer to the leaked struct *before* forgetting the Box (after
    // `forget` we no longer hold a reference, but the pointer stays valid because the
    // memory is never reclaimed). We address the individual fields through this so we
    // don't depend on a particular `offset_of!` macro version.
    let target: *mut Target = &mut *boxed;
    let base = target as u64;
    // SAFETY: `target` points at a live, leaked, properly-aligned `Target`.
    let counter_ptr: *mut u64 = unsafe { ptr::addr_of_mut!((*target).counter) };
    let slot_ptr: *mut u64 = unsafe { ptr::addr_of_mut!((*target).slot) };
    let counter_addr = counter_ptr as u64;
    let slot_addr = slot_ptr as u64;

    // Leak it. From here on the only handle to the struct is the raw pointer above.
    std::mem::forget(boxed);

    // Print the coordinates a human needs to drive the live gate from the host.
    println!("guest-target: resident self-verifying target is live.");
    println!("  struct base : 0x{base:016X}");
    println!("  counter @   : 0x{counter_addr:016X}  (base + 0x10, u64, increments ~1/s)");
    println!("  slot    @   : 0x{slot_addr:016X}  (base + 0x18, u64, host writes here)");
    println!("  sentinel    : 0x{SENTINEL:016X}  (value the host writes to prove a write landed)");
    println!();
    println!("  magic AOB   : {}", aob_string(&MAGIC));
    println!("  find me with : decant-cli scan <PID> \"{}\"", aob_string(&MAGIC));
    println!();
    let _ = std::io::stdout().flush();

    // Heartbeat loop. Never returns — the process stays alive (and the memory stays
    // resident) until killed from outside.
    loop {
        // Bump the counter. Volatile read-modify-write so the compiler can't fold the
        // increment away or cache the value: a daemon reading `counter` twice a second
        // apart must observe two different numbers.
        //
        // SAFETY: `counter_ptr`/`slot_ptr` point into the leaked, still-live struct.
        unsafe {
            let next = ptr::read_volatile(counter_ptr).wrapping_add(1);
            ptr::write_volatile(counter_ptr, next);

            // Check whether the host has written the sentinel into the slot. Volatile
            // because the slot is mutated by *another process* (the daemon), so the
            // compiler must actually re-read memory every iteration.
            let slot = ptr::read_volatile(slot_ptr);
            if slot == SENTINEL {
                // Human-facing confirmation only — the real pass/fail check is the
                // host reading the slot back after its write. See the module docs.
                println!("slot hit: sentinel observed (slot = 0x{slot:016X})");
            }
        }

        // Flush every iteration so a human tailing stdout sees progress promptly even
        // if the console is block-buffered.
        let _ = std::io::stdout().flush();
        thread::sleep(Duration::from_secs(1));
    }
}
