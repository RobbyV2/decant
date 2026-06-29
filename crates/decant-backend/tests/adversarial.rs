//! Adversarial + property tests for `MockBackend` / `MockGuest` — "the tasting".
//!
//! The mock is the keystone of Decant's offline testability, so its corner
//! behaviours need to be nailed down hard. The unit tests in `src/mock.rs` pin a
//! few concrete scenarios; here we attack the *edges* with proptest and a set of
//! targeted boundary cases:
//!
//!   * write/read round-trip over arbitrary byte payloads,
//!   * the exact off-by-one at a region's end (last byte in vs. one past),
//!   * zero-length reads,
//!   * writes to a non-writable region failing *without mutating* memory,
//!   * ASCII case-insensitive process/module lookup,
//!   * clean errors for unknown pid / module,
//!   * `memory_map` covering every planted byte,
//!   * and the documented "first matching region wins" behaviour for
//!     overlapping regions (verified empirically, not assumed).
//!
//! A note on region sizing: the builder infers a region's size from the bytes
//! written into it, rounded up to a whole page (0x1000) with a one-page minimum
//! (see `finalize_region` in mock.rs). So a region with a single planted byte at
//! its base spans exactly `[base, base + 0x1000)`. The boundary tests below lean
//! on that to know precisely where a region ends.

use decant_backend::{MemoryBackend, MockBackend, MockGuest, Pid};
use proptest::prelude::*;

const PAGE: u64 = 0x1000;

/// Build a single-process guest with one `rw-` region whose single planted byte
/// at `base` forces it to span exactly one page `[base, base + PAGE)`.
fn one_page_rw_guest(base: u64) -> MockBackend {
    let g = MockGuest::builder()
        .process("target.exe", Pid(1234))
        .region(base, "rw-")
        .bytes_at(base, &[0])
        .done()
        .build();
    MockBackend::new(g)
}

/// Randomly flip the ASCII case of each letter in `s` (non-letters untouched),
/// so a lookup with the result still has to match case-insensitively.
fn scramble_case(s: &str, flips: &[bool]) -> String {
    s.chars()
        .enumerate()
        .map(|(i, c)| {
            if flips.get(i).copied().unwrap_or(false) {
                if c.is_ascii_uppercase() {
                    c.to_ascii_lowercase()
                } else {
                    c.to_ascii_uppercase()
                }
            } else {
                c
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Property: arbitrary write into a writable region reads back identical.
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn write_then_read_roundtrips(
        // page-aligned base that leaves headroom and avoids u64 overflow.
        page in 1u64..0x1_0000_0000,
        data in prop::collection::vec(any::<u8>(), 1..=PAGE as usize),
    ) {
        let base = page * PAGE;
        let b = one_page_rw_guest(base);
        // `data` fits within the single page (len <= PAGE), written at base.
        let n = b.write(Pid(1234), base, &data).unwrap();
        prop_assert_eq!(n, data.len());
        let got = b.read(Pid(1234), base, data.len()).unwrap();
        prop_assert_eq!(got, data);
    }

    /// A read that stays strictly inside the region succeeds; the region end is a
    /// hard wall. `len` ranges over the whole in-bounds span.
    #[test]
    fn reads_inside_region_succeed(
        page in 1u64..0x1_0000_0000,
        len in 1usize..=PAGE as usize,
    ) {
        let base = page * PAGE;
        let b = one_page_rw_guest(base);
        // [base, base+len) with len <= PAGE is fully inside [base, base+PAGE).
        prop_assert!(b.read(Pid(1234), base, len).is_ok());
    }

    /// Process lookup is ASCII case-insensitive for any letter-casing of the name.
    #[test]
    fn process_lookup_is_case_insensitive(
        flips in prop::collection::vec(any::<bool>(), 0..16),
    ) {
        let name = "TaRgEt.ExE";
        let b = one_page_rw_guest(0x10_0000);
        let scrambled = scramble_case(name, &flips);
        let found = b.process_by_name(&scrambled).unwrap();
        prop_assert_eq!(found.pid, Pid(1234));
    }

    /// `memory_map` reports a region whose `[base, base+size)` covers every byte
    /// planted anywhere inside the (single) page, for arbitrary planted offsets.
    #[test]
    fn memory_map_covers_every_planted_byte(
        offsets in prop::collection::vec(0u64..PAGE, 1..32),
    ) {
        let base = 0x2000_0000u64;
        let mut builder = MockGuest::builder().process("p.exe", Pid(7)).region(base, "rw-");
        for off in &offsets {
            builder = builder.bytes_at(base + off, &[0xAB]);
        }
        let b = MockBackend::new(builder.done().build());

        let map = b.memory_map(Pid(7)).unwrap();
        prop_assert_eq!(map.len(), 1);
        let r = map[0];
        for off in &offsets {
            let addr = base + off;
            prop_assert!(addr >= r.base && addr < r.base + r.size,
                "planted addr {:#x} not covered by region [{:#x}, {:#x})",
                addr, r.base, r.base + r.size);
            // And the byte is actually readable at that address.
            prop_assert_eq!(b.read(Pid(7), addr, 1).unwrap(), vec![0xAB]);
        }
    }
}

// ---------------------------------------------------------------------------
// Targeted boundary / behaviour cases.
// ---------------------------------------------------------------------------

/// Off-by-one at the region's end: the last in-bounds byte reads, one past fails.
#[test]
fn read_off_by_one_at_region_end() {
    let base = 0x1400_0000u64;
    let b = one_page_rw_guest(base); // region is exactly [base, base + PAGE)

    // Exactly the whole region: bytes base .. base+PAGE-1, all in bounds.
    assert!(b.read(Pid(1234), base, PAGE as usize).is_ok());

    // One byte past the end: byte at base+PAGE is outside -> must fail.
    assert!(b.read(Pid(1234), base, PAGE as usize + 1).is_err());

    // Read starting on the boundary byte itself (base+PAGE) also fails.
    assert!(b.read(Pid(1234), base + PAGE, 1).is_err());

    // The last valid byte read individually succeeds.
    assert!(b.read(Pid(1234), base + PAGE - 1, 1).is_ok());
}

/// A zero-length read returns an empty buffer, not an error — even at an address
/// that would itself be out of bounds (no byte is actually touched).
#[test]
fn zero_length_read_is_empty_ok() {
    let base = 0x1400_0000u64;
    let b = one_page_rw_guest(base);

    assert_eq!(b.read(Pid(1234), base, 0).unwrap(), Vec::<u8>::new());
    // Even outside any region: zero bytes means zero addresses inspected.
    assert_eq!(b.read(Pid(1234), 0xdead_0000, 0).unwrap(), Vec::<u8>::new());
}

/// A write to a non-writable (`r-x`) region fails and leaves memory untouched.
#[test]
fn write_to_non_writable_region_fails_without_mutation() {
    let base = 0x3000u64;
    let g = MockGuest::builder()
        .process("ro.exe", Pid(1))
        .region(base, "r-x")
        .bytes_at(base, &[0xAB, 0xCD, 0xEF, 0x01])
        .done()
        .build();
    let b = MockBackend::new(g);

    let before = b.read(Pid(1), base, 4).unwrap();
    assert_eq!(before, vec![0xAB, 0xCD, 0xEF, 0x01]);

    // r-x is readable but not writable: the write must be refused.
    assert!(b.write(Pid(1), base, &[0xFF, 0xFF, 0xFF, 0xFF]).is_err());

    // ...and nothing changed.
    let after = b.read(Pid(1), base, 4).unwrap();
    assert_eq!(after, before);
}

/// Module lookup is ASCII case-insensitive, mirroring the process case.
#[test]
fn module_lookup_is_case_insensitive() {
    let g = MockGuest::builder()
        .process("p.exe", Pid(2))
        .module("Ntdll.DLL", 0x1400000000, 0x1000)
        .done()
        .build();
    let b = MockBackend::new(g);

    assert_eq!(b.module_by_name(Pid(2), "ntdll.dll").unwrap().base, 0x1400000000);
    assert_eq!(b.module_by_name(Pid(2), "NTDLL.DLL").unwrap().base, 0x1400000000);
    assert_eq!(b.module_by_name(Pid(2), "nTdLl.DlL").unwrap().base, 0x1400000000);
}

/// Unknown pid and unknown module both error cleanly (no panic, no silent empty).
#[test]
fn unknown_pid_and_module_error_cleanly() {
    let b = one_page_rw_guest(0x10_0000);

    // Wrong pid across every pid-taking method.
    assert!(b.process_by_pid(Pid(9999)).is_err());
    assert!(b.module_list(Pid(9999)).is_err());
    assert!(b.module_by_name(Pid(9999), "whatever.dll").is_err());
    assert!(b.module_exports(Pid(9999), "whatever.dll").is_err());
    assert!(b.read(Pid(9999), 0x10_0000, 4).is_err());
    assert!(b.write(Pid(9999), 0x10_0000, &[0]).is_err());
    assert!(b.memory_map(Pid(9999)).is_err());

    // Right pid, but a module that isn't loaded.
    assert!(b.module_by_name(Pid(1234), "nope.dll").is_err());
    assert!(b.module_exports(Pid(1234), "nope.dll").is_err());

    // Unknown name lookup also errors rather than returning something wrong.
    assert!(b.process_by_name("does-not-exist.exe").is_err());
}

/// Overlapping regions: `region_at` returns the *first declared* matching region
/// (`Vec::iter().find`), so the first region's permissions shadow any later one
/// covering the same address. We verify the actual behaviour rather than assume
/// it: a read-only region declared *before* a writable region at the same base
/// makes writes to the overlap fail, while reads still succeed.
#[test]
fn overlapping_regions_first_declared_wins() {
    let base = 0x4000_0000u64;
    let g = MockGuest::builder()
        .process("ov.exe", Pid(3))
        // Declared FIRST: read-only. This one wins for addresses in the overlap.
        .region(base, "r--")
        .bytes_at(base, &[0x11])
        // Declared SECOND: writable, same base/extent. Shadowed by the r-- above.
        .region(base, "rw-")
        .bytes_at(base, &[0x22])
        .done()
        .build();
    let b = MockBackend::new(g);

    // Both regions are reported in the map (two distinct entries, same base).
    let map = b.memory_map(Pid(3)).unwrap();
    assert_eq!(map.len(), 2);
    assert!(map.iter().all(|r| r.base == base));

    // The first (r--) region wins: it is readable...
    assert!(b.read(Pid(3), base, 1).is_ok());
    // ...but NOT writable, so the write is refused even though a writable region
    // also covers this address.
    assert!(b.write(Pid(3), base, &[0xFF]).is_err());
}

/// Adjacent (touching, non-overlapping) readable regions: a read may span the
/// shared boundary because `read` checks each byte's region independently, and
/// every byte falls in *some* readable region. This documents that contiguous
/// readable regions behave as one for reads, in contrast to the hard wall at a
/// region's outer edge (see `read_off_by_one_at_region_end`).
#[test]
fn adjacent_readable_regions_allow_a_read_across_the_seam() {
    let base = 0x5000_0000u64;
    let g = MockGuest::builder()
        .process("adj.exe", Pid(5))
        .region(base, "rw-")
        .bytes_at(base, &[0xA0])
        .region(base + PAGE, "rw-")
        .bytes_at(base + PAGE, &[0xB0])
        .done()
        .build();
    let b = MockBackend::new(g);

    // One byte into the second region (base+PAGE) is still in a readable region,
    // so a read of PAGE+1 bytes starting at base succeeds across the seam.
    let got = b.read(Pid(5), base, PAGE as usize + 1).unwrap();
    assert_eq!(got.len(), PAGE as usize + 1);
    assert_eq!(got[0], 0xA0);
    assert_eq!(got[PAGE as usize], 0xB0);

    // But reading one byte past the END of the second region still fails.
    assert!(b.read(Pid(5), base, 2 * PAGE as usize + 1).is_err());
}
