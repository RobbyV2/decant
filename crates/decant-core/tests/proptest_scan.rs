//! Adversarial property tests for the AOB **scanner** (`decant_core::scanner`).
//!
//! The unit tests in `src/scanner.rs` pin a handful of concrete cases. These tests
//! instead hammer the whole input space with proptest and check the scanner against
//! an independent, dead-simple reference implementation. The properties are chosen
//! to catch the classes of bug that are easy to introduce in a chunked scanner:
//!
//!   1. **Reference-oracle.** Over a random region, `scanner::scan` must return
//!      *exactly* the offsets a naive byte-by-byte slide finds (wildcards match
//!      anything), mapped to absolute addresses. This is the core correctness
//!      invariant — it catches off-by-one, missed matches, and false positives.
//!   2. **Chunk invariance.** The chunk size is purely an internal memory knob; it
//!      must never change the *result*. We scan the same guest at many chunk sizes
//!      (including 1, which forces a window per byte) and assert identical ascending
//!      hits. This is the property that catches overlap/dedup bugs at chunk seams.
//!   3. **Robustness.** Arbitrary printable-ASCII strings fed to `Pattern::parse`
//!      must only ever return `Ok`/`Err`, never panic; and scanning a guest with no
//!      readable region is an empty `Ok`.
//!   4. **Multi-region.** With the pattern planted in two disjoint regions, the
//!      scanner returns the hits from *both*, ascending, with nothing invented in
//!      the unmapped gap between them.
//!
//! ## Why the oracle pads to a page
//!
//! `MockGuest` infers a region's size from the highest written byte, rounded up to
//! a 0x1000 page (min one page). So a region holding `data` actually presents
//! `data` followed by zero-fill out to the page boundary, and the scanner sees all
//! of it. The oracle therefore searches that same page-padded byte image (see
//! [`region_image`]) rather than `data` alone — otherwise a pattern that happens to
//! match inside the zero padding would look like a (spurious) scanner "false
//! positive" when it is in fact a real, readable match.

use decant_core::scanner::{scan, scan_with_chunk};
use decant_core::Pattern;
use decant_backend::{MockBackend, MockGuest, Pid};
use proptest::prelude::*;

const PAGE: usize = 0x1000;

// ---------------------------------------------------------------------------
// Reference helpers (deliberately trivial — the whole point is that they are
// obviously correct, so any disagreement indicts the scanner, not the oracle).
// ---------------------------------------------------------------------------

/// The exact byte image a `MockGuest` presents for a region whose only content is
/// `data` written at the region base: `data` then zero-fill up to a whole page
/// (minimum one page). This mirrors `mock.rs`'s size inference.
fn region_image(data: &[u8]) -> Vec<u8> {
    let size = data.len().div_ceil(PAGE).max(1) * PAGE;
    let mut img = vec![0u8; size];
    img[..data.len()].copy_from_slice(data);
    img
}

/// Naive overlapping pattern search: slide the pattern over `hay`, a `None` entry
/// matches any byte. Returns every start offset, ascending.
fn naive_find(hay: &[u8], pat: &[Option<u8>]) -> Vec<usize> {
    let plen = pat.len();
    if plen == 0 || hay.len() < plen {
        return Vec::new();
    }
    (0..=hay.len() - plen)
        .filter(|&i| {
            pat.iter()
                .zip(&hay[i..i + plen])
                .all(|(p, &h)| match p {
                    Some(b) => *b == h,
                    None => true,
                })
        })
        .collect()
}

/// Render a `Vec<Option<u8>>` pattern as the textual AOB form `Pattern::parse`
/// consumes (`"4D ?? 00 ..."`), so the test exercises the real public parse path
/// rather than reaching into private fields.
fn pattern_string(pat: &[Option<u8>]) -> String {
    pat.iter()
        .map(|b| match b {
            Some(v) => format!("{v:02X}"),
            None => "??".to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// Strategies.
// ---------------------------------------------------------------------------

/// Generate a random data buffer (1..4096 bytes) together with a pattern *derived
/// from that buffer* so real matches occur: pick a random window of the data
/// (length 1..=16), then randomly turn some positions into `??` wildcards. The
/// pattern is returned as `Vec<Option<u8>>` (the oracle's view); the test renders
/// it to text for `Pattern::parse`.
fn arb_data_and_pattern() -> impl Strategy<Value = (Vec<u8>, Vec<Option<u8>>)> {
    prop::collection::vec(any::<u8>(), 1..4096)
        .prop_flat_map(|data| {
            let max_plen = data.len().min(16);
            (Just(data), 1usize..=max_plen)
        })
        .prop_flat_map(|(data, plen)| {
            let start_max = data.len() - plen;
            (
                Just(data),
                Just(plen),
                0usize..=start_max,
                prop::collection::vec(any::<bool>(), plen),
            )
        })
        .prop_map(|(data, plen, start, wildcard)| {
            let pat = (0..plen)
                .map(|i| if wildcard[i] { None } else { Some(data[start + i]) })
                .collect();
            (data, pat)
        })
}

/// A page-aligned, non-null region base in `[0x1000, 0x1_0000_0000)`.
fn arb_base() -> impl Strategy<Value = u64> {
    (1u64..0x10_0000).prop_map(|page| page * PAGE as u64)
}

/// Build a one-region rw- guest holding `data` at `base`, pid 1.
fn guest_with(base: u64, data: &[u8]) -> MockBackend {
    let guest = MockGuest::builder()
        .process("t.exe", Pid(1))
        .region(base, "rw-")
        .bytes_at(base, data)
        .done()
        .build();
    MockBackend::new(guest)
}

// ---------------------------------------------------------------------------
// Properties.
// ---------------------------------------------------------------------------

proptest! {
    /// CORE INVARIANT. The scanner's absolute hit list equals the naive oracle's
    /// offsets (searched over the page-padded region image) mapped to `base + off`.
    #[test]
    fn scan_equals_naive_oracle((data, pat) in arb_data_and_pattern(), base in arb_base()) {
        let backend = guest_with(base, &data);
        let pattern = Pattern::parse(&pattern_string(&pat)).unwrap();

        let got = scan(&backend, Pid(1), &pattern).unwrap();

        let expected: Vec<u64> = naive_find(&region_image(&data), &pat)
            .into_iter()
            .map(|off| base + off as u64)
            .collect();

        prop_assert_eq!(got, expected);
    }

    /// CHUNK INVARIANCE. For one fixed guest+pattern, every chunk size yields the
    /// identical ascending, duplicate-free hit list. Chunk 1 forces a fresh window
    /// per byte (maximum overlap churn); 4096 covers the whole region in one shot.
    #[test]
    fn scan_is_chunk_invariant((data, pat) in arb_data_and_pattern(), base in arb_base()) {
        let backend = guest_with(base, &data);
        let pattern = Pattern::parse(&pattern_string(&pat)).unwrap();

        let mut reference: Option<Vec<u64>> = None;
        for chunk in [1usize, 2, 3, 5, 8, 13, 64, 4096] {
            let hits = scan_with_chunk(&backend, Pid(1), &pattern, chunk).unwrap();

            // Strictly ascending => sorted and de-duplicated.
            prop_assert!(
                hits.windows(2).all(|w| w[0] < w[1]),
                "chunk={chunk} produced non-ascending/duplicate hits: {hits:?}"
            );

            match &reference {
                None => reference = Some(hits),
                Some(r) => prop_assert_eq!(&hits, r, "chunk={} disagrees with reference", chunk),
            }
        }
    }

    /// ROBUSTNESS. Any printable-ASCII string is safe to hand to `Pattern::parse`:
    /// it returns `Ok` or `Err`, never panics. (Garbage tokens, lone digits, mixed
    /// case, stray `?`, empty/whitespace — all must be handled, not crashed on.)
    #[test]
    fn parse_never_panics(s in "[\\x20-\\x7e]{0,64}") {
        let _ = Pattern::parse(&s);
    }

    /// ROBUSTNESS. A guest whose only region is non-readable yields an empty `Ok`:
    /// the scanner must skip unreadable memory, not error or invent hits.
    #[test]
    fn no_readable_region_is_empty_ok(pat_bytes in prop::collection::vec(any::<u8>(), 1..16)) {
        let guest = MockGuest::builder()
            .process("t.exe", Pid(1))
            .region(0x10000, "-w-") // writable but NOT readable
            .bytes_at(0x10000, &[0xAAu8; 64])
            .done()
            .build();
        let backend = MockBackend::new(guest);
        let pattern = Pattern::from_bytes(&pat_bytes);

        prop_assert!(scan(&backend, Pid(1), &pattern).unwrap().is_empty());
    }

    /// MULTI-REGION. The same pattern planted in two widely separated regions is
    /// found in both, ascending, with no hit landing in the unmapped gap between
    /// them. The two regions are a page each; the gap (region A's end up to region
    /// B's base) is not mapped at all, so nothing there is readable.
    #[test]
    fn hits_span_two_regions_with_clean_gap((data, pat) in arb_data_and_pattern()) {
        const BASE_A: u64 = 0x10_000;
        const BASE_B: u64 = 0x2000_0000; // far past A's single page
        let guest = MockGuest::builder()
            .process("t.exe", Pid(1))
            .region(BASE_A, "rw-")
            .bytes_at(BASE_A, &data)
            .region(BASE_B, "rw-")
            .bytes_at(BASE_B, &data)
            .done()
            .build();
        let backend = MockBackend::new(guest);
        let pattern = Pattern::parse(&pattern_string(&pat)).unwrap();

        let got = scan(&backend, Pid(1), &pattern).unwrap();

        let img = region_image(&data);
        let offs = naive_find(&img, &pat);
        let mut expected: Vec<u64> = Vec::new();
        for &o in &offs {
            expected.push(BASE_A + o as u64);
        }
        for &o in &offs {
            expected.push(BASE_B + o as u64);
        }
        expected.sort_unstable();

        prop_assert_eq!(&got, &expected);

        // Explicit gap check: no hit may fall between the end of region A's page
        // and the base of region B.
        let gap_start = BASE_A + img.len() as u64;
        prop_assert!(
            got.iter().all(|&a| a < gap_start || a >= BASE_B),
            "a hit landed in the unmapped gap: {got:?}"
        );
    }
}
