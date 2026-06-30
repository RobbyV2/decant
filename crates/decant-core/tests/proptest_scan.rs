use decant_backend::{MockBackend, MockGuest, Pid};
use decant_core::Pattern;
use decant_core::scanner::{scan, scan_with_chunk};
use proptest::prelude::*;

const PAGE: usize = 0x1000;

fn region_image(data: &[u8]) -> Vec<u8> {
    let size = data.len().div_ceil(PAGE).max(1) * PAGE;
    let mut img = vec![0u8; size];
    img[..data.len()].copy_from_slice(data);
    img
}

fn naive_find(hay: &[u8], pat: &[Option<u8>]) -> Vec<usize> {
    let plen = pat.len();
    if plen == 0 || hay.len() < plen {
        return Vec::new();
    }
    (0..=hay.len() - plen)
        .filter(|&i| {
            pat.iter().zip(&hay[i..i + plen]).all(|(p, &h)| match p {
                Some(b) => *b == h,
                None => true,
            })
        })
        .collect()
}

fn pattern_string(pat: &[Option<u8>]) -> String {
    pat.iter()
        .map(|b| match b {
            Some(v) => format!("{v:02X}"),
            None => "??".to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

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
                .map(|i| {
                    if wildcard[i] {
                        None
                    } else {
                        Some(data[start + i])
                    }
                })
                .collect();
            (data, pat)
        })
}

fn arb_base() -> impl Strategy<Value = u64> {
    (1u64..0x10_0000).prop_map(|page| page * PAGE as u64)
}

fn guest_with(base: u64, data: &[u8]) -> MockBackend {
    let guest = MockGuest::builder()
        .process("t.exe", Pid(1))
        .region(base, "rw-")
        .bytes_at(base, data)
        .done()
        .build();
    MockBackend::new(guest)
}

proptest! {
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

    #[test]
    fn scan_is_chunk_invariant((data, pat) in arb_data_and_pattern(), base in arb_base()) {
        let backend = guest_with(base, &data);
        let pattern = Pattern::parse(&pattern_string(&pat)).unwrap();

        let mut reference: Option<Vec<u64>> = None;
        for chunk in [1usize, 2, 3, 5, 8, 13, 64, 4096] {
            let hits = scan_with_chunk(&backend, Pid(1), &pattern, chunk).unwrap();

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

    #[test]
    fn parse_never_panics(s in "[\\x20-\\x7e]{0,64}") {
        let _ = Pattern::parse(&s);
    }

    #[test]
    fn no_readable_region_is_empty_ok(pat_bytes in prop::collection::vec(any::<u8>(), 1..16)) {
        let guest = MockGuest::builder()
            .process("t.exe", Pid(1))
            .region(0x10000, "-w-")
            .bytes_at(0x10000, &[0xAAu8; 64])
            .done()
            .build();
        let backend = MockBackend::new(guest);
        let pattern = Pattern::from_bytes(&pat_bytes);

        prop_assert!(scan(&backend, Pid(1), &pattern).unwrap().is_empty());
    }

    #[test]
    fn hits_span_two_regions_with_clean_gap((data, pat) in arb_data_and_pattern()) {
        const BASE_A: u64 = 0x10_000;
        const BASE_B: u64 = 0x2000_0000;
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

        let gap_start = BASE_A + img.len() as u64;
        prop_assert!(
            got.iter().all(|&a| a < gap_start || a >= BASE_B),
            "a hit landed in the unmapped gap: {got:?}"
        );
    }
}
