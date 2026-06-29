use decant_backend::{MemoryBackend, MockBackend, MockGuest, Pid};
use proptest::prelude::*;

const PAGE: u64 = 0x1000;

fn one_page_rw_guest(base: u64) -> MockBackend {
    let g = MockGuest::builder()
        .process("target.exe", Pid(1234))
        .region(base, "rw-")
        .bytes_at(base, &[0])
        .done()
        .build();
    MockBackend::new(g)
}

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

proptest! {
    #[test]
    fn write_then_read_roundtrips(
        page in 1u64..0x1_0000_0000,
        data in prop::collection::vec(any::<u8>(), 1..=PAGE as usize),
    ) {
        let base = page * PAGE;
        let b = one_page_rw_guest(base);
        let n = b.write(Pid(1234), base, &data).unwrap();
        prop_assert_eq!(n, data.len());
        let got = b.read(Pid(1234), base, data.len()).unwrap();
        prop_assert_eq!(got, data);
    }

    #[test]
    fn reads_inside_region_succeed(
        page in 1u64..0x1_0000_0000,
        len in 1usize..=PAGE as usize,
    ) {
        let base = page * PAGE;
        let b = one_page_rw_guest(base);
        prop_assert!(b.read(Pid(1234), base, len).is_ok());
    }

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
            prop_assert_eq!(b.read(Pid(7), addr, 1).unwrap(), vec![0xAB]);
        }
    }
}

#[test]
fn read_off_by_one_at_region_end() {
    let base = 0x1400_0000u64;
    let b = one_page_rw_guest(base);

    assert!(b.read(Pid(1234), base, PAGE as usize).is_ok());

    assert!(b.read(Pid(1234), base, PAGE as usize + 1).is_err());

    assert!(b.read(Pid(1234), base + PAGE, 1).is_err());

    assert!(b.read(Pid(1234), base + PAGE - 1, 1).is_ok());
}

#[test]
fn zero_length_read_is_empty_ok() {
    let base = 0x1400_0000u64;
    let b = one_page_rw_guest(base);

    assert_eq!(b.read(Pid(1234), base, 0).unwrap(), Vec::<u8>::new());
    assert_eq!(b.read(Pid(1234), 0xdead_0000, 0).unwrap(), Vec::<u8>::new());
}

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

    assert!(b.write(Pid(1), base, &[0xFF, 0xFF, 0xFF, 0xFF]).is_err());

    let after = b.read(Pid(1), base, 4).unwrap();
    assert_eq!(after, before);
}

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

#[test]
fn unknown_pid_and_module_error_cleanly() {
    let b = one_page_rw_guest(0x10_0000);

    assert!(b.process_by_pid(Pid(9999)).is_err());
    assert!(b.module_list(Pid(9999)).is_err());
    assert!(b.module_by_name(Pid(9999), "whatever.dll").is_err());
    assert!(b.module_exports(Pid(9999), "whatever.dll").is_err());
    assert!(b.read(Pid(9999), 0x10_0000, 4).is_err());
    assert!(b.write(Pid(9999), 0x10_0000, &[0]).is_err());
    assert!(b.memory_map(Pid(9999)).is_err());

    assert!(b.module_by_name(Pid(1234), "nope.dll").is_err());
    assert!(b.module_exports(Pid(1234), "nope.dll").is_err());

    assert!(b.process_by_name("does-not-exist.exe").is_err());
}

#[test]
fn overlapping_regions_first_declared_wins() {
    let base = 0x4000_0000u64;
    let g = MockGuest::builder()
        .process("ov.exe", Pid(3))
        .region(base, "r--")
        .bytes_at(base, &[0x11])
        .region(base, "rw-")
        .bytes_at(base, &[0x22])
        .done()
        .build();
    let b = MockBackend::new(g);

    let map = b.memory_map(Pid(3)).unwrap();
    assert_eq!(map.len(), 2);
    assert!(map.iter().all(|r| r.base == base));

    assert!(b.read(Pid(3), base, 1).is_ok());
    assert!(b.write(Pid(3), base, &[0xFF]).is_err());
}

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

    let got = b.read(Pid(5), base, PAGE as usize + 1).unwrap();
    assert_eq!(got.len(), PAGE as usize + 1);
    assert_eq!(got[0], 0xA0);
    assert_eq!(got[PAGE as usize], 0xB0);

    assert!(b.read(Pid(5), base, 2 * PAGE as usize + 1).is_err());
}
