use decant_backend::{MockBackend, MockGuest, Pid};
use decant_core::resolve;
use proptest::prelude::*;

fn arb_chain() -> impl Strategy<Value = (usize, Vec<u64>)> {
    (1usize..6).prop_flat_map(|n| (Just(n), prop::collection::vec(0u64..256, n)))
}

fn arb_base() -> impl Strategy<Value = u64> {
    (1u64..0x10_0000).prop_map(|page| page * 0x1000)
}

proptest! {
    #[test]
    fn valid_chain_resolves_to_constructed_final((n, offsets) in arb_chain(), base in arb_base()) {
        let d = |k: usize| base + (k as u64) * 0x100;
        let final_addr = base + 0x800;

        let mut pb = MockGuest::builder()
            .process("t.exe", Pid(1))
            .region(base, "rw-");
        for (k, &off) in offsets.iter().enumerate() {
            let next = if k + 1 < n { d(k + 1) } else { final_addr };
            pb = pb.u64_at(d(k), next.wrapping_sub(off));
        }
        let backend = MockBackend::new(pb.done().build());

        let got = resolve(&backend, Pid(1), base, &offsets).unwrap();
        prop_assert_eq!(got, final_addr);
    }

    #[test]
    fn empty_offsets_is_identity(base in any::<u64>()) {
        let guest = MockGuest::builder()
            .process("t.exe", Pid(1))
            .region(0x1000, "rw-")
            .bytes_at(0x1000, &[0u8; 8])
            .done()
            .build();
        let backend = MockBackend::new(guest);

        prop_assert_eq!(resolve(&backend, Pid(1), base, &[]).unwrap(), base);
    }

    #[test]
    fn unmapped_base_errors(offsets in prop::collection::vec(0u64..256, 1..6)) {
        let guest = MockGuest::builder()
            .process("t.exe", Pid(1))
            .region(0x10_000, "rw-")
            .bytes_at(0x10_000, &[0u8; 64])
            .done()
            .build();
        let backend = MockBackend::new(guest);

        let unmapped_base = 0xDEAD_0000u64;
        prop_assert!(resolve(&backend, Pid(1), unmapped_base, &offsets).is_err());
    }

    #[test]
    fn void_pointer_chain_errors(
        void in 0xFFFF_0000_0000u64..0xFFFF_FFFF_0000,
        offsets in prop::collection::vec(0u64..256, 2..6),
    ) {
        const BASE: u64 = 0x10_000;
        let guest = MockGuest::builder()
            .process("t.exe", Pid(1))
            .region(BASE, "rw-")
            .u64_at(BASE, void)
            .done()
            .build();
        let backend = MockBackend::new(guest);

        prop_assert!(resolve(&backend, Pid(1), BASE, &offsets).is_err());
    }
}
