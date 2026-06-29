//! Adversarial property tests for the pointer-chain **resolver**
//! (`decant_core::resolve`).
//!
//! The resolver's convention (from `src/resolver.rs`) is:
//! ```text
//! address = base
//! for off in offsets:
//!     address = deref_u64(address) + off
//! ```
//! i.e. each step dereferences the current address (8-byte little-endian pointer)
//! and adds the offset; the result of the *last* step is the final address and is
//! NOT dereferenced. Empty offsets => `base`.
//!
//! These properties construct random *valid* chains from the convention itself and
//! assert the resolver lands where the construction says it must, then probe the
//! two failure modes (unreadable base, pointer into the void) for clean `Err`s with
//! no panic and no infinite loop.
//!
//! ## How a valid chain is laid out
//!
//! For `N` offsets there are `N` dereferences at addresses `D_0..D_{N-1}` with
//! `D_0 == base`. The invariant tying them together is, for each step `k`:
//! ```text
//! deref(D_k) + offsets[k] == next_k
//! ```
//! where `next_k = D_{k+1}` for the intermediate steps and `next_{N-1} = final`
//! (the answer). So we store `V_k = next_k - offsets[k]` at `D_k`. We space the
//! `D_k` 0x100 apart inside one page so they never overlap (N <= 5 => D_k in
//! `base..=base+0x400`), and put `final` at `base + 0x800`, clear of every node.

use decant_core::resolve;
use decant_backend::{MockBackend, MockGuest, Pid};
use proptest::prelude::*;

/// `N` in 1..6 plus `N` small offsets (0..256), mirroring real pointer-chain hops
/// (struct field displacements) which are small and non-negative.
fn arb_chain() -> impl Strategy<Value = (usize, Vec<u64>)> {
    (1usize..6).prop_flat_map(|n| (Just(n), prop::collection::vec(0u64..256, n)))
}

/// A page-aligned, non-null base in `[0x1000, 0x1_0000_0000)`.
fn arb_base() -> impl Strategy<Value = u64> {
    (1u64..0x10_0000).prop_map(|page| page * 0x1000)
}

proptest! {
    /// VALID CHAIN. A chain built to the resolver's own convention resolves to the
    /// constructed final address, for any length 1..=5 and any small offsets.
    #[test]
    fn valid_chain_resolves_to_constructed_final((n, offsets) in arb_chain(), base in arb_base()) {
        // Deref site k lives at base + k*0x100; the answer sits clear of them all.
        let d = |k: usize| base + (k as u64) * 0x100;
        let final_addr = base + 0x800;

        let mut pb = MockGuest::builder()
            .process("t.exe", Pid(1))
            .region(base, "rw-");
        for k in 0..n {
            // next site is D_{k+1} for intermediate hops, else the final address.
            let next = if k + 1 < n { d(k + 1) } else { final_addr };
            // Store V_k so that deref(D_k) + offsets[k] == next. base/offsets are
            // far larger/smaller respectively, so this never underflows; use
            // wrapping_sub to mirror the resolver's wrapping arithmetic anyway.
            pb = pb.u64_at(d(k), next.wrapping_sub(offsets[k]));
        }
        let backend = MockBackend::new(pb.done().build());

        let got = resolve(&backend, Pid(1), base, &offsets).unwrap();
        prop_assert_eq!(got, final_addr);
    }

    /// IDENTITY. Empty offsets return `base` verbatim, for any `base` (the resolver
    /// reads no memory in this case — it short-circuits before any deref).
    #[test]
    fn empty_offsets_is_identity(base in any::<u64>()) {
        // A backend still has to exist (and know pid 1); its contents are irrelevant.
        let guest = MockGuest::builder()
            .process("t.exe", Pid(1))
            .region(0x1000, "rw-")
            .bytes_at(0x1000, &[0u8; 8])
            .done()
            .build();
        let backend = MockBackend::new(guest);

        prop_assert_eq!(resolve(&backend, Pid(1), base, &[]).unwrap(), base);
    }

    /// FAILURE — unreadable base. If `base` itself is outside every region, the very
    /// first deref's read fails and the resolver returns `Err` (never panics, never
    /// loops). Offsets are non-empty so a deref is actually attempted.
    #[test]
    fn unmapped_base_errors(offsets in prop::collection::vec(0u64..256, 1..6)) {
        let guest = MockGuest::builder()
            .process("t.exe", Pid(1))
            .region(0x10_000, "rw-")
            .bytes_at(0x10_000, &[0u8; 64])
            .done()
            .build();
        let backend = MockBackend::new(guest);

        let unmapped_base = 0xDEAD_0000u64; // nowhere near the lone region
        prop_assert!(resolve(&backend, Pid(1), unmapped_base, &offsets).is_err());
    }

    /// FAILURE — pointer into the void. `base` is readable and holds a pointer to an
    /// unmapped high address; following it (>= 2 offsets, so the void pointer is
    /// itself dereferenced) must `Err` cleanly with no panic / no infinite loop.
    #[test]
    fn void_pointer_chain_errors(
        void in 0xFFFF_0000_0000u64..0xFFFF_FFFF_0000,
        offsets in prop::collection::vec(0u64..256, 2..6),
    ) {
        const BASE: u64 = 0x10_000;
        let guest = MockGuest::builder()
            .process("t.exe", Pid(1))
            .region(BASE, "rw-")
            .u64_at(BASE, void) // first deref yields a pointer into the void
            .done()
            .build();
        let backend = MockBackend::new(guest);

        // Step 0 reads BASE (mapped) -> void+off0 (unmapped); step 1 then reads
        // there and fails.
        prop_assert!(resolve(&backend, Pid(1), BASE, &offsets).is_err());
    }
}
