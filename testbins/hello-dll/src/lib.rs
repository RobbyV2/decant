//! Phase 0 toolchain proof — the "hello DLL".
//!
//! A `cdylib` that exports a single `add(a, b)` function. `dll-smoke.exe`
//! `LoadLibrary`s this and calls `add(2, 3)`; `xtask wine-smoke` asserts the
//! result `5` is printed when run under the isolated Wine prefix. That single
//! end-to-end check proves: Rust → PE cross-compile → DLL load under Wine →
//! exported-symbol call all work, before any real logic is written (spec §Phase 0).
//!
//! `cdylib` auto-exports `#[no_mangle]` public functions, so no `.def` file or
//! `dllexport` attribute is needed. On x86_64 there is a single calling
//! convention and undecorated export names (spec operating rule #9), so `extern
//! "C"` and the bare name `add` are exactly what `GetProcAddress("add")` resolves.

/// Add two integers. Exported from the DLL as `add`.
#[no_mangle]
pub extern "C" fn add(a: i32, b: i32) -> i32 {
    a + b
}
