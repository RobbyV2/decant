//! # decant-daemon — "the cellar" (Phase 1)
//!
//! TCP server on `127.0.0.1:<port>` that dispatches `decant-protocol` requests to
//! a [`decant_backend::MemoryBackend`] chosen at startup (`--backend mock`
//! default, `--backend memflow`). Length-prefixed bincode framing.
//!
//! Phase 0 ships a stub `main` so the workspace builds; Phase 1 implements the
//! server loop, dispatch, and capability detection.

fn main() {
    eprintln!("decant-daemon: not implemented yet (Phase 1). The TCP server and");
    eprintln!("backend dispatch land in Phase 1; Phase 0 only proves the toolchain.");
    std::process::exit(0);
}
