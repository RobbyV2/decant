//! # decant-interpose — "the carafe" (Phase 3)
//!
//! The Windows DLL injected into the unmodified tool under Wine. It implements
//! the handful of Win32/NT memory + introspection exports Decant cares about
//! (marshaling them to the daemon over `decant-protocol`), maintains a synthetic
//! handle table, synthesizes process/module snapshots from daemon data *before*
//! the wineserver round-trip, and forwards every other export to the real Wine
//! builtin.
//!
//! The injection/interposition vector is resolved by the Phase 3 spike (spec §7)
//! and recorded as an ADR before this is implemented. Phase 0 ships an empty
//! `cdylib` so the cross-compile target is wired and builds.

#![allow(dead_code)]
