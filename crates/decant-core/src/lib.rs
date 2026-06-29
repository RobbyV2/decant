//! # decant-core — backend-agnostic analysis primitives
//!
//! The AOB/signature scanner and pointer-chain resolver. Both operate purely
//! through the [`decant_backend::MemoryBackend`] trait, so they are tested
//! deterministically against a `MockGuest` with no VM (spec §4, Phase 2).
//!
//! Filled in during Phase 2. The skeleton exists now so the workspace and the
//! frozen contracts compile end-to-end (spec operating rule #10).

#![allow(dead_code)]
