//! Cross-crate historical-exploit validation: obtains the real call trace
//! and receipt logs of a past transaction and runs them through the real
//! `detection` engine, using the same production `tripwire-context` code the
//! daemon uses — the Rust-side complement to `contracts/test/replay`'s
//! Solidity fork tests (ARCHITECTURE.md §4).
//!
//! This crate has no production code paths; the actual validation cases
//! live in `tests/`.

pub use tripwire_context::cast_trace;
pub mod support;
