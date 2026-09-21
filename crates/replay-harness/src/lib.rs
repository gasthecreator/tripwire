//! Cross-crate historical-exploit validation: obtains the real call
//! trace of a past transaction and runs it through the real `detection`
//! engine — the Rust-side complement to `contracts/test/replay`'s
//! Solidity fork tests (ARCHITECTURE.md §4).
//!
//! This crate has no production code paths; the actual validation cases
//! live in `tests/`.

pub mod cast_trace;
