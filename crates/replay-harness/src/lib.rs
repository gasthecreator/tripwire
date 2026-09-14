//! Cross-crate historical-exploit validation: fetches a real, past
//! transaction from a real archive-RPC endpoint via `chain-adapter`, and
//! runs its actual decoded call trace through the real `detection`
//! engine — the Rust-side complement to `contracts/test/replay`'s
//! Solidity fork tests (ARCHITECTURE.md §4).
//!
//! This crate has no production code of its own; see `tests/` for the
//! actual validation cases.
