//! Real-world context for the detection engine: the baselines its
//! fund-flow and oracle conditions compare against, and a call-trace
//! fallback for RPC nodes that don't serve `debug_traceTransaction`.
//!
//! The arithmetic is pure and unit-tested (`outflow`, `amm`); `evm` is the
//! thin RPC-backed layer that fetches balances/reserves at the block before
//! a transaction and implements [`detection::ContextSource`].

pub mod amm;
pub mod cast_trace;
pub mod evm;
pub mod outflow;
pub mod value;

pub use evm::{ContextConfig, EvmContext, TraceFallback};
pub use value::{AaveV2Oracle, CompoundOracle, FixedValues, TokenValuer};
