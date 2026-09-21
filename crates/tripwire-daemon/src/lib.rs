//! The Tripwire daemon as a library: a reorg-aware, confirmation-gated
//! engine (`engine`) plus the traits that let it be tested without a
//! network. `main.rs` only wires real implementations to it.

pub mod engine;
mod guardian_pauser;

pub use engine::{
    BaselineSource, ContextSource, Engine, EngineConfig, EngineError, NoContext, PauseError,
    PauseRecord, Pauser, TickReport,
};
