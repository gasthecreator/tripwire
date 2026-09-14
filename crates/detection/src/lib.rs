//! The detection state machine: loads exploit signatures (data, not
//! code — see `signatures/*.yaml`), evaluates them against transaction
//! events, and scores the result into an auditable `PauseDecision`.
//!
//! See ARCHITECTURE.md §3.3 for the design reasoning, and
//! `SECURITY.md` §3 for why scoring — not a boolean trigger — is the
//! false-positive control surface.

pub mod conditions;
pub mod engine;
pub mod loader;

pub use conditions::Baseline;
pub use engine::{evaluate, evaluate_signatures, score};
pub use loader::{load_signatures_from_dir, LoaderError};
