//! Connects the engine's `Pauser` trait to the real on-chain `Guardian`.

use alloy::providers::Provider;
use async_trait::async_trait;
use guardian_client::GuardianClient;
use tripwire_core::{Address, PauseDecision};

use crate::engine::{PauseError, Pauser};

#[async_trait]
impl<P: Provider> Pauser for GuardianClient<P> {
    async fn is_paused(&self, target: &Address) -> Result<bool, PauseError> {
        GuardianClient::is_paused(self, &target.to_string())
            .await
            .map_err(|e| PauseError(e.to_string()))
    }

    async fn submit_pause(&self, decision: &PauseDecision) -> Result<String, PauseError> {
        GuardianClient::submit_pause(self, decision)
            .await
            .map_err(|e| PauseError(e.to_string()))
    }
}
