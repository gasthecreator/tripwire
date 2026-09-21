//! Signs and submits the on-chain `pause()` call once the detection
//! engine has already decided to act. This crate deliberately does
//! *not* re-implement the confirmation-depth gate from ARCHITECTURE.md
//! §3.2 — that's the daemon's orchestration responsibility, applied
//! before a `PauseDecision` ever reaches this crate. `guardian-client`'s
//! only job is: given a decision that's already been cleared to act on,
//! get the transaction signed, submitted, and confirmed, and report
//! back honestly what happened.

use std::str::FromStr;

use alloy::network::EthereumWallet;
use alloy::primitives::Address as AlloyAddress;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::sol;
use thiserror::Error;
use tripwire_core::PauseDecision;

sol! {
    #[sol(rpc)]
    interface IGuardian {
        function pause(address target, string calldata reason) external;
        function unpause(address target) external;
        function registeredTargets(address target) external view returns (bool);
    }

    #[sol(rpc)]
    interface IPausableTarget {
        function paused() external view returns (bool);
    }
}

#[derive(Debug, Error)]
pub enum GuardianClientError {
    #[error("decision did not cross its threshold; refusing to submit a pause for it")]
    BelowThreshold,
    #[error("invalid RPC URL: {0}")]
    InvalidUrl(String),
    #[error("invalid guardian contract address: {0}")]
    InvalidAddress(String),
    #[error("invalid private key: {0}")]
    InvalidKey(String),
    #[error("transaction submission failed: {0}")]
    Submission(String),
}

/// Generic over the provider type deliberately: alloy's `ProviderBuilder`
/// output (a chain of `JoinFill`-nested gas/nonce/chain-id/wallet
/// fillers over a `RootProvider`) is a real but unnameable type, and
/// spelling it out by hand is exactly the kind of alloy-version-coupled
/// fragility this crate shouldn't carry. The free function `connect()`
/// below returns `GuardianClient<impl Provider<..>>`, letting the
/// compiler infer it instead.
///
/// Holding exactly `PAUSER_ROLE` on the `Guardian` contract and nothing
/// else is what bounds this key's blast radius to "can pause a
/// registered target" — see SECURITY.md T1. This client has no unpause
/// path at all: unpausing is deliberately a separate, timelock-gated
/// flow it doesn't participate in (ARCHITECTURE.md §3.4).
pub struct GuardianClient<P: Provider> {
    contract: IGuardian::IGuardianInstance<P>,
}

impl<P: Provider> GuardianClient<P> {
    /// Connects using an already-constructed provider — the entry point
    /// tests use to inject a provider pointed at a local `anvil` node,
    /// and that a real daemon could also use to share one provider
    /// across a `ChainAdapter` and this client.
    pub fn from_provider(guardian_address: &str, provider: P) -> Result<Self, GuardianClientError> {
        let address = AlloyAddress::from_str(guardian_address)
            .map_err(|e| GuardianClientError::InvalidAddress(e.to_string()))?;
        Ok(Self {
            contract: IGuardian::new(address, provider),
        })
    }

    /// Submits the pause transaction for `decision` and waits for it to
    /// be mined. Refuses (without ever hitting the network) to submit a
    /// decision that didn't cross its own threshold — the caller
    /// deciding to build a `PauseDecision` at all doesn't imply it
    /// should be acted on; only `should_pause()` does.
    pub async fn submit_pause(
        &self,
        decision: &PauseDecision,
    ) -> Result<String, GuardianClientError> {
        if !decision.should_pause() {
            return Err(GuardianClientError::BelowThreshold);
        }

        let target = AlloyAddress::from_str(&decision.target_contract.to_string())
            .map_err(|e| GuardianClientError::InvalidAddress(e.to_string()))?;
        let reason = format!(
            "conf={:.1} thr={:.1} sigs={}",
            decision.confidence.value(),
            decision.threshold.value(),
            decision
                .matches
                .iter()
                .map(|m| m.signature_id.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );

        let pending = self
            .contract
            .pause(target, reason)
            .send()
            .await
            .map_err(|e| GuardianClientError::Submission(e.to_string()))?;

        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| GuardianClientError::Submission(e.to_string()))?;

        tracing::info!(
            tx_hash = %receipt.transaction_hash,
            target = %decision.target_contract,
            triggering_tx = %decision.triggering_tx_hash,
            confidence = decision.confidence.value(),
            "submitted and confirmed guardian pause"
        );

        Ok(format!("{:#x}", receipt.transaction_hash))
    }

    /// Whether `target` is currently paused, read straight from the
    /// target contract. Lets the daemon avoid submitting a pause that
    /// would only revert (and burn gas) because something already paused
    /// the protocol — including a previous Tripwire pause.
    pub async fn is_paused(&self, target: &str) -> Result<bool, GuardianClientError> {
        let address = AlloyAddress::from_str(target)
            .map_err(|e| GuardianClientError::InvalidAddress(e.to_string()))?;
        IPausableTarget::new(address, self.contract.provider())
            .paused()
            .call()
            .await
            .map_err(|e| GuardianClientError::Submission(e.to_string()))
    }

    /// Read-only check of whether a target is currently registered with
    /// this guardian — useful for the daemon to validate its own config
    /// against on-chain state at startup rather than discovering a
    /// misconfiguration only when the first real pause attempt reverts.
    pub async fn is_target_registered(&self, target: &str) -> Result<bool, GuardianClientError> {
        let address = AlloyAddress::from_str(target)
            .map_err(|e| GuardianClientError::InvalidAddress(e.to_string()))?;
        self.contract
            .registeredTargets(address)
            .call()
            .await
            .map_err(|e| GuardianClientError::Submission(e.to_string()))
    }
}

/// Builds a wallet-signing HTTP provider and connects a `GuardianClient`
/// to it in one step — the constructor a daemon binary actually calls.
/// A free function rather than an inherent method on `GuardianClient<P>`
/// because it's the one place `P` gets chosen (via return-position `impl
/// Trait`) rather than supplied by the caller.
pub async fn connect(
    rpc_url: &str,
    guardian_address: &str,
    pauser_private_key: &str,
) -> Result<GuardianClient<impl Provider>, GuardianClientError> {
    let url = rpc_url
        .parse()
        .map_err(|e| GuardianClientError::InvalidUrl(format!("{e}")))?;
    let signer = alloy::signers::local::PrivateKeySigner::from_str(pauser_private_key)
        .map_err(|e| GuardianClientError::InvalidKey(e.to_string()))?;
    let wallet = EthereumWallet::from(signer);

    // Gas/nonce/chain-id/wallet fillers are on by default as of alloy
    // 1.x (previously required an explicit `.with_recommended_fillers()`
    // call, removed here as part of the alloy 0.9 -> 1.x upgrade).
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(url);

    GuardianClient::from_provider(guardian_address, provider)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tripwire_core::{Address, ChainId, Confidence};

    fn decision(confidence: f64, threshold: f64) -> PauseDecision {
        PauseDecision {
            chain: ChainId::ETHEREUM_MAINNET,
            target_contract: Address::from_str("0x0000000000000000000000000000000000000001")
                .unwrap(),
            triggering_tx_hash: "0xdead".into(),
            confidence: Confidence::new(confidence),
            threshold: Confidence::new(threshold),
            matches: vec![],
            counted_evidence: vec![],
            evaluated_at_unix: 0,
        }
    }

    #[tokio::test]
    async fn refuses_to_submit_below_threshold_without_any_network_call() {
        // Connects to an address with nothing listening -- if this test
        // ever tried to actually reach the network, it would hang/error
        // on the connection, not return `BelowThreshold` immediately.
        let client = connect(
            "http://127.0.0.1:1",
            "0x0000000000000000000000000000000000000002",
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )
        .await
        .unwrap();

        let result = client.submit_pause(&decision(50.0, 80.0)).await;
        assert!(matches!(result, Err(GuardianClientError::BelowThreshold)));
    }
}
