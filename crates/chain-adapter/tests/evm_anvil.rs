//! Integration test against a real, locally-spawned `anvil` node — not a
//! mock. Per this project's standing preference for validating against
//! real infrastructure over mocked behavior, this is what actually
//! proves `EvmAdapter` decodes real RPC responses correctly, rather than
//! only proving it satisfies a hand-written fake's shape.
//!
//! Requires `anvil` on `PATH` (installed via `foundryup`). Skipped with a
//! clear message, not a failure, if it isn't found — this must not break
//! `cargo test --workspace` on a machine that hasn't installed Foundry.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use chain_adapter::evm::EvmAdapter;
use chain_adapter::ChainAdapter;
use tripwire_core::ChainId;

struct AnvilGuard {
    child: Child,
    port: u16,
}

impl AnvilGuard {
    fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for AnvilGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn try_spawn_anvil() -> Option<AnvilGuard> {
    // A fixed high port in the ephemeral range, distinct from other
    // projects' default dev ports on this machine (per this session's
    // own host-capacity lessons about port/resource collisions across
    // concurrently running projects).
    let port: u16 = 8646;
    let child = Command::new("anvil")
        .args(["--port", &port.to_string(), "--silent"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    Some(AnvilGuard { child, port })
}

async fn wait_for_anvil_ready(rpc_url: &str) -> bool {
    for _ in 0..50 {
        let provider = ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());
        if provider.get_block_number().await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
async fn evm_adapter_decodes_a_real_anvil_transaction() {
    let Some(anvil) = try_spawn_anvil() else {
        eprintln!(
            "SKIPPED: `anvil` not found on PATH (install via `foundryup`) — see CONTRIBUTING.md"
        );
        return;
    };
    let rpc_url = anvil.rpc_url();

    if !wait_for_anvil_ready(&rpc_url).await {
        panic!("anvil did not become ready in time");
    }

    // Anvil's well-known, deterministic default dev account #0 private
    // key — funded with test ETH on every fresh anvil instance. Not a
    // secret: this key is published in Foundry's own documentation and
    // must never be used anywhere real funds could reach it.
    let signer: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();
    let recipient = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");

    let wallet = EthereumWallet::from(signer);
    let wallet_provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse().unwrap());

    let tx = TransactionRequest::default()
        .with_to(recipient)
        .with_value(U256::from(1_000_000_000_000_000_000u128)); // 1 ETH

    let pending = wallet_provider
        .send_transaction(tx)
        .await
        .expect("failed to send transaction to local anvil");
    let receipt = pending
        .get_receipt()
        .await
        .expect("failed to get receipt from local anvil");
    let block_number = receipt
        .block_number
        .expect("mined transaction must have a block number");

    let adapter = EvmAdapter::connect(&rpc_url, ChainId(31337))
        .await
        .expect("failed to connect EvmAdapter to local anvil");

    assert_eq!(adapter.chain_id(), ChainId(31337));

    let head = adapter
        .latest_block_number()
        .await
        .expect("failed to fetch latest block number");
    assert!(
        head >= block_number,
        "adapter's view of chain head must include our mined tx"
    );

    let events = adapter
        .get_block_tx_events(block_number)
        .await
        .expect("failed to fetch normalized tx events for the block");

    let expected_hash = format!("{:#x}", receipt.transaction_hash);
    let found = events
        .iter()
        .find(|e| e.tx_hash == expected_hash)
        .unwrap_or_else(|| {
            panic!("expected to find tx {expected_hash} in block {block_number}, got {events:?}")
        });

    assert_eq!(found.value_wei, 1_000_000_000_000_000_000u128);
    assert_eq!(
        found.to.unwrap().to_string().to_lowercase(),
        format!("{recipient:#x}").to_lowercase()
    );
    assert_eq!(found.chain, ChainId(31337));
}

#[tokio::test]
async fn evm_adapter_reports_block_not_found_for_future_block() {
    let Some(anvil) = try_spawn_anvil_on(8647) else {
        eprintln!("SKIPPED: `anvil` not found on PATH");
        return;
    };
    let rpc_url = anvil.rpc_url();
    if !wait_for_anvil_ready(&rpc_url).await {
        panic!("anvil did not become ready in time");
    }

    let adapter = EvmAdapter::connect(&rpc_url, ChainId(31337)).await.unwrap();
    let result = adapter.get_block_tx_events(999_999_999).await;
    assert!(matches!(
        result,
        Err(chain_adapter::ChainAdapterError::BlockNotFound(999_999_999))
    ));
}

fn try_spawn_anvil_on(port: u16) -> Option<AnvilGuard> {
    let child = Command::new("anvil")
        .args(["--port", &port.to_string(), "--silent"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    Some(AnvilGuard { child, port })
}

#[tokio::test]
async fn get_tx_event_matches_the_block_view_of_the_same_transaction() {
    let Some(anvil) = try_spawn_anvil_on(8649) else {
        eprintln!("SKIPPED: `anvil` not found on PATH");
        return;
    };
    let rpc_url = anvil.rpc_url();
    if !wait_for_anvil_ready(&rpc_url).await {
        panic!("anvil did not become ready in time");
    }
    let signer: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();
    let recipient = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
    let p = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(rpc_url.parse().unwrap());
    let receipt = p
        .send_transaction(
            TransactionRequest::default()
                .with_to(recipient)
                .with_value(U256::from(7u64)),
        )
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    let hash = format!("{:#x}", receipt.transaction_hash);

    let adapter = EvmAdapter::connect(&rpc_url, ChainId(31337)).await.unwrap();
    let single = adapter.get_tx_event(&hash).await.unwrap();
    let from_block = adapter
        .get_block_tx_events(receipt.block_number.unwrap())
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.tx_hash == hash)
        .unwrap();
    assert_eq!(single, from_block);
    assert_eq!(single.value_wei, 7);

    // Unknown and malformed hashes are errors, never an empty event.
    assert!(adapter
        .get_tx_event(&format!("0x{}", "ab".repeat(32)))
        .await
        .is_err());
    assert!(adapter.get_tx_event("not-a-hash").await.is_err());
}
