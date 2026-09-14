//! Full end-to-end integration test: deploys the *real* compiled
//! `Guardian` and `GuardedVault` bytecode (from `contracts/out/`, built
//! by `forge build`) onto a locally-spawned `anvil` node, then drives
//! the actual `guardian-client` crate against them exactly as the
//! daemon would. This is the strongest evidence in this repo that the
//! Rust and Solidity halves of the system actually interoperate, not
//! just that each compiles on its own.
//!
//! Requires `anvil` on `PATH` and `contracts/` already built
//! (`forge build`) — skipped with a clear message, not a failure, if
//! either precondition isn't met.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use alloy::network::EthereumWallet;
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use tripwire_core::{ChainId, Confidence, PauseDecision};

sol!(
    #[sol(rpc)]
    Guardian,
    "../../contracts/out/Guardian.sol/Guardian.json"
);

sol!(
    #[sol(rpc)]
    GuardedVault,
    "../../contracts/out/GuardedVault.sol/GuardedVault.json"
);

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

fn try_spawn_anvil(port: u16) -> Option<AnvilGuard> {
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

fn artifacts_built() -> bool {
    std::path::Path::new("../../contracts/out/Guardian.sol/Guardian.json").exists()
        && std::path::Path::new("../../contracts/out/GuardedVault.sol/GuardedVault.json").exists()
}

const ADMIN_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PAUSER_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

#[tokio::test]
async fn guardian_client_pauses_a_real_deployed_vault_end_to_end() {
    if !artifacts_built() {
        eprintln!("SKIPPED: contracts not built -- run `forge build` in contracts/ first");
        return;
    }
    let Some(anvil) = try_spawn_anvil(8648) else {
        eprintln!("SKIPPED: `anvil` not found on PATH (install via `foundryup`)");
        return;
    };
    let rpc_url = anvil.rpc_url();
    if !wait_for_anvil_ready(&rpc_url).await {
        panic!("anvil did not become ready in time");
    }

    let admin_signer: PrivateKeySigner = ADMIN_KEY.parse().unwrap();
    let admin_address = admin_signer.address();
    let pauser_signer: PrivateKeySigner = PAUSER_KEY.parse().unwrap();
    let pauser_address = pauser_signer.address();

    let admin_provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(admin_signer))
        .connect_http(rpc_url.parse().unwrap());

    // Deploy Guardian with `admin` as DEFAULT_ADMIN_ROLE (a plain EOA
    // here for test simplicity; ARCHITECTURE.md §3.4 calls for a
    // TimelockController in a real deployment, exercised separately in
    // the Solidity test suite itself).
    let guardian = Guardian::deploy(&admin_provider, admin_address)
        .await
        .expect("failed to deploy Guardian to local anvil");

    // Deploy GuardedVault pointing its GUARDIAN_ROLE at the Guardian
    // contract's own address -- only the Guardian contract, not any
    // EOA, can ever pause this vault.
    let vault = GuardedVault::deploy(&admin_provider, admin_address, *guardian.address())
        .await
        .expect("failed to deploy GuardedVault to local anvil");

    // Admin grants PAUSER_ROLE to the hot wallet and registers the vault.
    let pauser_role = guardian.PAUSER_ROLE().call().await.unwrap();
    guardian
        .grantRole(pauser_role, pauser_address)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    guardian
        .registerTarget(*vault.address())
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    assert!(!vault.paused().call().await.unwrap());

    // Now drive the real guardian-client crate, signed by the pauser
    // key -- exactly what the daemon would do once detection crosses
    // its threshold.
    let client = guardian_client::connect(&rpc_url, &guardian.address().to_string(), PAUSER_KEY)
        .await
        .expect("guardian_client::connect failed");

    let is_registered = client
        .is_target_registered(&vault.address().to_string())
        .await
        .expect("is_target_registered call failed");
    assert!(is_registered);

    let decision = PauseDecision {
        chain: ChainId(31337),
        target_contract: vault.address().to_string().parse().unwrap(),
        triggering_tx_hash: "0xexploit".into(),
        confidence: Confidence::new(95.0),
        threshold: Confidence::new(80.0),
        matches: vec![],
        evaluated_at_unix: 0,
    };

    let tx_hash = client
        .submit_pause(&decision)
        .await
        .expect("submit_pause failed against real deployed contracts");
    assert!(tx_hash.starts_with("0x"));

    // The real, on-chain, end-to-end assertion: the vault is now paused,
    // reached entirely through guardian-client's own submission path,
    // not by calling the contract directly.
    assert!(vault.paused().call().await.unwrap());

    // And a non-pauser address still cannot repeat this via the same
    // client code path pointed at a different key.
    let attacker_client =
        guardian_client::connect(&rpc_url, &guardian.address().to_string(), ADMIN_KEY)
            .await
            .unwrap();
    // admin is DEFAULT_ADMIN_ROLE, not PAUSER_ROLE -- unpause via admin
    // is a *different* method this client intentionally doesn't expose
    // (ARCHITECTURE.md §3.4); confirm submit_pause with the admin key
    // still requires PAUSER_ROLE and fails on-chain.
    let target_contract: tripwire_core::Address = vault.address().to_string().parse().unwrap();
    let second_decision = PauseDecision {
        target_contract,
        triggering_tx_hash: "0xsecond".into(),
        ..decision
    };
    let result = attacker_client.submit_pause(&second_decision).await;
    assert!(result.is_err(), "admin key must not hold PAUSER_ROLE");

    let _ = Address::ZERO; // silence unused-import if optimized away in some alloy versions
}
