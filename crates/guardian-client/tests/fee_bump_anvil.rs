//! The pause transaction must land even when the first attempt is stuck.
//!
//! Automine is switched off after setup, so a submitted pause sits in the
//! mempool exactly as a low-fee transaction does during a contested block.
//! The client must replace it (same nonce) with higher fees, and when a block
//! is finally mined exactly one pause must have landed, at a higher fee than
//! the first attempt.
//!
//! Requires `anvil` on `PATH` and built contracts; skipped otherwise.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use alloy::consensus::Transaction as _;
use alloy::network::EthereumWallet;
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use guardian_client::SubmitPolicy;
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

const ADMIN_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PAUSER_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

struct Anvil(Child);
impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn artifacts_built() -> bool {
    std::path::Path::new("../../contracts/out/Guardian.sol/Guardian.json").exists()
        && std::path::Path::new("../../contracts/out/GuardedVault.sol/GuardedVault.json").exists()
}

async fn start(port: u16) -> Option<(Anvil, String)> {
    if !artifacts_built() {
        eprintln!("SKIPPED: contracts not built -- run `forge build` in contracts/ first");
        return None;
    }
    let child = Command::new("anvil")
        .args(["--port", &port.to_string(), "--silent"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let url = format!("http://127.0.0.1:{port}");
    let p = ProviderBuilder::new().connect_http(url.parse().unwrap());
    for _ in 0..50 {
        if p.get_block_number().await.is_ok() {
            return Some((Anvil(child), url));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("anvil did not become ready");
}

/// Deploys Guardian + vault, grants the pauser role, registers the vault.
async fn setup(url: &str) -> (String, Address) {
    let admin: PrivateKeySigner = ADMIN_KEY.parse().unwrap();
    let pauser: PrivateKeySigner = PAUSER_KEY.parse().unwrap();
    let admin_addr = admin.address();
    let p = ProviderBuilder::new()
        .wallet(EthereumWallet::from(admin))
        .connect_http(url.parse().unwrap());
    let guardian = Guardian::deploy(&p, admin_addr).await.unwrap();
    let vault = GuardedVault::deploy(&p, admin_addr, *guardian.address())
        .await
        .unwrap();
    let role = guardian.PAUSER_ROLE().call().await.unwrap();
    guardian
        .grantRole(role, pauser.address())
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
    (guardian.address().to_string(), *vault.address())
}

fn decision(vault: &str) -> PauseDecision {
    PauseDecision {
        chain: ChainId(31337),
        target_contract: vault.parse().unwrap(),
        triggering_tx_hash: "0xexploit".into(),
        confidence: Confidence::new(95.0),
        threshold: Confidence::new(80.0),
        matches: vec![],
        counted_evidence: vec![],
        evaluated_at_unix: 0,
    }
}

fn fast_policy() -> SubmitPolicy {
    SubmitPolicy {
        attempt_timeout: Duration::from_millis(400),
        max_attempts: 6,
        ..SubmitPolicy::default()
    }
}

#[tokio::test]
async fn a_stuck_pause_is_replaced_with_higher_fees_and_exactly_one_lands() {
    let Some((_anvil, url)) = start(8660).await else {
        return;
    };
    let (guardian, vault_addr) = setup(&url).await;
    let raw = ProviderBuilder::new().connect_http(url.parse().unwrap());
    let vault = GuardedVault::new(vault_addr, raw.clone());
    let pauser_addr = PAUSER_KEY.parse::<PrivateKeySigner>().unwrap().address();
    let nonce_before = raw.get_transaction_count(pauser_addr).await.unwrap();

    // From here on nothing is mined until we say so.
    raw.raw_request::<_, ()>("evm_setAutomine".into(), (false,))
        .await
        .unwrap();

    let client = guardian_client::connect(&url, &guardian, PAUSER_KEY)
        .await
        .unwrap();
    let d = decision(&vault_addr.to_string());
    let policy = fast_policy();
    let submit = tokio::spawn({
        let policy = policy.clone();
        async move { client.submit_pause_with(&d, &policy).await }
    });

    // Let several attempts go by (400 ms each), then mine one block.
    tokio::time::sleep(Duration::from_millis(1_700)).await;
    assert!(!vault.paused().call().await.unwrap(), "nothing mined yet");
    raw.raw_request::<_, serde_json::Value>("evm_mine".into(), ())
        .await
        .unwrap();

    let hash = submit.await.unwrap().expect("a replacement must land");
    assert!(vault.paused().call().await.unwrap());

    // Exactly one pause transaction from the hot wallet was included: the
    // replacements shared a nonce, so the earlier attempts were superseded.
    let nonce_after = raw.get_transaction_count(pauser_addr).await.unwrap();
    assert_eq!(nonce_after, nonce_before + 1, "one nonce consumed");

    // It landed at a higher priority fee than the first attempt used.
    let tx = raw
        .get_transaction_by_hash(hash.parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    let landed = tx.max_priority_fee_per_gas().expect("1559 tx");
    assert!(
        landed > policy.min_priority_fee_wei * 130 / 100,
        "fee should have been bumped at least once, was {landed}"
    );
    assert!(tx.max_fee_per_gas() <= policy.max_fee_ceiling_wei);
}

#[tokio::test]
async fn attempts_are_bounded_and_the_fee_ceiling_holds() {
    let Some((_anvil, url)) = start(8661).await else {
        return;
    };
    let (guardian, vault_addr) = setup(&url).await;
    let raw = ProviderBuilder::new().connect_http(url.parse().unwrap());
    let vault = GuardedVault::new(vault_addr, raw.clone());
    raw.raw_request::<_, ()>("evm_setAutomine".into(), (false,))
        .await
        .unwrap();

    let client = guardian_client::connect(&url, &guardian, PAUSER_KEY)
        .await
        .unwrap();
    let policy = SubmitPolicy {
        attempt_timeout: Duration::from_millis(150),
        max_attempts: 3,
        ..SubmitPolicy::default()
    };
    let err = client
        .submit_pause_with(&decision(&vault_addr.to_string()), &policy)
        .await
        .expect_err("nothing is ever mined");
    assert!(err.to_string().contains("not mined"), "{err}");
    assert!(!vault.paused().call().await.unwrap());

    // Every pending transaction respects the ceiling, and (same nonce)
    // only one pause is pending however many attempts were made.
    let pool: serde_json::Value = raw.raw_request("txpool_content".into(), ()).await.unwrap();
    let mut pending = 0;
    for (_addr, by_nonce) in pool["pending"].as_object().unwrap() {
        for (_nonce, tx) in by_nonce.as_object().unwrap() {
            pending += 1;
            let max_fee = u128::from_str_radix(
                tx["maxFeePerGas"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap();
            assert!(max_fee <= policy.max_fee_ceiling_wei, "{max_fee}");
        }
    }
    assert_eq!(pending, 1, "replacements share a nonce: {pool}");
}

#[tokio::test]
async fn a_pause_that_reverts_fails_fast_instead_of_retrying() {
    let Some((_anvil, url)) = start(8662).await else {
        return;
    };
    let (guardian, vault_addr) = setup(&url).await;
    // The admin key does not hold PAUSER_ROLE: estimation reverts.
    let client = guardian_client::connect(&url, &guardian, ADMIN_KEY)
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let r = client
        .submit_pause_with(&decision(&vault_addr.to_string()), &SubmitPolicy::default())
        .await;
    assert!(r.is_err());
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "must not wait out attempt timeouts for a hard failure: {:?}",
        started.elapsed()
    );
}
