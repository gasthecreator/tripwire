//! The whole daemon against a real chain: a live `anvil` node, the real
//! compiled `Guardian`/`GuardedVault` contracts, the real `EvmAdapter` and
//! `GuardianClient`, driven by the real `Engine`. Includes a *real* reorg
//! (snapshot + revert), which the in-memory fake-chain tests can only
//! simulate.
//!
//! The signature used here is deliberately trivial: any call to the vault's
//! `deposit()` scores 100. The point is the plumbing and the state machine
//! (confirmation gating, reorg cancellation, idempotency), not detection
//! quality — that is covered by the replay tests against real exploits.
//!
//! Requires `anvil` on PATH and `contracts/` built (`forge build`); skipped
//! with a message otherwise.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use chain_adapter::evm::EvmAdapter;
use tripwire_core::{ChainId, Condition, ConditionKind, Confidence, Signature, SignatureCategory};
use tripwire_daemon::{Engine, EngineConfig, NoContext};

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

// Anvil's well-known deterministic dev keys (published in Foundry's docs).
const ADMIN_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PAUSER_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const USER_KEY: &str = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
/// `deposit()`
const DEPOSIT_SELECTOR: &str = "0xd0e30db0";

struct Anvil(Child);
impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_anvil(port: u16) -> Option<Anvil> {
    Command::new("anvil")
        .args(["--port", &port.to_string(), "--silent"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
        .map(Anvil)
}

fn deposit_signature() -> Signature {
    Signature {
        id: "any-deposit".into(),
        description: "test signature: any call to deposit()".into(),
        category: SignatureCategory::FundFlowAnomaly,
        window_seconds: 60,
        conditions: vec![Condition {
            id: "deposit-called".into(),
            kind: ConditionKind::CallSequence {
                selectors: vec![DEPOSIT_SELECTOR.into()],
            },
            weight: 100.0,
        }],
    }
}

struct Env {
    _anvil: Anvil,
    rpc: String,
    vault: Address,
    guardian: Address,
    reader: alloy::providers::DynProvider,
}

async fn setup(port: u16) -> Option<Env> {
    if !std::path::Path::new("../../contracts/out/Guardian.sol/Guardian.json").exists() {
        eprintln!("SKIPPED: contracts not built -- run `forge build` in contracts/");
        return None;
    }
    let Some(anvil) = spawn_anvil(port) else {
        eprintln!("SKIPPED: `anvil` not on PATH (install via foundryup)");
        return None;
    };
    let rpc = format!("http://127.0.0.1:{port}");
    let reader = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    let mut ready = false;
    for _ in 0..80 {
        if reader.get_block_number().await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "anvil did not start");

    let admin: PrivateKeySigner = ADMIN_KEY.parse().unwrap();
    let pauser: PrivateKeySigner = PAUSER_KEY.parse().unwrap();
    let admin_addr = admin.address();
    let admin_provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(admin))
        .connect_http(rpc.parse().unwrap());

    let guardian = Guardian::deploy(&admin_provider, admin_addr).await.unwrap();
    let vault = GuardedVault::deploy(&admin_provider, admin_addr, *guardian.address())
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

    Some(Env {
        _anvil: anvil,
        rpc,
        vault: *vault.address(),
        guardian: *guardian.address(),
        reader: reader.erased(),
    })
}

async fn make_engine(
    env: &Env,
    min_confirmations: u64,
) -> Engine<EvmAdapter, impl tripwire_daemon::Pauser, NoContext> {
    let adapter = EvmAdapter::connect(&env.rpc, ChainId(31337)).await.unwrap();
    let guardian = guardian_client::connect(&env.rpc, &env.guardian.to_string(), PAUSER_KEY)
        .await
        .unwrap();
    let mut cfg = EngineConfig::new(
        ChainId(31337),
        env.vault.to_string().parse().unwrap(),
        Confidence::new(80.0),
    );
    cfg.min_confirmations = min_confirmations;
    Engine::new(adapter, guardian, NoContext, vec![deposit_signature()], cfg)
}

async fn user_send(env: &Env, value_wei: u128, calldata: Option<Vec<u8>>) {
    let user: PrivateKeySigner = USER_KEY.parse().unwrap();
    let p = ProviderBuilder::new()
        .wallet(EthereumWallet::from(user))
        .connect_http(env.rpc.parse().unwrap());
    let mut tx = TransactionRequest::default()
        .with_to(env.vault)
        .with_value(U256::from(value_wei));
    if let Some(data) = calldata {
        tx = tx.with_input(data);
    }
    p.send_transaction(tx)
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
}

/// `deposit()` calldata
fn deposit_call() -> Vec<u8> {
    vec![0xd0, 0xe3, 0x0d, 0xb0]
}

async fn is_paused(env: &Env) -> bool {
    GuardedVault::new(env.vault, &env.reader)
        .paused()
        .call()
        .await
        .unwrap()
}

async fn mine(env: &Env, n: u64) {
    for _ in 0..n {
        let _: serde_json::Value = env.reader.raw_request("evm_mine".into(), ()).await.unwrap();
    }
}

#[tokio::test]
async fn detects_waits_for_confirmation_then_pauses_the_real_vault() {
    let Some(env) = setup(8650).await else { return };
    let mut engine = make_engine(&env, 1).await;
    engine.tick().await.unwrap(); // anchor at current head

    // A benign plain ETH transfer to the vault: touches the target, matches nothing.
    user_send(&env, 1, None).await;
    let r = engine.tick().await.unwrap();
    assert_eq!((r.evaluated, r.pending), (1, 0));
    assert!(!is_paused(&env).await);

    // The "exploit": a deposit() call. Seen at the head => held for a confirmation.
    user_send(&env, 1_000, Some(deposit_call())).await;
    let r = engine.tick().await.unwrap();
    assert_eq!((r.evaluated, r.pending, r.pauses.len()), (1, 1, 0));
    assert!(
        !is_paused(&env).await,
        "must not act before the block is confirmed"
    );

    mine(&env, 1).await;
    let r = engine.tick().await.unwrap();
    assert_eq!(r.pauses.len(), 1, "report: {r:?}");
    assert!(
        is_paused(&env).await,
        "the real vault is now paused on-chain"
    );
    println!(
        "detect->pause latency on a local chain: {:?}",
        r.pauses[0].latency
    );

    // Idempotent: further ticks (and another exploit tx) do not re-pause.
    mine(&env, 2).await;
    let r = engine.tick().await.unwrap();
    assert!(r.pauses.is_empty() && r.pause_errors == 0);
}

#[tokio::test]
async fn a_real_reorg_before_confirmation_cancels_the_pause() {
    let Some(env) = setup(8651).await else { return };
    let mut engine = make_engine(&env, 2).await;
    engine.tick().await.unwrap();

    let snapshot: String = env
        .reader
        .raw_request("evm_snapshot".into(), ())
        .await
        .unwrap();

    user_send(&env, 1_000, Some(deposit_call())).await;
    let r = engine.tick().await.unwrap();
    assert_eq!(r.pending, 1);

    // The block holding the exploit is abandoned: revert the chain to the
    // snapshot and build a different one (empty blocks) in its place.
    let ok: bool = env
        .reader
        .raw_request("evm_revert".into(), (snapshot,))
        .await
        .unwrap();
    assert!(ok);
    mine(&env, 3).await;

    let r = engine.tick().await.unwrap();
    assert!(
        r.reorg_depth.is_some(),
        "the engine noticed the reorg: {r:?}"
    );
    assert_eq!(r.dropped_by_reorg, 1);
    assert!(r.pauses.is_empty());
    assert!(
        !is_paused(&env).await,
        "a transaction that never happened must not pause the vault"
    );

    mine(&env, 2).await;
    engine.tick().await.unwrap();
    assert!(!is_paused(&env).await);
}

#[tokio::test]
async fn zero_confirmations_pauses_in_the_next_tick() {
    let Some(env) = setup(8652).await else { return };
    let mut engine = make_engine(&env, 0).await;
    engine.tick().await.unwrap();
    user_send(&env, 1_000, Some(deposit_call())).await;
    let r = engine.tick().await.unwrap();
    assert_eq!(r.pauses.len(), 1);
    assert!(is_paused(&env).await);
}
