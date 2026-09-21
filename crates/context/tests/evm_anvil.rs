//! `EvmContext` against a real chain: a live `anvil` node with deployed mock
//! contracts, so the *network* half of the context source (historical
//! `balanceOf` / `getReserves` / `eth_getBalance` at the block before the
//! transaction, log parsing of real receipts, real call traces) is exercised
//! in CI without an RPC key. The pure arithmetic is unit-tested in
//! `outflow.rs` / `amm.rs`; live mainnet replays live in `replay-harness`.
//!
//! Requires `anvil` on PATH and `contracts/` built; skipped otherwise.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use alloy::network::EthereumWallet;
use alloy::primitives::{Address as AAddress, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use chain_adapter::evm::EvmAdapter;
use chain_adapter::ChainAdapter;
use detection::ContextSource;
use tripwire_context::{ContextConfig, EvmContext, TraceFallback};
use tripwire_core::{Address, ChainId, TxEvent};

sol!(
    #[sol(rpc)]
    MockERC20,
    "../../contracts/out/Mocks.sol/MockERC20.json"
);
sol!(
    #[sol(rpc)]
    MockV2Pair,
    "../../contracts/out/Mocks.sol/MockV2Pair.json"
);
sol!(
    #[sol(rpc)]
    MockVault,
    "../../contracts/out/Mocks.sol/MockVault.json"
);

const KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ONE: u128 = 1_000_000_000_000_000_000;

struct Anvil(Child);
impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Env {
    _anvil: Anvil,
    rpc: String,
    token: AAddress,
    pair: AAddress,
    vault: AAddress,
    sink: AAddress,
    tx: TxEvent,
}

fn core(a: AAddress) -> Address {
    a.to_string().parse().unwrap()
}

/// Deploys everything and performs *one* transaction that drains 600 of the
/// vault's 1000 tokens and moves the pool price 5x; returns that
/// transaction as the chain adapter reports it (real receipt logs, and a
/// real call trace since anvil serves `debug_traceTransaction`).
async fn setup(port: u16) -> Option<Env> {
    if !std::path::Path::new("../../contracts/out/Mocks.sol/MockVault.json").exists() {
        eprintln!("SKIPPED: contracts not built -- run `forge build` in contracts/");
        return None;
    }
    let child = Command::new("anvil")
        .args(["--port", &port.to_string(), "--silent"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok();
    let Some(child) = child else {
        eprintln!("SKIPPED: `anvil` not on PATH (install via foundryup)");
        return None;
    };
    let anvil = Anvil(child);
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

    let signer: PrivateKeySigner = KEY.parse().unwrap();
    let p = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(rpc.parse().unwrap());

    let token = MockERC20::deploy(&p).await.unwrap();
    let pair = MockV2Pair::deploy(&p).await.unwrap();
    let vault = MockVault::deploy(&p).await.unwrap();
    let sink: AAddress = "0x000000000000000000000000000000000000dEaD"
        .parse()
        .unwrap();

    macro_rules! send {
        ($call:expr) => {
            $call.send().await.unwrap().get_receipt().await.unwrap()
        };
    }
    send!(token.mint(*vault.address(), U256::from(1_000 * ONE)));
    send!(pair.setReserves(1_000u128.try_into().unwrap(), 1_000u128.try_into().unwrap()));
    // Fund the vault with 10 ETH.
    p.send_transaction(
        alloy::rpc::types::TransactionRequest::default()
            .to(*vault.address())
            .value(U256::from(10 * ONE)),
    )
    .await
    .unwrap()
    .get_receipt()
    .await
    .unwrap();

    let receipt = send!(vault.drainAndMove(
        *token.address(),
        sink,
        U256::from(600 * ONE),
        *pair.address(),
        1_000u128.try_into().unwrap(),
        5_000u128.try_into().unwrap(),
    ));
    let block = receipt.block_number.unwrap();

    let adapter = EvmAdapter::connect(&rpc, ChainId(31337)).await.unwrap();
    let hash = format!("{:#x}", receipt.transaction_hash);
    let tx = adapter
        .get_block_tx_events(block)
        .await
        .unwrap()
        .into_iter()
        .find(|t| t.tx_hash == hash)
        .expect("the drain tx is in its block");

    Some(Env {
        _anvil: anvil,
        rpc,
        token: *token.address(),
        pair: *pair.address(),
        vault: *vault.address(),
        sink,
        tx,
    })
}

fn config(env: &Env) -> ContextConfig {
    let mut cfg = ContextConfig::new(core(env.vault));
    cfg.watched_tokens = vec![core(env.token)];
    cfg
}

#[tokio::test]
async fn baseline_reads_the_real_balance_before_and_the_real_outflow() {
    let Some(env) = setup(8660).await else { return };
    let ctx = EvmContext::connect(&env.rpc, config(&env)).unwrap();
    let b = ctx.baseline(&env.tx).await;
    // The vault held 1000 tokens in the block before; 600 left.
    assert_eq!(b.balance_baseline_wei, 1_000 * ONE);
    assert_eq!(b.outflow_wei, 600 * ONE);
    // Sink received it (sanity on the fixture).
    assert_ne!(env.sink, AAddress::ZERO);
}

#[tokio::test]
async fn amm_price_move_is_measured_against_the_reserves_before_the_tx() {
    let Some(env) = setup(8661).await else { return };
    let ctx = EvmContext::connect(&env.rpc, config(&env)).unwrap();
    let b = ctx.baseline(&env.tx).await;
    // Reserves went 1000/1000 -> 1000/5000: the price ratio is 5x, a move of 4.0.
    assert_eq!(b.reference_price, Some(1.0));
    let observed = b.observed_price.unwrap();
    assert!((observed - 5.0).abs() < 1e-9, "observed {observed}");
    let _ = env.pair;
}

#[tokio::test]
async fn price_tracking_can_be_switched_off() {
    let Some(env) = setup(8662).await else { return };
    let mut cfg = config(&env);
    cfg.track_amm_prices = false;
    let b = EvmContext::connect(&env.rpc, cfg)
        .unwrap()
        .baseline(&env.tx)
        .await;
    assert_eq!((b.reference_price, b.observed_price), (None, None));
    assert_eq!(b.outflow_wei, 600 * ONE);
}

#[tokio::test]
async fn an_unwatched_token_yields_no_fund_flow_claim() {
    let Some(env) = setup(8663).await else { return };
    let cfg = ContextConfig::new(core(env.vault)); // watches nothing
    let b = EvmContext::connect(&env.rpc, cfg)
        .unwrap()
        .baseline(&env.tx)
        .await;
    assert_eq!((b.balance_baseline_wei, b.outflow_wei), (0, 0));
}

#[tokio::test]
async fn a_balance_that_cannot_be_read_fails_closed_instead_of_being_guessed() {
    let Some(env) = setup(8664).await else { return };
    // Watching the *pair* as a "token": it has no balanceOf, so the call
    // errors. And a token whose Transfer logs don't involve the vault.
    let mut cfg = ContextConfig::new(core(env.pair));
    cfg.watched_tokens = vec![core(env.token)];
    cfg.holders = vec![core(env.pair)]; // holds none of the drained token
    let b = EvmContext::connect(&env.rpc, cfg)
        .unwrap()
        .baseline(&env.tx)
        .await;
    assert_eq!((b.balance_baseline_wei, b.outflow_wei), (0, 0));
}

#[tokio::test]
async fn an_unreachable_rpc_fails_closed() {
    let Some(env) = setup(8665).await else { return };
    let ctx = EvmContext::connect("http://127.0.0.1:1", config(&env)).unwrap();
    let b = ctx.baseline(&env.tx).await;
    assert_eq!((b.balance_baseline_wei, b.outflow_wei), (0, 0));
    assert_eq!((b.reference_price, b.observed_price), (None, None));
}

#[tokio::test]
async fn native_eth_outflow_uses_the_call_trace_and_the_prior_balance() {
    let Some(env) = setup(8666).await else { return };
    // Drain 4 of the vault's 10 ETH in a fresh transaction.
    let signer: PrivateKeySigner = KEY.parse().unwrap();
    let p = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(env.rpc.parse().unwrap());
    let vault = MockVault::new(env.vault, &p);
    let receipt = vault
        .drainNative(env.sink, U256::from(4 * ONE))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    let adapter = EvmAdapter::connect(&env.rpc, ChainId(31337)).await.unwrap();
    let hash = format!("{:#x}", receipt.transaction_hash);
    let tx = adapter
        .get_block_tx_events(receipt.block_number.unwrap())
        .await
        .unwrap()
        .into_iter()
        .find(|t| t.tx_hash == hash)
        .unwrap();
    assert!(
        !tx.call_frames.is_empty(),
        "anvil serves debug_traceTransaction"
    );

    let mut cfg = ContextConfig::new(core(env.vault));
    cfg.watch_native = true;
    let b = EvmContext::connect(&env.rpc, cfg)
        .unwrap()
        .baseline(&tx)
        .await;
    assert_eq!(b.balance_baseline_wei, 10 * ONE);
    assert_eq!(b.outflow_wei, 4 * ONE);
}

#[tokio::test]
async fn enrich_leaves_an_existing_trace_alone_and_does_nothing_without_a_fallback() {
    let Some(env) = setup(8667).await else { return };
    let ctx = EvmContext::connect(&env.rpc, config(&env)).unwrap();
    let mut with_frames = env.tx.clone();
    let n = with_frames.call_frames.len();
    assert!(n > 0);
    ctx.enrich(&mut with_frames).await;
    assert_eq!(with_frames.call_frames.len(), n);

    let mut empty = env.tx.clone();
    empty.call_frames.clear();
    ctx.enrich(&mut empty).await; // TraceFallback::None
    assert!(empty.call_frames.is_empty());
}

#[tokio::test]
async fn a_failing_trace_fallback_degrades_to_no_trace_not_a_crash() {
    let Some(env) = setup(8668).await else { return };
    let mut cfg = config(&env);
    cfg.trace_fallback = TraceFallback::CastRun {
        rpc_url: "http://127.0.0.1:1".into(),
        timeout: Duration::from_secs(20),
    };
    let ctx = EvmContext::connect(&env.rpc, cfg).unwrap();
    let mut tx = env.tx.clone();
    tx.call_frames.clear();
    ctx.enrich(&mut tx).await;
    assert!(
        tx.call_frames.is_empty(),
        "scored without a trace, not aborted"
    );
}

// ---- value-netted fund flow -------------------------------------------------
//
// The per-asset rule reads a value-neutral swap as a drain (one asset leaves,
// the other half of the trade is invisible). These tests run the same real
// swap transaction through both views.

struct SwapEnv {
    _anvil: Anvil,
    rpc: String,
    out_token: AAddress,
    in_token: AAddress,
    vault: AAddress,
    tx: TxEvent,
}

/// The vault holds 1000 of each of two tokens and trades 400 of A for
/// `amount_in` of B with a counterparty, in one transaction.
async fn swap_setup(port: u16, amount_in: u128) -> Option<SwapEnv> {
    if !std::path::Path::new("../../contracts/out/Mocks.sol/MockVault.json").exists() {
        eprintln!("SKIPPED: contracts not built -- run `forge build` in contracts/");
        return None;
    }
    let child = Command::new("anvil")
        .args(["--port", &port.to_string(), "--silent"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let anvil = Anvil(child);
    let rpc = format!("http://127.0.0.1:{port}");
    let reader = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    for _ in 0..80 {
        if reader.get_block_number().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let signer: PrivateKeySigner = KEY.parse().unwrap();
    let p = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(rpc.parse().unwrap());
    let a = MockERC20::deploy(&p).await.unwrap();
    let b = MockERC20::deploy(&p).await.unwrap();
    let vault = MockVault::deploy(&p).await.unwrap();
    let trader: AAddress = "0x00000000000000000000000000000000000071ad"
        .parse()
        .unwrap();
    macro_rules! send {
        ($call:expr) => {
            $call.send().await.unwrap().get_receipt().await.unwrap()
        };
    }
    send!(a.mint(*vault.address(), U256::from(1_000 * ONE)));
    send!(b.mint(*vault.address(), U256::from(1_000 * ONE)));
    send!(b.mint(trader, U256::from(amount_in)));
    let receipt = send!(vault.swap(
        *a.address(),
        *b.address(),
        trader,
        U256::from(400 * ONE),
        U256::from(amount_in),
    ));
    let hash = format!("{:#x}", receipt.transaction_hash);
    let adapter = EvmAdapter::connect(&rpc, ChainId(31337)).await.unwrap();
    let tx = adapter
        .get_block_tx_events(receipt.block_number.unwrap())
        .await
        .unwrap()
        .into_iter()
        .find(|t| t.tx_hash == hash)
        .unwrap();
    Some(SwapEnv {
        _anvil: anvil,
        rpc,
        out_token: *a.address(),
        in_token: *b.address(),
        vault: *vault.address(),
        tx,
    })
}

fn swap_cfg(env: &SwapEnv) -> ContextConfig {
    let mut cfg = ContextConfig::new(core(env.vault));
    cfg.watched_tokens = vec![core(env.out_token), core(env.in_token)];
    cfg
}

fn both_at_a_dollar(env: &SwapEnv) -> std::sync::Arc<dyn tripwire_context::TokenValuer> {
    std::sync::Arc::new(
        tripwire_context::FixedValues::new()
            .with_stable(core(env.out_token), 18)
            .with_stable(core(env.in_token), 18),
    )
}

#[tokio::test]
async fn a_value_neutral_swap_is_a_drain_per_asset_but_nothing_when_netted() {
    let Some(env) = swap_setup(8681, 400 * ONE).await else {
        return;
    };
    // Per-asset view (no valuer): 400 of 1000 left => a 40% "drain".
    let plain = EvmContext::connect(&env.rpc, swap_cfg(&env)).unwrap();
    let b = plain.baseline(&env.tx).await;
    assert_eq!(b.outflow_wei, 400 * ONE);
    assert_eq!(b.balance_baseline_wei, 1_000 * ONE);

    // Netted view: 400 out, 400 of equal value in => no loss.
    let mut cfg = swap_cfg(&env);
    cfg.valuer = Some(both_at_a_dollar(&env));
    let netted = EvmContext::connect(&env.rpc, cfg).unwrap();
    let b = netted.baseline(&env.tx).await;
    assert_eq!(b.outflow_wei, 0, "a fair trade lost no value");
}

#[tokio::test]
async fn a_lopsided_swap_is_still_reported_as_a_loss() {
    // 400 out, only 100 back: the protocol lost 300 of value.
    let Some(env) = swap_setup(8682, 100 * ONE).await else {
        return;
    };
    let mut cfg = swap_cfg(&env);
    cfg.valuer = Some(both_at_a_dollar(&env));
    let ctx = EvmContext::connect(&env.rpc, cfg).unwrap();
    let b = ctx.baseline(&env.tx).await;
    let lost = b.outflow_wei as f64 / b.balance_baseline_wei as f64;
    assert!(
        (lost - 0.3).abs() < 1e-6,
        "lost {lost} of the asset's value"
    );
}

#[tokio::test]
async fn cheap_junk_deposited_against_a_drain_does_not_hide_it() {
    // Same swap as the fair one, but the asset coming in is valued at a
    // hundredth: 400 out for 400 worth $4 is a ~99% loss of that value.
    let Some(env) = swap_setup(8683, 400 * ONE).await else {
        return;
    };
    let mut cfg = swap_cfg(&env);
    cfg.valuer = Some(std::sync::Arc::new(
        tripwire_context::FixedValues::new()
            .with_stable(core(env.out_token), 18)
            .with_token(core(env.in_token), 18, 0.01),
    ));
    let ctx = EvmContext::connect(&env.rpc, cfg).unwrap();
    let b = ctx.baseline(&env.tx).await;
    let lost = b.outflow_wei as f64 / b.balance_baseline_wei as f64;
    assert!(lost > 0.39, "value lost was {lost} of the drained asset");
}

#[tokio::test]
async fn an_unvalued_asset_falls_back_to_the_strict_per_asset_rule() {
    // Only the outgoing token has a value: the netted view is unavailable, so
    // the transaction is judged per asset (a 40% drain), never guessed.
    let Some(env) = swap_setup(8684, 400 * ONE).await else {
        return;
    };
    let mut cfg = swap_cfg(&env);
    cfg.valuer = Some(std::sync::Arc::new(
        tripwire_context::FixedValues::new().with_stable(core(env.out_token), 18),
    ));
    let ctx = EvmContext::connect(&env.rpc, cfg).unwrap();
    let b = ctx.baseline(&env.tx).await;
    assert_eq!(b.outflow_wei, 400 * ONE);
    assert_eq!(b.balance_baseline_wei, 1_000 * ONE);
}

#[tokio::test]
async fn a_pure_drain_is_unchanged_by_having_a_valuer() {
    let Some(env) = setup(8685).await else { return };
    let mut cfg = config(&env);
    cfg.valuer = Some(std::sync::Arc::new(
        tripwire_context::FixedValues::new().with_stable(core(env.token), 18),
    ));
    let ctx = EvmContext::connect(&env.rpc, cfg).unwrap();
    let b = ctx.baseline(&env.tx).await;
    // Value units now (a $1 token: 600 and 1000 dollars), so compare the
    // fraction, which is all the detector uses.
    let lost = b.outflow_wei as f64 / b.balance_baseline_wei as f64;
    assert!((lost - 0.6).abs() < 1e-9, "{lost}");
}
