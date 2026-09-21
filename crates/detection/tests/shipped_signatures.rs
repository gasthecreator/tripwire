//! Behavioural tests against the *actual shipped* `signatures/*.yaml`,
//! not hand-built fixtures. The evidence-double-counting bug was invisible
//! to fixture-based tests precisely because the fixtures never modelled how
//! the real signature set overlaps: three shipped signatures each contain an
//! outflow condition, so one large outflow scored 60 + 40 + 30 and paused.

use std::path::Path;
use std::str::FromStr;

use detection::{evaluate, load_signatures_from_dir, Baseline};
use tripwire_core::{
    Address, CallFrame, CallKind, ChainId, Confidence, PauseDecision, Signature, TxEvent,
};

const VAULT: &str = "0x0000000000000000000000000000000000000002";

fn shipped() -> Vec<Signature> {
    load_signatures_from_dir(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../signatures"))
        .expect("shipped signatures load")
}

fn frame(depth: u32, selector: &str, kind: CallKind) -> CallFrame {
    CallFrame {
        depth,
        from: Address::ZERO,
        to: Address::from_str(VAULT).unwrap(),
        selector: Some(selector.into()),
        value_wei: 0,
        kind,
    }
}

fn tx(frames: Vec<CallFrame>) -> TxEvent {
    TxEvent {
        chain: ChainId::ETHEREUM_MAINNET,
        tx_hash: "0xtx".into(),
        block_number: 1,
        confirmations: 1,
        from: Address::ZERO,
        to: Some(Address::from_str(VAULT).unwrap()),
        value_wei: 0,
        logs: vec![],
        call_frames: frames,
        timestamp_unix: 0,
    }
}

fn outflow_pct(pct: u128) -> Baseline {
    Baseline {
        balance_baseline_wei: 10_000,
        outflow_wei: 100 * pct,
        ..Default::default()
    }
}

fn run(t: &TxEvent, b: &Baseline) -> PauseDecision {
    evaluate(
        &shipped(),
        ChainId::ETHEREUM_MAINNET,
        Address::from_str(VAULT).unwrap(),
        t,
        b,
        Confidence::new(80.0),
        0,
    )
}

#[test]
fn a_large_legitimate_withdrawal_alone_never_pauses() {
    // A whale withdraws a quarter, then all, of a balance with no other
    // suspicious behaviour. One fact, however large, must not pause.
    for pct in [10, 25, 60, 100] {
        let d = run(
            &tx(vec![frame(0, "0xa9059cbb", CallKind::Call)]),
            &outflow_pct(pct),
        );
        assert!(
            !d.should_pause(),
            "{pct}% outflow alone scored {} and would pause",
            d.confidence.value()
        );
        assert!(d.confidence.value() <= 60.0);
    }
}

#[test]
fn outflow_alone_is_counted_as_exactly_one_piece_of_evidence() {
    let d = run(
        &tx(vec![frame(0, "0xa9059cbb", CallKind::Call)]),
        &outflow_pct(100),
    );
    assert!(
        d.matches.len() >= 2,
        "several signatures see the same outflow"
    );
    assert_eq!(d.counted_evidence.len(), 1);
    assert_eq!(d.counted_evidence[0].key, "fund_flow");
    assert_eq!(d.counted_evidence[0].weight, 60.0);
}

#[test]
fn a_real_reentry_plus_a_real_drain_still_pauses() {
    // Corroboration across *different* facts must still work: a call
    // re-entering itself while a large outflow happens.
    let frames = vec![
        frame(0, "0xwithdraw", CallKind::Call),
        frame(1, "0xhook", CallKind::Call),
        frame(2, "0xwithdraw", CallKind::Call),
    ];
    let d = run(&tx(frames), &outflow_pct(50));
    assert!(d.should_pause(), "scored only {}", d.confidence.value());
    let keys: Vec<_> = d.counted_evidence.iter().map(|e| e.key.as_str()).collect();
    assert!(keys.contains(&"fund_flow") && keys.contains(&"reentrancy"));
}

#[test]
fn a_reentry_without_an_outflow_stays_below_threshold() {
    let frames = vec![
        frame(0, "0xwithdraw", CallKind::Call),
        frame(1, "0xhook", CallKind::Call),
        frame(2, "0xwithdraw", CallKind::Call),
    ];
    let d = run(&tx(frames), &Baseline::default());
    assert!(!d.should_pause());
}
