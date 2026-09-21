use tripwire_core::{CallFrame, ConditionKind, TxEvent};

/// External context a condition evaluator needs beyond what's in a raw
/// `TxEvent` — a protocol balance baseline, a reference oracle price, a
/// governance voting-power baseline. Computing these values from chain
/// state is the caller's job (the `chain-adapter`/daemon layer); this
/// crate stays chain-agnostic and only reasons about the numbers once
/// they're in hand, per ARCHITECTURE.md §3.1's trait boundary.
#[derive(Debug, Clone, Default)]
pub struct Baseline {
    /// The watched contract's balance (wei) at the start of the
    /// signature's evaluation window — the denominator for
    /// `FundFlowDelta`. When the context source values assets it is in the
    /// valuer's common *value unit* rather than raw token units; only the
    /// ratio to `outflow_wei` is ever used.
    pub balance_baseline_wei: u128,
    /// Net value that left the watched contract during this transaction,
    /// as computed upstream from the raw call trace.
    pub outflow_wei: u128,
    /// A reference price (TWAP, or an independent second oracle).
    pub reference_price: Option<f64>,
    /// The price this transaction's oracle-reporting call actually
    /// reported.
    pub observed_price: Option<f64>,
    /// Voting power baseline for the address a governance proposal
    /// concerns, before this transaction.
    pub voting_power_baseline: Option<f64>,
    /// Voting power for that same address after this transaction.
    pub observed_voting_power: Option<f64>,
    /// Every contract that belongs to the protocol (markets, comptroller,
    /// vaults, the target). Used to tell a callback *out of* the protocol
    /// and back in from ordinary internal composition. Empty disables
    /// `ProtocolCallbackReentry`.
    pub protocol_addresses: Vec<tripwire_core::Address>,
}

/// Evaluates a single condition against one transaction and its
/// baseline context. This is the one place a new `ConditionKind` variant
/// gets real evaluation logic — matching and scoring above this layer
/// are generic over whatever conditions exist (ARCHITECTURE.md §3.3).
pub fn evaluate(kind: &ConditionKind, tx: &TxEvent, baseline: &Baseline) -> bool {
    match kind {
        ConditionKind::FundFlowDelta { threshold_pct } => {
            evaluate_fund_flow_delta(*threshold_pct, baseline)
        }
        ConditionKind::CallSequence { selectors } => evaluate_call_sequence(selectors, tx),
        ConditionKind::CallAny { selectors } => evaluate_call_any(selectors, tx),
        ConditionKind::OraclePriceDeviation { threshold_pct } => {
            evaluate_oracle_price_deviation(*threshold_pct, baseline)
        }
        ConditionKind::ProtocolCallbackReentry {} => {
            evaluate_protocol_callback_reentry(&baseline.protocol_addresses, tx)
        }
        ConditionKind::ReentrancyDepth { min_depth_delta } => {
            evaluate_reentrancy_depth(*min_depth_delta, tx)
        }
        ConditionKind::GovernanceProposalAnomaly { threshold_pct } => {
            evaluate_governance_anomaly(*threshold_pct, baseline)
        }
    }
}

fn evaluate_fund_flow_delta(threshold_pct: f64, baseline: &Baseline) -> bool {
    if baseline.balance_baseline_wei == 0 {
        // No baseline to compare against: fail closed (not satisfied)
        // rather than divide by zero or treat any outflow as an
        // infinite percentage. A protocol with a genuinely zero balance
        // baseline has bigger problems than a missed signature match.
        return false;
    }
    let pct = (baseline.outflow_wei as f64 / baseline.balance_baseline_wei as f64) * 100.0;
    pct >= threshold_pct
}

fn evaluate_call_sequence(selectors: &[String], tx: &TxEvent) -> bool {
    if selectors.is_empty() {
        return true;
    }
    let observed: Vec<&str> = tx
        .call_frames
        .iter()
        .filter_map(|f| f.selector.as_deref())
        .collect();
    if observed.len() < selectors.len() {
        return false;
    }
    observed.windows(selectors.len()).any(|window| {
        window
            .iter()
            .zip(selectors.iter())
            .all(|(o, s)| o.eq_ignore_ascii_case(s))
    })
}

fn evaluate_call_any(selectors: &[String], tx: &TxEvent) -> bool {
    // An empty set can never be satisfied: "any of nothing" is false, so a
    // misconfigured signature fails closed instead of matching everything.
    tx.call_frames.iter().any(|f| {
        f.kind.is_message_call()
            && f.selector
                .as_deref()
                .is_some_and(|s| selectors.iter().any(|w| w.eq_ignore_ascii_case(s)))
    })
}

fn evaluate_oracle_price_deviation(threshold_pct: f64, baseline: &Baseline) -> bool {
    match (baseline.reference_price, baseline.observed_price) {
        (Some(reference), Some(observed)) if reference > 0.0 => {
            let deviation_pct = ((observed - reference).abs() / reference) * 100.0;
            deviation_pct >= threshold_pct
        }
        _ => false,
    }
}

/// Real reentrancy: a state-changing call to `(target, selector)` is made
/// while an *earlier, still-active* call to that same `(target,
/// selector)` is on the call stack at least `min_depth_delta` levels up.
///
/// Two properties matter, both found by scoring a real exploit trace (the
/// Beanstalk transaction) with the previous version of this check, which
/// flagged 36 "recurrences" in a trace containing no reentrancy:
///
/// * The earlier call must be an *ancestor* of the later one, not merely
///   something that appeared earlier in the trace. A call that already
///   returned cannot be re-entered. Ancestry is reconstructed from the
///   pre-order frame list and `depth`: a frame's active ancestors are the
///   most recent frame at each shallower depth.
/// * Read-only `STATICCALL` frames are ignored on both sides. They cannot
///   modify state, so repeated `balanceOf`/`totalSupply` lookups are not
///   re-entry. Frames without a selector are ignored too: there is no
///   function identity to compare.
///
/// Assumes `tx.call_frames` is in execution (pre-order) order with
/// accurate depths, which both trace sources guarantee.
fn evaluate_reentrancy_depth(min_depth_delta: u32, tx: &TxEvent) -> bool {
    // Active call stack: one frame per depth level, deepest last.
    let mut stack: Vec<&CallFrame> = Vec::new();
    for frame in &tx.call_frames {
        // Leaving deeper subtrees: drop everything at or below this depth.
        while stack.last().is_some_and(|top| top.depth >= frame.depth) {
            stack.pop();
        }
        if !frame.kind.is_static() && frame.selector.is_some() {
            let reenters = stack.iter().any(|ancestor| {
                !ancestor.kind.is_static()
                    && ancestor.to == frame.to
                    && ancestor.selector == frame.selector
                    && frame.depth >= ancestor.depth + min_depth_delta
            });
            if reenters {
                return true;
            }
        }
        stack.push(frame);
    }
    false
}

/// Callback re-entry across protocol contracts. Walks the pre-order frame
/// list keeping the active call stack (as `evaluate_reentrancy_depth`), and
/// fires when a state-changing call into a protocol contract `f` has, among
/// its active ancestors, both
///
/// * an earlier state-changing call `a` into a protocol contract, and
/// * between `a` and `f`, a real (non-delegate, non-static) call whose
///   target lies *outside* the protocol -- the call out of the protocol.
///
/// `DELEGATECALL` frames are internal to the protocol (proxy -> implementation)
/// and are neither the outside contract nor a re-entry. Read-only calls are
/// ignored on both sides.
fn evaluate_protocol_callback_reentry(protocol: &[tripwire_core::Address], tx: &TxEvent) -> bool {
    if protocol.is_empty() {
        return false;
    }
    let inside = |a: &tripwire_core::Address| protocol.contains(a);
    let mut stack: Vec<&CallFrame> = Vec::new();
    for frame in &tx.call_frames {
        while stack.last().is_some_and(|top| top.depth >= frame.depth) {
            stack.pop();
        }
        if !frame.kind.is_static() && !frame.kind.is_delegate() && inside(&frame.to) {
            // Find the shallowest active protocol call, then look for an
            // outside call below it.
            let first_in = stack
                .iter()
                .position(|a| !a.kind.is_static() && !a.kind.is_delegate() && inside(&a.to));
            if let Some(i) = first_in {
                let callout = stack[i + 1..]
                    .iter()
                    .any(|c| !c.kind.is_static() && !c.kind.is_delegate() && !inside(&c.to));
                if callout {
                    return true;
                }
            }
        }
        stack.push(frame);
    }
    false
}

fn evaluate_governance_anomaly(threshold_pct: f64, baseline: &Baseline) -> bool {
    match (
        baseline.voting_power_baseline,
        baseline.observed_voting_power,
    ) {
        (Some(base), Some(observed)) if base > 0.0 => {
            let pct_increase = ((observed - base) / base) * 100.0;
            pct_increase >= threshold_pct
        }
        (Some(0.0), Some(observed)) => observed > 0.0,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tripwire_core::{Address, CallKind, ChainId};

    fn empty_tx() -> TxEvent {
        TxEvent {
            chain: ChainId::ETHEREUM_MAINNET,
            tx_hash: "0x1".into(),
            block_number: 1,
            confirmations: 0,
            from: Address::ZERO,
            to: None,
            value_wei: 0,
            logs: vec![],
            call_frames: vec![],
            timestamp_unix: 0,
        }
    }

    fn frame(depth: u32, to: &str, selector: Option<&str>) -> CallFrame {
        frame_k(depth, to, selector, CallKind::Call)
    }

    fn frame_k(depth: u32, to: &str, selector: Option<&str>, kind: CallKind) -> CallFrame {
        CallFrame {
            depth,
            from: Address::ZERO,
            to: Address::from_str(to).unwrap(),
            selector: selector.map(String::from),
            value_wei: 0,
            kind,
        }
    }

    const VAULT: &str = "0x0000000000000000000000000000000000000002";
    const OTHER: &str = "0x0000000000000000000000000000000000000003";

    // --- fund flow delta ---

    #[test]
    fn fund_flow_fails_closed_with_zero_baseline() {
        let baseline = Baseline {
            balance_baseline_wei: 0,
            outflow_wei: 1_000_000,
            ..Default::default()
        };
        assert!(!evaluate_fund_flow_delta(1.0, &baseline));
    }

    #[test]
    fn fund_flow_below_threshold_does_not_fire() {
        let baseline = Baseline {
            balance_baseline_wei: 1_000_000,
            outflow_wei: 10_000, // 1%
            ..Default::default()
        };
        assert!(!evaluate_fund_flow_delta(50.0, &baseline));
    }

    #[test]
    fn fund_flow_at_exact_threshold_fires() {
        let baseline = Baseline {
            balance_baseline_wei: 1_000_000,
            outflow_wei: 500_000, // exactly 50%
            ..Default::default()
        };
        assert!(evaluate_fund_flow_delta(50.0, &baseline));
    }

    #[test]
    fn small_legitimate_withdrawal_does_not_fire_high_threshold() {
        // A normal user withdrawal: 2% of TVL. Should not look like a drain.
        let baseline = Baseline {
            balance_baseline_wei: 10_000_000,
            outflow_wei: 200_000,
            ..Default::default()
        };
        assert!(!evaluate_fund_flow_delta(80.0, &baseline));
    }

    // --- call sequence ---

    #[test]
    fn call_sequence_matches_contiguous_in_order() {
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xaaaaaaaa")),
            frame(1, VAULT, Some("0xbbbbbbbb")),
            frame(2, VAULT, Some("0xcccccccc")),
        ];
        assert!(evaluate_call_sequence(
            &["0xaaaaaaaa".into(), "0xbbbbbbbb".into()],
            &tx
        ));
    }

    #[test]
    fn call_sequence_does_not_match_wrong_order() {
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xbbbbbbbb")),
            frame(1, VAULT, Some("0xaaaaaaaa")),
        ];
        assert!(!evaluate_call_sequence(
            &["0xaaaaaaaa".into(), "0xbbbbbbbb".into()],
            &tx
        ));
    }

    #[test]
    fn call_sequence_does_not_match_non_contiguous() {
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xaaaaaaaa")),
            frame(1, VAULT, Some("0xdddddddd")),
            frame(2, VAULT, Some("0xbbbbbbbb")),
        ];
        assert!(!evaluate_call_sequence(
            &["0xaaaaaaaa".into(), "0xbbbbbbbb".into()],
            &tx
        ));
    }

    #[test]
    fn call_sequence_is_case_insensitive() {
        let mut tx = empty_tx();
        tx.call_frames = vec![frame(0, VAULT, Some("0xAAAAAAAA"))];
        assert!(evaluate_call_sequence(&["0xaaaaaaaa".into()], &tx));
    }

    #[test]
    fn call_sequence_empty_selectors_trivially_matches() {
        let tx = empty_tx();
        assert!(evaluate_call_sequence(&[], &tx));
    }

    #[test]
    fn call_sequence_no_match_on_empty_call_frames() {
        let tx = empty_tx();
        assert!(!evaluate_call_sequence(&["0xaaaaaaaa".into()], &tx));
    }

    // --- call_any ---

    #[test]
    fn call_any_matches_when_any_listed_selector_is_called() {
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xaaaaaaaa")),
            frame(1, VAULT, Some("0xbbbbbbbb")),
        ];
        assert!(evaluate_call_any(
            &["0xbbbbbbbb".into(), "0xcccccccc".into()],
            &tx
        ));
        assert!(
            evaluate_call_any(&["0xBBBBBBBB".into()], &tx),
            "case-insensitive"
        );
    }

    #[test]
    fn call_any_does_not_match_unlisted_selectors_or_empty_sets() {
        let mut tx = empty_tx();
        tx.call_frames = vec![frame(0, VAULT, Some("0xaaaaaaaa"))];
        assert!(!evaluate_call_any(&["0xdddddddd".into()], &tx));
        assert!(!evaluate_call_any(&[], &tx), "an empty set fails closed");
        assert!(
            !evaluate_call_any(&["0xaaaaaaaa".into()], &empty_tx()),
            "no frames"
        );
    }

    #[test]
    fn call_any_ignores_create_frames_whose_data_is_initcode() {
        let mut tx = empty_tx();
        tx.call_frames = vec![frame_k(0, VAULT, Some("0x60806040"), CallKind::Create)];
        assert!(!evaluate_call_any(&["0x60806040".into()], &tx));
    }

    // --- oracle price deviation ---

    #[test]
    fn oracle_deviation_fires_on_large_spike() {
        let baseline = Baseline {
            reference_price: Some(100.0),
            observed_price: Some(150.0), // +50%
            ..Default::default()
        };
        assert!(evaluate_oracle_price_deviation(30.0, &baseline));
    }

    #[test]
    fn oracle_deviation_fires_on_large_drop_via_abs_value() {
        let baseline = Baseline {
            reference_price: Some(100.0),
            observed_price: Some(40.0), // -60%
            ..Default::default()
        };
        assert!(evaluate_oracle_price_deviation(30.0, &baseline));
    }

    #[test]
    fn oracle_deviation_does_not_fire_on_normal_market_move() {
        let baseline = Baseline {
            reference_price: Some(100.0),
            observed_price: Some(103.0), // +3%, ordinary volatility
            ..Default::default()
        };
        assert!(!evaluate_oracle_price_deviation(20.0, &baseline));
    }

    #[test]
    fn oracle_deviation_fails_closed_when_data_missing() {
        let baseline = Baseline::default();
        assert!(!evaluate_oracle_price_deviation(1.0, &baseline));
    }

    #[test]
    fn oracle_deviation_fails_closed_on_zero_reference() {
        let baseline = Baseline {
            reference_price: Some(0.0),
            observed_price: Some(10.0),
            ..Default::default()
        };
        assert!(!evaluate_oracle_price_deviation(1.0, &baseline));
    }

    // --- reentrancy depth ---

    #[test]
    fn reentrancy_fires_when_same_target_selector_recurs_deeper() {
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xwithdraw")),
            frame(1, OTHER, Some("0xfallback")),
            frame(2, VAULT, Some("0xwithdraw")), // reenters withdraw() one level deeper
        ];
        assert!(evaluate_reentrancy_depth(1, &tx));
    }

    #[test]
    fn reentrancy_does_not_fire_for_different_selector() {
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xwithdraw")),
            frame(1, VAULT, Some("0xdeposit")), // different function, not reentrancy
        ];
        assert!(!evaluate_reentrancy_depth(1, &tx));
    }

    #[test]
    fn reentrancy_does_not_fire_for_different_target() {
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xwithdraw")),
            frame(1, OTHER, Some("0xwithdraw")), // same selector, different contract
        ];
        assert!(!evaluate_reentrancy_depth(1, &tx));
    }

    #[test]
    fn reentrancy_respects_min_depth_delta_boundary() {
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xwithdraw")),
            frame(1, VAULT, Some("0xwithdraw")), // only 1 deeper
        ];
        assert!(evaluate_reentrancy_depth(1, &tx));
        assert!(!evaluate_reentrancy_depth(2, &tx));
    }

    #[test]
    fn nested_legitimate_calls_do_not_look_like_reentrancy() {
        // A normal multi-hop swap: A -> B -> C, no repeated (to, selector).
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xswap")),
            frame(1, OTHER, Some("0xtransfer")),
            frame(
                2,
                "0x0000000000000000000000000000000000000004",
                Some("0xtransfer"),
            ),
        ];
        assert!(!evaluate_reentrancy_depth(1, &tx));
    }

    // --- reentrancy: ancestry and read-only calls ---

    #[test]
    fn reentrancy_requires_the_earlier_call_to_still_be_active() {
        // V.withdraw returns inside A's subtree, then V.withdraw runs
        // again deeper inside B's subtree. The first call had already
        // finished, so nothing was re-entered. (The previous check keyed
        // only on "seen earlier at a shallower depth" and fired here.)
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, OTHER, Some("0xroot")),
            frame(1, OTHER, Some("0xaaaa")),
            frame(2, VAULT, Some("0xwithdraw")),
            frame(1, OTHER, Some("0xbbbb")),
            frame(2, OTHER, Some("0xcccc")),
            frame(3, VAULT, Some("0xwithdraw")),
        ];
        assert!(!evaluate_reentrancy_depth(1, &tx));
    }

    #[test]
    fn reentrancy_fires_when_the_earlier_call_is_an_active_ancestor() {
        // Same shape, but the second withdraw is nested inside the first.
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, OTHER, Some("0xroot")),
            frame(1, VAULT, Some("0xwithdraw")),
            frame(2, OTHER, Some("0xfallback")),
            frame(3, VAULT, Some("0xwithdraw")),
        ];
        assert!(evaluate_reentrancy_depth(1, &tx));
    }

    #[test]
    fn sibling_repeats_at_the_same_depth_are_not_reentrancy() {
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, OTHER, Some("0xroot")),
            frame(1, VAULT, Some("0xtransfer")),
            frame(1, VAULT, Some("0xtransfer")),
        ];
        assert!(!evaluate_reentrancy_depth(1, &tx));
    }

    #[test]
    fn repeated_read_only_staticcalls_are_not_reentrancy() {
        // The shape that produced 36 false matches on the real Beanstalk
        // trace: the same view function on the same token, nested deeper.
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame_k(0, VAULT, Some("0x70a08231"), CallKind::StaticCall),
            frame_k(1, VAULT, Some("0x70a08231"), CallKind::StaticCall),
            frame_k(2, VAULT, Some("0x70a08231"), CallKind::StaticCall),
        ];
        assert!(!evaluate_reentrancy_depth(1, &tx));
    }

    #[test]
    fn a_staticcall_cannot_be_the_reentering_call_or_the_reentered_one() {
        let mut tx = empty_tx();
        // state-changing ancestor, static re-entry
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xwithdraw")),
            frame_k(1, VAULT, Some("0xwithdraw"), CallKind::StaticCall),
        ];
        assert!(!evaluate_reentrancy_depth(1, &tx));
        // static ancestor, state-changing re-entry
        tx.call_frames = vec![
            frame_k(0, VAULT, Some("0xwithdraw"), CallKind::StaticCall),
            frame(1, VAULT, Some("0xwithdraw")),
        ];
        assert!(!evaluate_reentrancy_depth(1, &tx));
    }

    #[test]
    fn delegatecall_reentry_into_the_same_target_still_counts() {
        // Only STATICCALL is exempt: a DELEGATECALL can modify state.
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xwithdraw")),
            frame_k(1, VAULT, Some("0xwithdraw"), CallKind::DelegateCall),
        ];
        assert!(evaluate_reentrancy_depth(1, &tx));
    }

    #[test]
    fn frames_without_a_selector_are_ignored_by_reentrancy() {
        let mut tx = empty_tx();
        tx.call_frames = vec![frame(0, VAULT, None), frame(1, VAULT, None)];
        assert!(!evaluate_reentrancy_depth(1, &tx));
    }

    #[test]
    fn deep_reentrancy_two_levels_below_the_original_call_is_found() {
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xwithdraw")),
            frame(1, OTHER, Some("0xhook")),
            frame(2, VAULT, Some("0xdeposit")),
            frame(3, OTHER, Some("0xhook")),
            frame(4, VAULT, Some("0xwithdraw")),
        ];
        assert!(evaluate_reentrancy_depth(1, &tx));
        assert!(evaluate_reentrancy_depth(4, &tx));
        assert!(!evaluate_reentrancy_depth(5, &tx));
    }

    // --- governance anomaly ---

    #[test]
    fn governance_anomaly_fires_on_flash_loaned_voting_power() {
        let baseline = Baseline {
            voting_power_baseline: Some(1_000.0),
            observed_voting_power: Some(1_000_000.0), // massive spike
            ..Default::default()
        };
        assert!(evaluate_governance_anomaly(100.0, &baseline));
    }

    #[test]
    fn governance_anomaly_fires_when_baseline_is_zero_and_power_appears() {
        let baseline = Baseline {
            voting_power_baseline: Some(0.0),
            observed_voting_power: Some(500.0),
            ..Default::default()
        };
        assert!(evaluate_governance_anomaly(10.0, &baseline));
    }

    #[test]
    fn governance_anomaly_does_not_fire_on_normal_delegation() {
        let baseline = Baseline {
            voting_power_baseline: Some(10_000.0),
            observed_voting_power: Some(10_500.0), // +5%, ordinary
            ..Default::default()
        };
        assert!(!evaluate_governance_anomaly(50.0, &baseline));
    }

    #[test]
    fn governance_anomaly_fails_closed_when_data_missing() {
        assert!(!evaluate_governance_anomaly(1.0, &Baseline::default()));
    }

    // --- protocol callback re-entry ---

    const MARKET: &str = "0x0000000000000000000000000000000000000010";
    const COMPTROLLER: &str = "0x0000000000000000000000000000000000000011";
    const IMPL: &str = "0x0000000000000000000000000000000000000012";
    const ATTACKER: &str = "0x00000000000000000000000000000000000000aa";
    const TOKEN: &str = "0x00000000000000000000000000000000000000bb";

    fn protocol() -> Vec<Address> {
        vec![
            Address::from_str(MARKET).unwrap(),
            Address::from_str(COMPTROLLER).unwrap(),
        ]
    }

    fn cb(frames: Vec<CallFrame>) -> bool {
        let mut tx = empty_tx();
        tx.call_frames = frames;
        evaluate_protocol_callback_reentry(&protocol(), &tx)
    }

    #[test]
    fn callback_reentry_fires_on_the_rari_shape_through_a_proxy() {
        // attacker -> market.borrow -> (delegatecall impl) -> attacker.receive
        //          -> comptroller.exitMarket
        assert!(cb(vec![
            frame(0, ATTACKER, Some("0xstart")),
            frame(1, MARKET, Some("0xborrow")),
            frame_k(2, IMPL, Some("0xborrow"), CallKind::DelegateCall),
            frame(3, ATTACKER, None),
            frame(4, COMPTROLLER, Some("0xexitMarket")),
        ]));
    }

    #[test]
    fn callback_reentry_needs_a_call_out_of_the_protocol() {
        // market -> comptroller is internal composition, not re-entry.
        assert!(!cb(vec![
            frame(0, ATTACKER, Some("0xstart")),
            frame(1, MARKET, Some("0xborrow")),
            frame(2, COMPTROLLER, Some("0xborrowAllowed")),
        ]));
        // Proxy -> implementation is not a call out either.
        assert!(!cb(vec![
            frame(0, MARKET, Some("0xborrow")),
            frame_k(1, IMPL, Some("0xborrow"), CallKind::DelegateCall),
            frame(2, COMPTROLLER, Some("0xborrowAllowed")),
        ]));
    }

    #[test]
    fn a_call_out_that_does_not_call_back_is_not_reentry() {
        // market -> token.transfer, returns; later a separate protocol call.
        assert!(!cb(vec![
            frame(0, ATTACKER, Some("0xstart")),
            frame(1, MARKET, Some("0xredeem")),
            frame(2, TOKEN, Some("0xtransfer")),
            frame(1, COMPTROLLER, Some("0xredeemVerify")),
        ]));
    }

    #[test]
    fn callback_reentry_ignores_read_only_calls_back_in() {
        assert!(!cb(vec![
            frame(0, MARKET, Some("0xborrow")),
            frame(1, ATTACKER, None),
            frame_k(
                2,
                COMPTROLLER,
                Some("0xgetAccountLiquidity"),
                CallKind::StaticCall
            ),
        ]));
    }

    #[test]
    fn callback_reentry_is_inert_without_a_protocol_set() {
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, MARKET, Some("0xborrow")),
            frame(1, ATTACKER, None),
            frame(2, COMPTROLLER, Some("0xexitMarket")),
        ];
        assert!(!evaluate_protocol_callback_reentry(&[], &tx));
    }

    #[test]
    fn callback_reentry_finds_the_same_function_too() {
        assert!(cb(vec![
            frame(0, MARKET, Some("0xborrow")),
            frame(1, ATTACKER, None),
            frame(2, MARKET, Some("0xborrow")),
        ]));
    }
}
