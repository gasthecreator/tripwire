//! Pure fund-flow arithmetic: how much of an asset left a protected
//! contract during one transaction, derived from evidence the transaction
//! itself carries (ERC-20 `Transfer` logs, internal call values). No I/O.

use tripwire_core::{Address, CallFrame, CallKind, LogEvent};

const ERC20_TRANSFER_TOPIC: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

/// Net amount of `token` that left `holder` per ERC-20 `Transfer` logs:
/// transfers out minus transfers in, floored at zero. A flash loan that is
/// borrowed and repaid inside the transaction therefore nets out, while a
/// genuine drain does not.
pub fn erc20_net_outflow(logs: &[LogEvent], token: &Address, holder: &Address) -> u128 {
    let (mut out, mut inn) = (0u128, 0u128);
    for log in logs {
        // ERC-20 Transfer has 3 topics (ERC-721's has 4).
        if &log.address != token
            || log.topics.len() != 3
            || !log.topics[0].eq_ignore_ascii_case(ERC20_TRANSFER_TOPIC)
        {
            continue;
        }
        let value = hex_to_u128_saturating(&log.data);
        if topic_address(&log.topics[1]).as_ref() == Some(holder) {
            out = out.saturating_add(value);
        }
        if topic_address(&log.topics[2]).as_ref() == Some(holder) {
            inn = inn.saturating_add(value);
        }
    }
    out.saturating_sub(inn)
}

/// Net native-currency (ETH) that left `holder` per the call trace: value
/// sent by `holder` in calls and contract creations, minus value received.
/// Needs a call trace; returns 0 without one.
pub fn native_net_outflow(frames: &[CallFrame], holder: &Address) -> u128 {
    let (mut out, mut inn) = (0u128, 0u128);
    for f in frames {
        // Only CALL and CREATE move value between accounts. DELEGATECALL /
        // CALLCODE carry the parent's value as a bookkeeping field, and
        // STATICCALL cannot transfer.
        if !matches!(f.kind, CallKind::Call | CallKind::Create) {
            continue;
        }
        if &f.from == holder {
            out = out.saturating_add(f.value_wei);
        }
        if &f.to == holder {
            inn = inn.saturating_add(f.value_wei);
        }
    }
    out.saturating_sub(inn)
}

/// Total ERC-20 `token` moved out of / into `holder` in this transaction
/// (not netted, unlike [`erc20_net_outflow`]).
pub fn erc20_flows(logs: &[LogEvent], token: &Address, holder: &Address) -> (u128, u128) {
    let (mut out, mut inn) = (0u128, 0u128);
    for log in logs {
        if &log.address != token
            || log.topics.len() != 3
            || !log.topics[0].eq_ignore_ascii_case(ERC20_TRANSFER_TOPIC)
        {
            continue;
        }
        let value = hex_to_u128_saturating(&log.data);
        if topic_address(&log.topics[1]).as_ref() == Some(holder) {
            out = out.saturating_add(value);
        }
        if topic_address(&log.topics[2]).as_ref() == Some(holder) {
            inn = inn.saturating_add(value);
        }
    }
    (out, inn)
}

/// Native value sent from / received by `holder` per the call trace.
pub fn native_flows(frames: &[CallFrame], holder: &Address) -> (u128, u128) {
    let (mut out, mut inn) = (0u128, 0u128);
    for f in frames {
        if !matches!(f.kind, CallKind::Call | CallKind::Create) {
            continue;
        }
        if &f.from == holder {
            out = out.saturating_add(f.value_wei);
        }
        if &f.to == holder {
            inn = inn.saturating_add(f.value_wei);
        }
    }
    (out, inn)
}

/// One asset's movement across the *whole protocol* in one transaction.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TokenMove {
    /// Net amount that left the protocol (negative = net inflow), in raw units.
    pub net_out: i128,
    /// Pre-transaction balance summed over the holders that lost it. Only
    /// meaningful (and only needed) when `net_out > 0`.
    pub balance: u128,
    /// Value of one raw unit, in whatever common unit the valuer uses.
    pub unit_value: f64,
}

/// Net *value* that left the protocol, against the value of the assets it
/// left from.
///
/// The per-asset rule ([`worst_flow`]) reads a value-neutral swap, or a
/// borrow against fresh collateral, as a drain: USDC leaves, USDT arrives,
/// and only the first half is seen. Here every asset's movement is valued
/// and summed, so what is measured is *value lost*:
///
/// `outflow = max(0, sum(net_out_i * value_i))`
/// `baseline = sum over assets with net_out_i > 0 of balance_i * value_i`
///
/// A drain of one asset with nothing coming back is unchanged (outflow over
/// that asset's balance); a swap or a collateral-backed borrow nets toward
/// zero. Returns `None` if nothing net left.
///
/// The caller decides which assets are counted (only the protocol's watched
/// custody assets, so an attacker cannot cancel a drain by depositing
/// something the protocol does not custody) and at which block values are
/// taken (the one *before* the transaction, so a price manipulated inside it
/// cannot inflate a deposit's worth).
pub fn value_netted_flow(moves: &[TokenMove]) -> Option<AssetFlow> {
    let mut net = 0.0f64;
    let mut baseline = 0.0f64;
    for m in moves {
        net += m.net_out as f64 * m.unit_value;
        if m.net_out > 0 {
            baseline += m.balance as f64 * m.unit_value;
        }
    }
    // Values are floats, so exact cancellation leaves rounding dust: treat a
    // loss below one part in a billion of the baseline as no loss.
    if !(net.is_finite() && baseline.is_finite()) || baseline <= 0.0 || net <= baseline * 1e-9 {
        return None;
    }
    Some(AssetFlow {
        balance_before: baseline as u128,
        outflow: net as u128,
    })
}

/// One asset's outflow against the holder's balance just before the tx.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetFlow {
    pub balance_before: u128,
    pub outflow: u128,
}

impl AssetFlow {
    /// Fraction of the pre-transaction balance that left. Zero when there
    /// was no balance to leave (no baseline => no claim).
    pub fn fraction(&self) -> f64 {
        if self.balance_before == 0 {
            0.0
        } else {
            self.outflow as f64 / self.balance_before as f64
        }
    }
}

/// The asset that lost the largest *fraction* of its balance.
///
/// A protocol holds many assets and their amounts aren't comparable without
/// prices, so the signal used is the worst single-asset drain: losing most
/// of any one asset in one transaction is anomalous whatever it is worth.
pub fn worst_flow(flows: &[AssetFlow]) -> Option<AssetFlow> {
    flows
        .iter()
        .filter(|f| f.balance_before > 0 && f.outflow > 0)
        .copied()
        .max_by(|a, b| {
            a.fraction()
                .partial_cmp(&b.fraction())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
}

pub(crate) fn topic_address(topic: &str) -> Option<Address> {
    let hex = topic.trim_start_matches("0x");
    if hex.len() != 64 {
        return None;
    }
    format!("0x{}", &hex[24..]).parse().ok()
}

pub(crate) fn hex_to_u128_saturating(data: &str) -> u128 {
    let hex = data.trim_start_matches("0x").trim_start_matches('0');
    if hex.is_empty() {
        return 0;
    }
    u128::from_str_radix(hex, 16).unwrap_or(u128::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0x6b175474e89094c44da98b954eedeac495271d0f";
    const HOLDER: &str = "0x27182842e098f60e3d576794a5bffb0777e025d3";
    const OTHER: &str = "0x00000000000000000000000000000000000000aa";

    fn pad(addr: &str) -> String {
        format!("0x{:0>64}", addr.trim_start_matches("0x"))
    }

    fn transfer(token: &str, from: &str, to: &str, value: u128) -> LogEvent {
        LogEvent {
            address: token.parse().unwrap(),
            topics: vec![ERC20_TRANSFER_TOPIC.into(), pad(from), pad(to)],
            data: format!("0x{value:064x}"),
        }
    }

    fn addr(s: &str) -> Address {
        s.parse().unwrap()
    }

    fn call(from: &str, to: &str, value: u128, kind: CallKind) -> CallFrame {
        CallFrame {
            depth: 0,
            from: addr(from),
            to: addr(to),
            selector: None,
            value_wei: value,
            kind,
        }
    }

    #[test]
    fn counts_transfers_out_of_the_holder() {
        let logs = vec![transfer(TOKEN, HOLDER, OTHER, 700)];
        assert_eq!(erc20_net_outflow(&logs, &addr(TOKEN), &addr(HOLDER)), 700);
    }

    #[test]
    fn a_flash_loan_borrowed_and_repaid_nets_to_the_real_drain() {
        // Mirrors Euler: 30M in, 38.9M out => 8.9M net drained.
        let logs = vec![
            transfer(TOKEN, OTHER, HOLDER, 30_000),
            transfer(TOKEN, HOLDER, OTHER, 38_900),
        ];
        assert_eq!(erc20_net_outflow(&logs, &addr(TOKEN), &addr(HOLDER)), 8_900);
    }

    #[test]
    fn net_inflow_floors_at_zero() {
        let logs = vec![transfer(TOKEN, OTHER, HOLDER, 500)];
        assert_eq!(erc20_net_outflow(&logs, &addr(TOKEN), &addr(HOLDER)), 0);
    }

    #[test]
    fn ignores_other_tokens_and_non_transfer_or_nft_logs() {
        let mut nft = transfer(TOKEN, HOLDER, OTHER, 1);
        nft.topics.push(pad("0x1")); // 4 topics: ERC-721 shape
        let mut not_transfer = transfer(TOKEN, HOLDER, OTHER, 9);
        not_transfer.topics[0] = pad("0xdead");
        let logs = vec![transfer(OTHER, HOLDER, OTHER, 999), nft, not_transfer];
        assert_eq!(erc20_net_outflow(&logs, &addr(TOKEN), &addr(HOLDER)), 0);
    }

    #[test]
    fn oversized_values_saturate_instead_of_wrapping() {
        let mut log = transfer(TOKEN, HOLDER, OTHER, 0);
        log.data = format!("0x{}", "f".repeat(64));
        assert_eq!(
            erc20_net_outflow(&[log], &addr(TOKEN), &addr(HOLDER)),
            u128::MAX
        );
    }

    #[test]
    fn native_outflow_counts_calls_and_creates_net_of_inflows() {
        let frames = vec![
            call(HOLDER, OTHER, 900, CallKind::Call),
            call(OTHER, HOLDER, 300, CallKind::Call),
            call(HOLDER, OTHER, 50, CallKind::Create),
        ];
        assert_eq!(native_net_outflow(&frames, &addr(HOLDER)), 650);
    }

    #[test]
    fn native_outflow_ignores_delegate_static_and_callcode_values() {
        let frames = vec![
            call(HOLDER, OTHER, 1_000, CallKind::DelegateCall),
            call(HOLDER, OTHER, 1_000, CallKind::StaticCall),
            call(HOLDER, OTHER, 1_000, CallKind::CallCode),
        ];
        assert_eq!(native_net_outflow(&frames, &addr(HOLDER)), 0);
        assert_eq!(native_net_outflow(&[], &addr(HOLDER)), 0);
    }

    #[test]
    fn worst_flow_picks_the_largest_fraction_not_the_largest_amount() {
        let big_amount_small_share = AssetFlow {
            balance_before: 1_000_000,
            outflow: 10_000,
        }; // 1%
        let small_amount_big_share = AssetFlow {
            balance_before: 100,
            outflow: 90,
        }; // 90%
        assert_eq!(
            worst_flow(&[big_amount_small_share, small_amount_big_share]),
            Some(small_amount_big_share)
        );
    }

    #[test]
    fn worst_flow_ignores_assets_with_no_balance_or_no_outflow() {
        let no_balance = AssetFlow {
            balance_before: 0,
            outflow: 50,
        };
        let no_outflow = AssetFlow {
            balance_before: 50,
            outflow: 0,
        };
        assert_eq!(worst_flow(&[no_balance, no_outflow]), None);
        assert_eq!(worst_flow(&[]), None);
        assert_eq!(no_balance.fraction(), 0.0);
    }

    // --- value-netted flow

    fn mv(net_out: i128, balance: u128, unit_value: f64) -> TokenMove {
        TokenMove {
            net_out,
            balance,
            unit_value,
        }
    }

    #[test]
    fn a_value_neutral_swap_is_not_an_outflow() {
        // 5.7M USDC out, 5.7M USDT in, both $1 (6 decimals): what a Curve
        // trade looks like. The per-asset view saw a 19% drain.
        let unit = 1e-6;
        let f = value_netted_flow(&[
            mv(5_700_000_000_000, 30_000_000_000_000, unit),
            mv(-5_700_000_000_000, 40_000_000_000_000, unit),
        ]);
        assert_eq!(f, None);
    }

    #[test]
    fn borrowing_against_fresh_collateral_nets_to_nothing() {
        // 304k LUSD leaves a small reserve (100% of it), 304k USDC arrives.
        let f = value_netted_flow(&[
            mv(
                304_000_000_000_000_000_000_000,
                304_000_000_000_000_000_000_000,
                1e-18,
            ),
            mv(-304_000_000_000, 5_000_000_000_000, 1e-6),
        ]);
        assert_eq!(f, None);
    }

    #[test]
    fn a_pure_drain_keeps_its_per_asset_fraction() {
        // 8.9M of 8.9M DAI leaves, nothing comes back: 100%, as before.
        let unit = 1e-18;
        let bal = 8_900_000_000_000_000_000_000_000u128;
        let f = value_netted_flow(&[mv(bal as i128, bal, unit)]).unwrap();
        assert!((f.fraction() - 1.0).abs() < 1e-9, "{}", f.fraction());
    }

    #[test]
    fn a_partial_return_reduces_but_does_not_hide_the_loss() {
        // 1000 of asset A leaves (its whole balance), 300 worth comes back.
        let f = value_netted_flow(&[mv(1_000, 1_000, 1.0), mv(-300, 5_000, 1.0)]).unwrap();
        assert!((f.fraction() - 0.7).abs() < 1e-9, "{}", f.fraction());
    }

    #[test]
    fn value_not_units_decides_which_side_is_larger() {
        // 1 unit of an expensive asset out, 100 units of a cheap one in.
        assert_eq!(
            value_netted_flow(&[mv(1, 10, 100.0), mv(-100, 0, 1.0)]),
            None
        );
        // ...but not if the cheap one is worth less than that.
        assert!(value_netted_flow(&[mv(1, 10, 100.0), mv(-50, 0, 1.0)]).is_some());
    }

    #[test]
    fn nothing_moving_out_or_no_baseline_makes_no_claim() {
        assert_eq!(value_netted_flow(&[]), None);
        assert_eq!(value_netted_flow(&[mv(-500, 0, 1.0)]), None);
        // Outflow with no recorded balance is no claim (fail closed).
        assert_eq!(value_netted_flow(&[mv(500, 0, 1.0)]), None);
    }

    #[test]
    fn non_finite_values_make_no_claim() {
        assert_eq!(value_netted_flow(&[mv(10, 10, f64::NAN)]), None);
        assert_eq!(value_netted_flow(&[mv(10, 10, f64::INFINITY)]), None);
    }

    #[test]
    fn flows_report_both_directions_unnetted() {
        let logs = vec![
            transfer(TOKEN, HOLDER, OTHER, 700),
            transfer(TOKEN, OTHER, HOLDER, 200),
        ];
        assert_eq!(erc20_flows(&logs, &addr(TOKEN), &addr(HOLDER)), (700, 200));
        let frames = vec![
            call(HOLDER, OTHER, 9, CallKind::Call),
            call(OTHER, HOLDER, 4, CallKind::Call),
            call(HOLDER, OTHER, 100, CallKind::DelegateCall),
        ];
        assert_eq!(native_flows(&frames, &addr(HOLDER)), (9, 4));
    }
}
