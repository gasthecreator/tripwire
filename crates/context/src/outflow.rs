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
}
