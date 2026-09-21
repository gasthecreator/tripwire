//! Detecting spot-price manipulation of Uniswap-V2-style pools from the
//! `Sync` events a transaction emits. Every V2 swap/mint/burn emits
//! `Sync(reserve0, reserve1)`, so the transaction's own logs record how far
//! it pushed a pool's price — exactly what a spot-price oracle reads, and
//! what oracle-manipulation exploits (Warp Finance, Cheese Bank, ...)
//! abuse. No I/O here; the pre-transaction reference reserves are fetched
//! by the caller.

use std::collections::HashMap;

use tripwire_core::{Address, LogEvent};

use crate::outflow::hex_to_u128_saturating;

/// `keccak256("Sync(uint112,uint112)")`
const SYNC_TOPIC: &str = "0x1c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncEvent {
    pub pair: Address,
    pub reserve0: u128,
    pub reserve1: u128,
}

/// All V2 `Sync` events in `logs`, in order. Only the exact shape counts:
/// one topic, and two 32-byte words of data.
pub fn parse_syncs(logs: &[LogEvent]) -> Vec<SyncEvent> {
    logs.iter()
        .filter(|l| l.topics.len() == 1 && l.topics[0].eq_ignore_ascii_case(SYNC_TOPIC))
        .filter_map(|l| {
            let d = l.data.trim_start_matches("0x");
            if d.len() != 128 {
                return None;
            }
            Some(SyncEvent {
                pair: l.address,
                reserve0: hex_to_u128_saturating(&d[..64]),
                reserve1: hex_to_u128_saturating(&d[64..]),
            })
        })
        .collect()
}

/// Distinct pairs, in first-seen order, capped at `limit` (each needs an
/// RPC call for its reference reserves).
pub fn distinct_pairs(syncs: &[SyncEvent], limit: usize) -> Vec<Address> {
    let mut seen = Vec::new();
    for s in syncs {
        if !seen.contains(&s.pair) {
            seen.push(s.pair);
            if seen.len() == limit {
                break;
            }
        }
    }
    seen
}

/// The largest relative spot-price move any pair underwent in the
/// transaction, versus its reserves before it.
///
/// Price is `reserve1 / reserve0`. The move is direction- and
/// orientation-symmetric — `max(p/p_ref, p_ref/p) - 1` — so a token
/// crashing 95% and its counter-asset rising 20x are the same event and
/// don't depend on which side is "token0". `None` if no pair had usable
/// reference reserves.
pub fn max_relative_price_move(
    reference: &HashMap<Address, (u128, u128)>,
    syncs: &[SyncEvent],
) -> Option<f64> {
    let mut worst: Option<f64> = None;
    for s in syncs {
        let Some(&(r0, r1)) = reference.get(&s.pair) else {
            continue;
        };
        if r0 == 0 || r1 == 0 || s.reserve0 == 0 || s.reserve1 == 0 {
            continue;
        }
        let p_ref = r1 as f64 / r0 as f64;
        let p = s.reserve1 as f64 / s.reserve0 as f64;
        let ratio = p / p_ref;
        let mv = ratio.max(1.0 / ratio) - 1.0;
        if worst.is_none_or(|w| mv > w) {
            worst = Some(mv);
        }
    }
    worst
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAIR_A: &str = "0x00000000000000000000000000000000000000a1";
    const PAIR_B: &str = "0x00000000000000000000000000000000000000b2";

    fn sync_log(pair: &str, r0: u128, r1: u128) -> LogEvent {
        LogEvent {
            address: pair.parse().unwrap(),
            topics: vec![SYNC_TOPIC.into()],
            data: format!("0x{r0:064x}{r1:064x}"),
        }
    }

    fn a(s: &str) -> Address {
        s.parse().unwrap()
    }

    #[test]
    fn parses_only_well_formed_sync_events() {
        let mut short = sync_log(PAIR_A, 1, 1);
        short.data = "0x1234".into();
        let mut two_topics = sync_log(PAIR_A, 1, 1);
        two_topics.topics.push("0xab".into());
        let mut other = sync_log(PAIR_A, 1, 1);
        other.topics[0] = "0xdead".into();
        let logs = vec![sync_log(PAIR_A, 100, 200), short, two_topics, other];
        let s = parse_syncs(&logs);
        assert_eq!(s.len(), 1);
        assert_eq!((s[0].reserve0, s[0].reserve1), (100, 200));
    }

    #[test]
    fn distinct_pairs_dedupes_in_order_and_respects_the_cap() {
        let s = parse_syncs(&[
            sync_log(PAIR_A, 1, 1),
            sync_log(PAIR_B, 1, 1),
            sync_log(PAIR_A, 2, 2),
        ]);
        assert_eq!(distinct_pairs(&s, 10), vec![a(PAIR_A), a(PAIR_B)]);
        assert_eq!(distinct_pairs(&s, 1), vec![a(PAIR_A)]);
    }

    #[test]
    fn a_swap_at_the_reference_price_moves_nothing() {
        let reference = HashMap::from([(a(PAIR_A), (1_000_000u128, 2_000_000u128))]);
        // fee-sized change: same ratio to 3 decimals
        let s = parse_syncs(&[sync_log(PAIR_A, 1_001_000, 1_998_000)]);
        let m = max_relative_price_move(&reference, &s).unwrap();
        assert!(m < 0.005, "got {m}");
    }

    #[test]
    fn the_warp_finance_shape_is_a_huge_move() {
        // DAI/WETH: 61.87M DAI / 93.9K WETH  ->  13.29M DAI / 436K WETH
        let reference = HashMap::from([(a(PAIR_A), (61_873_635u128, 93_893u128))]);
        let s = parse_syncs(&[sync_log(PAIR_A, 13_288_688, 436_146)]);
        let m = max_relative_price_move(&reference, &s).unwrap();
        assert!(m > 20.0, "got {m}"); // price of WETH in DAI fell ~95% => ratio ~21x
    }

    #[test]
    fn the_move_is_symmetric_in_orientation() {
        let reference = HashMap::from([(a(PAIR_A), (1_000u128, 1_000u128))]);
        let up = parse_syncs(&[sync_log(PAIR_A, 1_000, 4_000)]); // price x4
        let down = parse_syncs(&[sync_log(PAIR_A, 4_000, 1_000)]); // price /4
        let mu = max_relative_price_move(&reference, &up).unwrap();
        let md = max_relative_price_move(&reference, &down).unwrap();
        assert!((mu - md).abs() < 1e-9 && (mu - 3.0).abs() < 1e-9);
    }

    #[test]
    fn takes_the_worst_move_across_syncs_and_pairs() {
        let reference = HashMap::from([
            (a(PAIR_A), (1_000u128, 1_000u128)),
            (a(PAIR_B), (1_000u128, 1_000u128)),
        ]);
        let s = parse_syncs(&[
            sync_log(PAIR_A, 1_000, 1_100),
            sync_log(PAIR_B, 1_000, 3_000),
            sync_log(PAIR_A, 1_000, 1_050),
        ]);
        assert!((max_relative_price_move(&reference, &s).unwrap() - 2.0).abs() < 1e-9);
    }

    #[test]
    fn missing_or_zero_reference_reserves_are_skipped_not_guessed() {
        let s = parse_syncs(&[sync_log(PAIR_A, 1_000, 9_000)]);
        assert_eq!(max_relative_price_move(&HashMap::new(), &s), None);
        let zero = HashMap::from([(a(PAIR_A), (0u128, 1_000u128))]);
        assert_eq!(max_relative_price_move(&zero, &s), None);
        let drained = parse_syncs(&[sync_log(PAIR_A, 0, 5)]);
        let ok = HashMap::from([(a(PAIR_A), (10u128, 10u128))]);
        assert_eq!(max_relative_price_move(&ok, &drained), None);
    }
}
