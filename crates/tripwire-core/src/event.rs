use crate::{Address, ChainId};
use serde::{Deserialize, Serialize};

/// A normalized transaction event — the boundary type between a
/// `ChainAdapter` implementation (in the `chain-adapter` crate) and
/// everything downstream (detection engine, scoring). No EVM-specific
/// concept — gas, opcodes, RLP encoding — appears here, only what a
/// fund-flow or call-sequence signature actually needs to reason about.
/// This is what makes the detection engine chain-agnostic in practice,
/// not just in intent (ARCHITECTURE.md §3.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxEvent {
    pub chain: ChainId,
    pub tx_hash: String,
    pub block_number: u64,
    /// Confirmations at the time this event was last observed. The
    /// listener updates this in place as new blocks arrive; the
    /// detection engine may evaluate a signature at 0 confirmations
    /// deliberately (ARCHITECTURE.md §3.2) — only the pause *decision*
    /// gates on a configured minimum depth, not detection itself.
    pub confirmations: u64,
    pub from: Address,
    pub to: Option<Address>,
    pub value_wei: u128,
    pub logs: Vec<LogEvent>,
    pub call_frames: Vec<CallFrame>,
    pub timestamp_unix: u64,
}

impl TxEvent {
    /// The maximum call depth reached anywhere in this transaction's
    /// trace. Depth 0 for a transaction with no internal calls at all.
    pub fn max_call_depth(&self) -> u32 {
        self.call_frames.iter().map(|f| f.depth).max().unwrap_or(0)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogEvent {
    pub address: Address,
    pub topics: Vec<String>,
    pub data: String,
}

/// One frame of a transaction's internal call trace. A reentrancy
/// signature looks for the same `(to, selector)` pair recurring at a
/// depth greater than its first occurrence within one `TxEvent`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallFrame {
    pub depth: u32,
    pub from: Address,
    pub to: Address,
    /// First 4 bytes of calldata, hex-encoded (`0x` + 8 hex chars) — the
    /// function selector. `None` for a plain value transfer with no
    /// calldata.
    pub selector: Option<String>,
    pub value_wei: u128,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn frame(depth: u32) -> CallFrame {
        CallFrame {
            depth,
            from: Address::ZERO,
            to: Address::from_str("0x0000000000000000000000000000000000000002").unwrap(),
            selector: Some("0xa9059cbb".into()),
            value_wei: 0,
        }
    }

    #[test]
    fn max_call_depth_is_zero_with_no_frames() {
        let tx = TxEvent {
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
        };
        assert_eq!(tx.max_call_depth(), 0);
    }

    #[test]
    fn max_call_depth_finds_deepest_frame() {
        let mut tx = TxEvent {
            chain: ChainId::ETHEREUM_MAINNET,
            tx_hash: "0x1".into(),
            block_number: 1,
            confirmations: 0,
            from: Address::ZERO,
            to: None,
            value_wei: 0,
            logs: vec![],
            call_frames: vec![frame(0), frame(3), frame(1)],
            timestamp_unix: 0,
        };
        assert_eq!(tx.max_call_depth(), 3);
        tx.call_frames.push(frame(7));
        assert_eq!(tx.max_call_depth(), 7);
    }

    #[test]
    fn serde_round_trip_with_logs_and_frames() {
        let tx = TxEvent {
            chain: ChainId::ETHEREUM_MAINNET,
            tx_hash: "0xdeadbeef".into(),
            block_number: 100,
            confirmations: 2,
            from: Address::ZERO,
            to: Some(Address::from_str("0x0000000000000000000000000000000000000002").unwrap()),
            value_wei: 1_000_000_000_000_000_000,
            logs: vec![LogEvent {
                address: Address::ZERO,
                topics: vec!["0xabc".into()],
                data: "0x".into(),
            }],
            call_frames: vec![frame(0), frame(1)],
            timestamp_unix: 1_700_000_000,
        };
        let json = serde_json::to_string(&tx).unwrap();
        let back: TxEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(tx, back);
    }
}
