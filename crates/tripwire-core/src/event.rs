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

/// The minimum a listener needs to follow a chain and notice reorgs: a
/// block's identity and its link to its parent. Chain-agnostic on purpose —
/// any chain with hash-linked blocks fits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub number: u64,
    pub hash: String,
    pub parent_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogEvent {
    pub address: Address,
    pub topics: Vec<String>,
    pub data: String,
}

/// The EVM call variant that produced a [`CallFrame`]. Matters for
/// detection: a `StaticCall` cannot modify state, so it can never be the
/// re-entering half of a reentrancy exploit, and treating read-only
/// lookups such as `balanceOf` as re-entry made the generic reentrancy
/// signature fire on ordinary transactions (found by scoring the real
/// Beanstalk exploit trace).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    #[default]
    Call,
    StaticCall,
    DelegateCall,
    CallCode,
    Create,
}

impl CallKind {
    /// Parses the kind names emitted by geth's `callTracer` (`type`) and
    /// Foundry's `cast run --json` (`kind`), case-insensitively.
    ///
    /// Anything unrecognised maps to `Call`, deliberately: an unknown kind
    /// might be state-changing, and silently classing it as read-only
    /// would hide a possible re-entry from the detector. The cost of the
    /// conservative default is at worst the old (noisier) behaviour.
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "STATICCALL" => CallKind::StaticCall,
            "DELEGATECALL" => CallKind::DelegateCall,
            "CALLCODE" => CallKind::CallCode,
            "CREATE" | "CREATE2" => CallKind::Create,
            _ => CallKind::Call,
        }
    }

    /// True for the variants that carry a function selector in calldata.
    pub fn is_message_call(self) -> bool {
        !matches!(self, CallKind::Create)
    }

    /// True if this frame is read-only by construction.
    pub fn is_static(self) -> bool {
        matches!(self, CallKind::StaticCall)
    }
}

/// One frame of a transaction's internal call trace. Frames are stored
/// in execution (pre-order) order, and `depth` is the call-stack depth —
/// together these let a consumer reconstruct which earlier frames are
/// still active ancestors of a given frame, which is what real
/// reentrancy detection needs.
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
    #[serde(default)]
    pub kind: CallKind,
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
            kind: CallKind::Call,
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

    #[test]
    fn call_kind_parses_tracer_names_case_insensitively() {
        assert_eq!(CallKind::parse("STATICCALL"), CallKind::StaticCall);
        assert_eq!(CallKind::parse("staticcall"), CallKind::StaticCall);
        assert_eq!(CallKind::parse("DELEGATECALL"), CallKind::DelegateCall);
        assert_eq!(CallKind::parse("CALLCODE"), CallKind::CallCode);
        assert_eq!(CallKind::parse("CREATE"), CallKind::Create);
        assert_eq!(CallKind::parse("CREATE2"), CallKind::Create);
        assert_eq!(CallKind::parse("CALL"), CallKind::Call);
    }

    #[test]
    fn unknown_call_kind_is_conservatively_state_changing() {
        assert_eq!(CallKind::parse("SOMETHING_NEW"), CallKind::Call);
        assert!(!CallKind::parse("SOMETHING_NEW").is_static());
    }

    #[test]
    fn only_staticcall_is_static_and_only_create_lacks_a_selector() {
        assert!(CallKind::StaticCall.is_static());
        assert!(!CallKind::DelegateCall.is_static());
        assert!(!CallKind::Create.is_message_call());
        assert!(CallKind::Call.is_message_call());
    }

    #[test]
    fn frame_without_kind_field_deserializes_as_call() {
        let json = r#"{"depth":0,"from":"0x0000000000000000000000000000000000000000","to":"0x0000000000000000000000000000000000000002","selector":null,"value_wei":0}"#;
        let f: CallFrame = serde_json::from_str(json).unwrap();
        assert_eq!(f.kind, CallKind::Call);
    }
}
