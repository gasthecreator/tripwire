use serde::{Deserialize, Serialize};
use std::fmt;

/// EIP-155 chain identifier. A newtype rather than a bare `u64` so the
/// detection engine and signature configs can't accidentally compare a
/// chain id against, say, a block number or a confirmation-depth count —
/// the type system catches that whole class of bug at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChainId(pub u64);

impl ChainId {
    pub const ETHEREUM_MAINNET: ChainId = ChainId(1);

    pub fn is_ethereum_mainnet(self) -> bool {
        self == Self::ETHEREUM_MAINNET
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for ChainId {
    fn from(v: u64) -> Self {
        ChainId(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_constant_is_one() {
        assert_eq!(ChainId::ETHEREUM_MAINNET, ChainId(1));
        assert!(ChainId::ETHEREUM_MAINNET.is_ethereum_mainnet());
    }

    #[test]
    fn other_chain_is_not_mainnet() {
        assert!(!ChainId(137).is_ethereum_mainnet());
    }

    #[test]
    fn displays_as_bare_number() {
        assert_eq!(ChainId(1).to_string(), "1");
    }

    #[test]
    fn serde_round_trip() {
        let id = ChainId(42161);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "42161");
        let back: ChainId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }
}
