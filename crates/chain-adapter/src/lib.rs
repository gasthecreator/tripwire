//! Chain adapters translate a specific chain's native RPC surface into
//! `tripwire-core`'s chain-agnostic types. The detection engine never
//! depends on this crate — only on the types it produces — which is the
//! concrete mechanism behind ARCHITECTURE.md §3.1's multi-chain claim:
//! a second EVM chain is a config change, a non-EVM chain is a new
//! module here implementing [`ChainAdapter`], and neither touches
//! `detection` at all.

pub mod evm;

use async_trait::async_trait;
use thiserror::Error;
use tripwire_core::{BlockHeader, ChainId, TxEvent};

#[derive(Debug, Error)]
pub enum ChainAdapterError {
    #[error("RPC transport error: {0}")]
    Transport(String),
    #[error("block {0} not found")]
    BlockNotFound(u64),
    #[error("failed to decode a value returned by the node: {0}")]
    Decode(String),
}

/// The trait every chain integration implements. Deliberately narrow:
/// three operations are all the detection pipeline needs, and adding a
/// chain means implementing exactly these three against that chain's
/// own RPC/indexing surface.
#[async_trait]
pub trait ChainAdapter: Send + Sync {
    fn chain_id(&self) -> ChainId;

    /// The chain's current head block number.
    async fn latest_block_number(&self) -> Result<u64, ChainAdapterError>;

    /// Identity and parent link of one block, or `BlockNotFound` if the
    /// chain doesn't currently have that block (e.g. it was reorged away
    /// or is beyond the head). This is what lets a listener detect reorgs:
    /// a block number whose hash changed is a different block.
    async fn block_header(&self, block_number: u64) -> Result<BlockHeader, ChainAdapterError>;

    /// Every confirmation-relevant fact the listener needs about one
    /// block's transactions, normalized to `TxEvent`. `confirmations` on
    /// each returned event is computed relative to whatever the chain's
    /// head was at call time — the caller (the listener) is responsible
    /// for re-deriving this as new blocks arrive if it holds onto the
    /// event past that instant (ARCHITECTURE.md §3.2).
    async fn get_block_tx_events(
        &self,
        block_number: u64,
    ) -> Result<Vec<TxEvent>, ChainAdapterError>;
}
