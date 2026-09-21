//! Valuing assets, so fund flow can be measured as *value* lost instead of
//! one asset at a time (see [`crate::outflow::value_netted_flow`]).
//!
//! A [`TokenValuer`] answers "what is one raw unit of this token worth, in a
//! common unit, at this block?". Two rules keep it from becoming an attack
//! surface:
//!
//! * **Pre-transaction prices.** The context asks for the block *before* the
//!   transaction being judged, so a price manipulated inside that
//!   transaction (Warp Finance) cannot inflate the worth of what an attacker
//!   deposits and thereby cancel a drain.
//! * **Unknown means unknown.** A token with no value returns `None`, and the
//!   caller then falls back to the stricter per-asset rule for that
//!   transaction. A price is never guessed.
//!
//! Residual risk, stated plainly: a price that was already manipulated in an
//! *earlier* block is trusted. The protocol's own oracle is the reference here
//! because it is the one the protocol itself acts on.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use alloy::eips::BlockId;
use alloy::providers::{ProviderBuilder, RootProvider};
use alloy::sol;
use async_trait::async_trait;
use tripwire_core::Address;

/// The address used for native ETH in a valuer.
pub const NATIVE: Address = Address::ZERO;

#[async_trait]
pub trait TokenValuer: Send + Sync + fmt::Debug {
    /// Value of ONE RAW UNIT (smallest denomination) of `token` at `block`,
    /// in a unit common to every token this valuer answers for. `None` if
    /// unknown.
    async fn unit_value(&self, token: &Address, block: u64) -> Option<f64>;
}

/// Operator-supplied constant values: the right tool for pegged assets
/// (stablecoin pools) and for a protocol whose assets are all one unit.
#[derive(Debug, Default, Clone)]
pub struct FixedValues {
    per_raw_unit: HashMap<Address, f64>,
}

impl FixedValues {
    pub fn new() -> Self {
        Self::default()
    }

    /// A token worth `value_per_token` (in the common unit) with `decimals`.
    pub fn with_token(mut self, token: Address, decimals: u8, value_per_token: f64) -> Self {
        self.per_raw_unit
            .insert(token, value_per_token / 10f64.powi(decimals as i32));
        self
    }

    /// Convenience: a $1 stablecoin.
    pub fn with_stable(self, token: Address, decimals: u8) -> Self {
        self.with_token(token, decimals, 1.0)
    }

    /// Native ETH at `value_per_eth` (18 decimals).
    pub fn with_native(self, value_per_eth: f64) -> Self {
        self.with_token(NATIVE, 18, value_per_eth)
    }
}

#[async_trait]
impl TokenValuer for FixedValues {
    async fn unit_value(&self, token: &Address, _block: u64) -> Option<f64> {
        self.per_raw_unit.get(token).copied()
    }
}

/// Tries each valuer in order and returns the first answer, so operator-fixed
/// values (pegs) can take precedence over an oracle, or an oracle can be
/// supplemented with a fixed native-ETH price.
#[derive(Debug, Default)]
pub struct Layered(pub Vec<std::sync::Arc<dyn TokenValuer>>);

#[async_trait]
impl TokenValuer for Layered {
    async fn unit_value(&self, token: &Address, block: u64) -> Option<f64> {
        for v in &self.0 {
            if let Some(x) = v.unit_value(token, block).await {
                return Some(x);
            }
        }
        None
    }
}

sol! {
    #[sol(rpc)]
    interface IERC20Decimals {
        function decimals() external view returns (uint8);
    }
    #[sol(rpc)]
    interface IAaveV2Pool {
        function getAddressesProvider() external view returns (address);
    }
    #[sol(rpc)]
    interface IAaveV2AddressesProvider {
        function getPriceOracle() external view returns (address);
    }
    #[sol(rpc)]
    interface IAaveV2Oracle {
        function getAssetPrice(address asset) external view returns (uint256);
    }
    #[sol(rpc)]
    interface ICompoundComptrollerOracle {
        function oracle() external view returns (address);
    }
    #[sol(rpc)]
    interface ICompoundPriceOracle {
        function getUnderlyingPrice(address cToken) external view returns (uint256);
    }
}

fn to_alloy(a: &Address) -> alloy::primitives::Address {
    a.to_string()
        .parse()
        .expect("tripwire Address is valid hex")
}

fn provider(rpc_url: &str) -> Result<RootProvider, String> {
    let url = rpc_url
        .parse()
        .map_err(|e| format!("invalid RPC URL: {e}"))?;
    Ok(ProviderBuilder::new()
        .disable_recommended_fillers()
        .connect_http(url))
}

#[derive(Default)]
struct PriceCache {
    block: u64,
    prices: HashMap<Address, Option<f64>>,
}

fn cached(cache: &Mutex<PriceCache>, block: u64, token: &Address) -> Option<Option<f64>> {
    let mut c = cache.lock().unwrap_or_else(|p| p.into_inner());
    if c.block != block {
        *c = PriceCache {
            block,
            ..Default::default()
        };
    }
    c.prices.get(token).copied()
}

fn store(cache: &Mutex<PriceCache>, block: u64, token: Address, v: Option<f64>) {
    let mut c = cache.lock().unwrap_or_else(|p| p.into_inner());
    if c.block == block {
        c.prices.insert(token, v);
    }
}

/// Aave V2's own price oracle (ETH-denominated: wei per whole token), read at
/// the given block. Native ETH is worth exactly one wei per wei.
pub struct AaveV2Oracle {
    provider: RootProvider,
    oracle: Address,
    decimals: Mutex<HashMap<Address, Option<u8>>>,
    cache: Mutex<PriceCache>,
}

impl fmt::Debug for AaveV2Oracle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AaveV2Oracle({})", self.oracle)
    }
}

impl AaveV2Oracle {
    /// Resolves the oracle through the pool's addresses provider (so a
    /// governance-changed oracle is followed).
    pub async fn connect(rpc_url: &str, pool: &Address) -> Result<Self, String> {
        let provider = provider(rpc_url)?;
        let ap = IAaveV2Pool::new(to_alloy(pool), &provider)
            .getAddressesProvider()
            .call()
            .await
            .map_err(|e| format!("addresses provider: {e}"))?;
        let oracle = IAaveV2AddressesProvider::new(ap, &provider)
            .getPriceOracle()
            .call()
            .await
            .map_err(|e| format!("price oracle: {e}"))?;
        Ok(Self {
            provider,
            oracle: oracle
                .to_string()
                .parse()
                .map_err(|e| format!("oracle address: {e}"))?,
            decimals: Mutex::new(HashMap::new()),
            cache: Mutex::new(PriceCache::default()),
        })
    }

    async fn decimals_of(&self, token: &Address) -> Option<u8> {
        if let Some(d) = self
            .decimals
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(token)
        {
            return *d;
        }
        let d = IERC20Decimals::new(to_alloy(token), &self.provider)
            .decimals()
            .call()
            .await
            .ok();
        self.decimals
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(*token, d);
        d
    }
}

#[async_trait]
impl TokenValuer for AaveV2Oracle {
    async fn unit_value(&self, token: &Address, block: u64) -> Option<f64> {
        if *token == NATIVE {
            return Some(1.0);
        }
        if let Some(v) = cached(&self.cache, block, token) {
            return v;
        }
        let dec = self.decimals_of(token).await;
        let price = match dec {
            Some(_) => IAaveV2Oracle::new(to_alloy(&self.oracle), &self.provider)
                .getAssetPrice(to_alloy(token))
                .block(BlockId::number(block))
                .call()
                .await
                .ok(),
            None => None,
        };
        let v = match (price, dec) {
            (Some(p), Some(d)) => {
                let p = u128::try_from(p).ok()? as f64;
                // A zero price means "no price", not "worthless".
                (p > 0.0).then(|| p / 10f64.powi(d as i32))
            }
            _ => None,
        };
        store(&self.cache, block, *token, v);
        v
    }
}

/// Compound V2's own price oracle (USD, `price = usd_per_raw_unit * 1e36`).
/// Needs the underlying -> cToken mapping. Native ETH is not answered (cETH
/// has no underlying); combine with [`FixedValues`] if it matters.
pub struct CompoundOracle {
    provider: RootProvider,
    oracle: Address,
    ctoken_of: HashMap<Address, Address>,
    cache: Mutex<PriceCache>,
}

impl fmt::Debug for CompoundOracle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CompoundOracle({})", self.oracle)
    }
}

impl CompoundOracle {
    pub async fn connect(
        rpc_url: &str,
        comptroller: &Address,
        ctoken_of_underlying: HashMap<Address, Address>,
    ) -> Result<Self, String> {
        let provider = provider(rpc_url)?;
        let oracle = ICompoundComptrollerOracle::new(to_alloy(comptroller), &provider)
            .oracle()
            .call()
            .await
            .map_err(|e| format!("comptroller oracle: {e}"))?;
        Ok(Self {
            provider,
            oracle: oracle
                .to_string()
                .parse()
                .map_err(|e| format!("oracle address: {e}"))?,
            ctoken_of: ctoken_of_underlying,
            cache: Mutex::new(PriceCache::default()),
        })
    }
}

#[async_trait]
impl TokenValuer for CompoundOracle {
    async fn unit_value(&self, token: &Address, block: u64) -> Option<f64> {
        let ctoken = self.ctoken_of.get(token)?;
        if let Some(v) = cached(&self.cache, block, token) {
            return v;
        }
        let price = ICompoundPriceOracle::new(to_alloy(&self.oracle), &self.provider)
            .getUnderlyingPrice(to_alloy(ctoken))
            .block(BlockId::number(block))
            .call()
            .await
            .ok();
        let v = price.and_then(|p| {
            let p = u128::try_from(p).ok()? as f64;
            (p > 0.0).then(|| p / 1e36)
        });
        store(&self.cache, block, *token, v);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Address {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn layered_returns_the_first_answer_and_none_when_nobody_knows() {
        let t1 = a("0x00000000000000000000000000000000000000a1");
        let t2 = a("0x00000000000000000000000000000000000000a2");
        let t3 = a("0x00000000000000000000000000000000000000a3");
        let first = FixedValues::new().with_token(t1, 0, 5.0);
        let second = FixedValues::new()
            .with_token(t1, 0, 9.0)
            .with_token(t2, 0, 7.0);
        let l = Layered(vec![
            std::sync::Arc::new(first),
            std::sync::Arc::new(second),
        ]);
        assert_eq!(l.unit_value(&t1, 1).await, Some(5.0)); // first wins
        assert_eq!(l.unit_value(&t2, 1).await, Some(7.0)); // falls through
        assert_eq!(l.unit_value(&t3, 1).await, None);
    }

    #[tokio::test]
    async fn fixed_values_scale_by_decimals_and_answer_only_for_known_tokens() {
        let usdc = a("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
        let v = FixedValues::new().with_stable(usdc, 6).with_native(3000.0);
        assert_eq!(v.unit_value(&usdc, 1).await, Some(1e-6));
        assert_eq!(v.unit_value(&NATIVE, 1).await, Some(3000.0 / 1e18));
        assert_eq!(
            v.unit_value(&a("0x00000000000000000000000000000000000000aa"), 1)
                .await,
            None
        );
    }
}
