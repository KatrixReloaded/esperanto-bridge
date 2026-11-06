//! Chain policy over a consensus-authenticated view. No verifier implementation exists here.
use monero_wallet::{interface::ScannableBlock, transaction::Timelock, Scanner, WalletOutput};
use zz_core::{ChainEvidence, Id};

/// Implement only with a validated, fresh Monero consensus view. Raw node/wallet RPC does not
/// satisfy this contract. The provider must authenticate the complete block, each transaction
/// and prunable hash, and the global output indices; it must return a coherent canonical snapshot.
/// There is deliberately no production implementation yet.
pub trait AuthenticatedChain {
    type Error;
    fn tip(&self) -> Result<ChainEvidence, Self::Error>;
    fn canonical_hash(&self, height: u64) -> Result<Option<Id>, Self::Error>;
    /// Conservative consensus time suitable for timelock checks, not host wall-clock time.
    fn consensus_time(&self) -> Result<u64, Self::Error>;
    fn scannable_block(&self, height: u64) -> Result<ScannableBlock, Self::Error>;
}

pub struct ObservedOutput {
    pub output: WalletOutput,
    pub block: ChainEvidence,
    pub coinbase: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChainStatus {
    Reorganized,
    Pending,
    Mature,
}

/// Scan only a block furnished by the authenticated boundary. This checks the canonical hash
/// before and after scanning, but duplicate output keys and internal transfers still need durable
/// classification before a mint. The caller must discard these observations on any reorg.
pub fn scan_block<C: AuthenticatedChain>(
    chain: &C,
    scanner: &mut Scanner,
    height: u64,
) -> Result<Vec<ObservedOutput>, String> {
    let block = chain
        .scannable_block(height)
        .map_err(|_| "chain block unavailable")?;
    if u64::try_from(block.block.number()).map_err(|_| "block height overflow")? != height {
        return Err("block height mismatch".into());
    }
    let hash = Id(block.block.hash());
    if chain
        .canonical_hash(height)
        .map_err(|_| "canonical hash unavailable")?
        != Some(hash)
    {
        return Err("noncanonical block".into());
    }
    let miner = block.block.miner_transaction().hash();
    let outputs = scanner
        .scan(block)
        .map_err(|_| "block scan failed")?
        .ignore_additional_timelock();
    if chain
        .canonical_hash(height)
        .map_err(|_| "canonical hash unavailable")?
        != Some(hash)
    {
        return Err("chain changed during scan".into());
    }
    let mut keys = std::collections::HashSet::new();
    if outputs
        .iter()
        .any(|o| !keys.insert(o.key().compress().to_bytes()))
    {
        return Err("duplicate output key in block".into());
    }
    Ok(outputs
        .into_iter()
        .map(|output| ObservedOutput {
            coinbase: output.transaction() == miner,
            output,
            block: ChainEvidence {
                height,
                block_hash: hash,
            },
        })
        .collect())
}

/// `Mature` means only that this observation satisfies this chain policy. It is not a mint
/// authorization: output-key deduplication and classification remain separate mandatory gates.
/// Re-evaluate against a fresh authenticated snapshot immediately before taking an action.
pub fn status<C: AuthenticatedChain>(
    chain: &C,
    observed: &ObservedOutput,
    confirmations: u64,
) -> Result<ChainStatus, String> {
    if confirmations == 0 {
        return Err("confirmation policy must be nonzero".into());
    }
    let tip = chain.tip().map_err(|_| "chain tip unavailable")?;
    if chain
        .canonical_hash(tip.height)
        .map_err(|_| "tip unavailable")?
        != Some(tip.block_hash)
    {
        return Err("inconsistent tip".into());
    }
    match chain
        .canonical_hash(observed.block.height)
        .map_err(|_| "block unavailable")?
    {
        Some(hash) if hash != observed.block.block_hash => return Ok(ChainStatus::Reorganized),
        Some(_) => {}
        None => return Err("canonical block unavailable".into()),
    }
    let depth = tip
        .height
        .checked_sub(observed.block.height)
        .ok_or("tip predates observation")?;
    let confirmations_seen = depth.checked_add(1).ok_or("confirmation overflow")?;
    let maturity = if observed.coinbase { 60 } else { 10 };
    if confirmations_seen < confirmations || depth < maturity {
        return Ok(ChainStatus::Pending);
    }
    let unlocked = match observed.output.additional_timelock() {
        Timelock::None => true,
        Timelock::Block(h) => tip.height >= u64::try_from(h).map_err(|_| "timelock overflow")?,
        Timelock::Time(t) => {
            chain
                .consensus_time()
                .map_err(|_| "consensus time unavailable")?
                >= t
        }
    };
    if chain
        .canonical_hash(observed.block.height)
        .map_err(|_| "block unavailable")?
        != Some(observed.block.block_hash)
        || chain
            .canonical_hash(tip.height)
            .map_err(|_| "tip unavailable")?
            != Some(tip.block_hash)
    {
        return Err("chain changed during evaluation".into());
    }
    Ok(if unlocked {
        ChainStatus::Mature
    } else {
        ChainStatus::Pending
    })
}
