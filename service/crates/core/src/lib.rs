use serde::{Deserialize, Serialize};

/// XMR atomic units (10^-12 XMR), also the cwXMR base unit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AtomicAmount(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Id(pub [u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Domain {
    pub chain_id: u64,
    pub bridge: [u8; 20],
    pub vault: Id,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositIntent {
    pub id: Id,
    pub domain: Domain,
    pub recipient: [u8; 20],
    pub nonce: Id,
    pub subaddress_index: u32,
    pub subaddress: String,
}

/// An evidence reference, not a proof of consensus or finality.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEvidence {
    pub block_hash: Id,
    pub height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservedPayout {
    pub request_id: Id,
    pub domain: Domain,
    pub amount: AtomicAmount,
    pub fee_headroom: AtomicAmount,
    pub destination: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedPayout {
    pub reservation: ReservedPayout,
    pub signed_transaction: Vec<u8>,
    pub transaction_id: Id,
}

/// Implementations must sign inside the trusted boundary.
pub trait PayoutSigner {
    type Error;
    fn prepare(&self, payout: &ReservedPayout) -> Result<PreparedPayout, Self::Error>;
}

/// A storage implementation must persist the exact signed bytes before broadcast.
pub trait PayoutJournal {
    type Error;
    fn reserve(&mut self, payout: ReservedPayout, spendable: AtomicAmount) -> Result<(), Self::Error>;
    fn prepare(&mut self, payout: PreparedPayout) -> Result<(), Self::Error>;
    fn prepared(&mut self, request: Id) -> Result<Option<PreparedPayout>, Self::Error>;
}
