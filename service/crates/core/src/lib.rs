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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservedPayout {
    pub request_id: Id,
    pub domain: Domain,
    pub amount: AtomicAmount,
    pub fee_headroom: AtomicAmount,
    pub input_ids: Vec<Id>,
    pub destination: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    fn reserve(
        &mut self,
        payout: ReservedPayout,
        spendable: AtomicAmount,
    ) -> Result<(), Self::Error>;
    fn prepare(&mut self, payout: PreparedPayout) -> Result<(), Self::Error>;
    fn prepared(
        &mut self,
        domain: &Domain,
        request: Id,
    ) -> Result<Option<PreparedPayout>, Self::Error>;
}

pub mod deposits;
pub mod payouts;
pub mod storage;

impl AtomicAmount {
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(Self)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayoutState {
    Reserved(ReservedPayout),
    Prepared(PreparedPayout),
    Broadcast(PreparedPayout),
    Confirmed {
        payout: PreparedPayout,
        evidence: ChainEvidence,
    },
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct VaultState {
    #[serde(default)]
    pub poc_attempts: Vec<payouts::PocAttempt>,
    pub intents: Vec<DepositIntent>,
    pub payouts: Vec<PayoutState>,
    pub mint_results: Vec<(Id, AtomicAmount)>,
    pub evm_operations: Vec<EvmOperation>,
    #[serde(default)]
    pub deposits: Vec<deposits::Deposit>,
    #[serde(default)]
    pub monero_cursor: Option<ChainEvidence>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StateError {
    Conflict,
    InsufficientFunds,
    Overflow,
    InvalidTransition,
    ZeroResult,
    FencingUnavailable,
}

impl PayoutState {
    pub fn reservation(&self) -> &ReservedPayout {
        match self {
            Self::Reserved(p) => p,
            Self::Prepared(p) | Self::Broadcast(p) | Self::Confirmed { payout: p, .. } => {
                &p.reservation
            }
        }
    }
}

impl VaultState {
    pub fn insert_intent(&mut self, intent: DepositIntent) -> Result<(), StateError> {
        if let Some(existing) = self
            .intents
            .iter()
            .find(|x| x.id == intent.id || (x.domain == intent.domain && x.nonce == intent.nonce))
        {
            return if existing == &intent {
                Ok(())
            } else {
                Err(StateError::Conflict)
            };
        }
        if self
            .intents
            .iter()
            .any(|x| x.subaddress_index == intent.subaddress_index)
        {
            return Err(StateError::Conflict);
        }
        self.intents.push(intent);
        Ok(())
    }
    pub fn reserve(
        &mut self,
        payout: ReservedPayout,
        spendable: AtomicAmount,
    ) -> Result<(), StateError> {
        if let Some(existing) = self.payouts.iter().find(|x| {
            x.reservation().domain == payout.domain
                && x.reservation().request_id == payout.request_id
        }) {
            return if existing.reservation() == &payout {
                Ok(())
            } else {
                Err(StateError::Conflict)
            };
        }
        if payout.amount.0 == 0 {
            return Err(StateError::ZeroResult);
        }
        if payout.input_ids.is_empty()
            || payout
                .input_ids
                .iter()
                .enumerate()
                .any(|(i, id)| payout.input_ids[..i].contains(id))
        {
            return Err(StateError::Conflict);
        }
        if self
            .payouts
            .iter()
            .filter(|p| {
                !matches!(p, PayoutState::Confirmed { .. })
                    && p.reservation().domain.vault == payout.domain.vault
            })
            .any(|p| {
                p.reservation()
                    .input_ids
                    .iter()
                    .any(|id| payout.input_ids.contains(id))
            })
        {
            return Err(StateError::Conflict);
        }

        let used = self
            .payouts
            .iter()
            .filter(|p| !matches!(p, PayoutState::Confirmed { .. }))
            .try_fold(AtomicAmount(0), |sum, p| {
                sum.checked_add(p.reservation().amount)?
                    .checked_add(p.reservation().fee_headroom)
            })
            .ok_or(StateError::Overflow)?;
        let need = used
            .checked_add(payout.amount)
            .and_then(|x| x.checked_add(payout.fee_headroom))
            .ok_or(StateError::Overflow)?;
        if need > spendable {
            return Err(StateError::InsufficientFunds);
        }
        self.payouts.push(PayoutState::Reserved(payout));
        Ok(())
    }
    pub fn prepare(&mut self, payout: PreparedPayout) -> Result<(), StateError> {
        if payout.signed_transaction.is_empty() {
            return Err(StateError::InvalidTransition);
        }
        let state = self
            .payouts
            .iter_mut()
            .find(|x| {
                x.reservation().domain == payout.reservation.domain
                    && x.reservation().request_id == payout.reservation.request_id
            })
            .ok_or(StateError::InvalidTransition)?;
        match state {
            PayoutState::Reserved(r) if *r == payout.reservation => {
                *state = PayoutState::Prepared(payout);
                Ok(())
            }
            PayoutState::Prepared(p) | PayoutState::Broadcast(p) if *p == payout => Ok(()),
            _ => Err(StateError::Conflict),
        }
    }
    /// No spending authority is issued until rollback-resistant fencing is integrated.
    pub fn authorize_broadcast(&self, _request: Id) -> Result<&[u8], StateError> {
        Err(StateError::FencingUnavailable)
    }
    pub fn record_mint_result(
        &mut self,
        deposit: Id,
        actual: AtomicAmount,
    ) -> Result<(), StateError> {
        if actual.0 == 0 {
            return Err(StateError::ZeroResult);
        }
        if let Some((_, old)) = self.mint_results.iter().find(|(id, _)| *id == deposit) {
            return if *old == actual {
                Ok(())
            } else {
                Err(StateError::Conflict)
            };
        }
        self.mint_results.push((deposit, actual));
        Ok(())
    }
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for StateError {}

/// Durable signed transaction; nonce is unique per chain and signer, across operations.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmOperation {
    pub domain: Domain,
    pub operation_id: Id,
    pub signer: [u8; 20],
    pub nonce: u64,
    pub signed_bytes: Vec<u8>,
    pub tx_hash: Id,
}
impl VaultState {
    pub fn journal_evm(&mut self, operation: EvmOperation) -> Result<(), StateError> {
        if operation.signed_bytes.is_empty() {
            return Err(StateError::InvalidTransition);
        }
        if let Some(existing) = self
            .evm_operations
            .iter()
            .find(|x| x.domain == operation.domain && x.operation_id == operation.operation_id)
        {
            return if existing == &operation {
                Ok(())
            } else {
                Err(StateError::Conflict)
            };
        }
        if self.evm_operations.iter().any(|x| {
            x.domain.chain_id == operation.domain.chain_id
                && x.signer == operation.signer
                && x.nonce == operation.nonce
        }) {
            return Err(StateError::Conflict);
        }
        self.evm_operations.push(operation);
        Ok(())
    }
}
