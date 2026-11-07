//! Durable deposit bookkeeping. Chain observations must be checked by the caller; none of these
//! methods turn an RPC response into consensus evidence or authorize a mint on their own.
use crate::{AtomicAmount, ChainEvidence, EvmOperation, Id, StateError, VaultState};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deposit {
    pub id: Id,
    pub intent_id: Id,
    /// Monero output public key, retained encrypted to detect duplicate-key deposits.
    pub output_key: Id,
    pub transaction: Id,
    pub output_index: u64,
    pub amount: AtomicAmount,
    /// Serialized scanner output, including private wallet metadata; encrypted with the vault state.
    pub wallet_output: Vec<u8>,
    pub inclusion: ChainEvidence,
    pub state: MintState,
    pub quarantined: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MintState {
    Observed,
    /// Exact input ciphertext/proof and authorization are persisted before requesting NSM evidence.
    Authorized(MintAuthorization),
    Submitted {
        authorization: MintAuthorization,
        transaction: Id,
    },
    Confirmed {
        authorization: MintAuthorization,
        transaction: Id,
        actual: AtomicAmount,
        inclusion: ChainEvidence,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintAuthorization {
    pub amount_handle: Id,
    pub input_proof: Vec<u8>,
    pub nonce: u64,
    pub deadline: u64,
    pub signature: Vec<u8>,
}

/// A finalized status-zero receipt. Keep both the signed bytes and original authorization
/// when explicitly recovering a reverted mint; its consumed gas nonce stays reserved.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevertedMint {
    pub operation: EvmOperation,
    pub authorization: MintAuthorization,
    pub inclusion: ChainEvidence,
}

impl VaultState {
    /// Caller verifies a canonical finalized status-zero receipt, fresh source eligibility and
    /// unused bridge deposit/nonce. Never use this for an absent or ambiguous transaction.
    pub fn recover_reverted_mint(
        &mut self,
        id: Id,
        transaction: Id,
        inclusion: ChainEvidence,
        observed_time: u64,
        deadline: u64,
        signature: Vec<u8>,
    ) -> Result<(), StateError> {
        if inclusion.block_hash.0 == [0; 32] || deadline <= observed_time || signature.len() != 65 {
            return Err(StateError::InvalidTransition);
        }
        let index = self
            .deposits
            .iter()
            .position(|d| d.id == id)
            .ok_or(StateError::InvalidTransition)?;
        let deposit = &self.deposits[index];
        if deposit.quarantined {
            return Err(StateError::InvalidTransition);
        }
        let MintState::Submitted {
            authorization,
            transaction: expected,
        } = &deposit.state
        else {
            return Err(StateError::InvalidTransition);
        };
        if *expected != transaction || observed_time <= authorization.deadline {
            return Err(StateError::Conflict);
        }
        let intent = self
            .intents
            .iter()
            .find(|i| i.id == deposit.intent_id)
            .ok_or(StateError::InvalidTransition)?;
        let op_index = self
            .evm_operations
            .iter()
            .position(|op| {
                op.operation_id == id && op.domain == intent.domain && op.tx_hash == transaction
            })
            .ok_or(StateError::Conflict)?;
        let original = authorization.clone();
        let mut renewed = original.clone();
        renewed.deadline = deadline;
        renewed.signature = signature;
        self.reverted_mints.push(RevertedMint {
            operation: self.evm_operations.remove(op_index),
            authorization: original,
            inclusion,
        });
        self.deposits[index].state = MintState::Authorized(renewed);
        Ok(())
    }

    /// Call within a durable transaction after scanning an issued subaddress. Change and primary
    /// address outputs must never be supplied here. Repeated identical observations are harmless.
    pub fn observe_deposit(&mut self, deposit: Deposit) -> Result<(), StateError> {
        if deposit.id.0 == [0; 32]
            || deposit.output_key.0 == [0; 32]
            || deposit.transaction.0 == [0; 32]
            || deposit.amount.0 == 0
            || deposit.wallet_output.is_empty()
            || deposit.wallet_output.len() > 65536
            || deposit.inclusion.block_hash.0 == [0; 32]
            || deposit.state != MintState::Observed
            || deposit.quarantined
            || !self
                .intents
                .iter()
                .any(|i| i.id == deposit.intent_id && i.subaddress_index != 0)
        {
            return Err(StateError::InvalidTransition);
        }
        if let Some(old) = self.deposits.iter().find(|d| {
            d.id == deposit.id
                || d.output_key == deposit.output_key
                || (d.transaction == deposit.transaction && d.output_index == deposit.output_index)
        }) {
            // A rescan after advancement does not roll back the mint state.
            return if old.id == deposit.id
                && old.intent_id == deposit.intent_id
                && old.output_key == deposit.output_key
                && old.transaction == deposit.transaction
                && old.output_index == deposit.output_index
                && old.amount == deposit.amount
                && old.wallet_output == deposit.wallet_output
                && old.inclusion == deposit.inclusion
            {
                Ok(())
            } else {
                Err(StateError::Conflict)
            };
        }
        self.deposits.push(deposit);
        Ok(())
    }

    /// The caller rechecks maturity/canonicality immediately before signing. Persisted
    /// authorization is immutable so retries cannot change recipient, amount or nonce.
    pub fn authorize_mint(
        &mut self,
        id: Id,
        authorization: MintAuthorization,
    ) -> Result<(), StateError> {
        if authorization.amount_handle.0 == [0; 32]
            || authorization.input_proof.is_empty()
            || authorization.input_proof.len() > 1024 * 1024
            || authorization.signature.len() != 65
            || authorization.deadline == 0
        {
            return Err(StateError::InvalidTransition);
        }
        if self.deposits.iter().any(|d| {
            d.id != id
                && match &d.state {
                    MintState::Authorized(a)
                    | MintState::Submitted {
                        authorization: a, ..
                    }
                    | MintState::Confirmed {
                        authorization: a, ..
                    } => a.nonce == authorization.nonce,
                    _ => false,
                }
        }) {
            return Err(StateError::Conflict);
        }
        let deposit = self
            .deposits
            .iter_mut()
            .find(|d| d.id == id)
            .ok_or(StateError::InvalidTransition)?;
        if deposit.quarantined {
            return Err(StateError::InvalidTransition);
        }
        match &deposit.state {
            MintState::Observed => {
                deposit.state = MintState::Authorized(authorization);
                Ok(())
            }
            MintState::Authorized(old) if *old == authorization => Ok(()),
            _ => Err(StateError::Conflict),
        }
    }

    /// Explicit recovery only: caller verifies expiry and unused on-chain deposit/nonce.
    /// Preserve every mint term except deadline/signature; never replace a journaled transaction.
    pub fn renew_expired_mint(
        &mut self,
        id: Id,
        expected_deadline: u64,
        observed_time: u64,
        deadline: u64,
        signature: Vec<u8>,
    ) -> Result<(), StateError> {
        if observed_time <= expected_deadline
            || deadline <= observed_time
            || signature.len() != 65
            || self.evm_operations.iter().any(|op| op.operation_id == id)
        {
            return Err(StateError::InvalidTransition);
        }
        let deposit = self
            .deposits
            .iter_mut()
            .find(|d| d.id == id)
            .ok_or(StateError::InvalidTransition)?;
        if deposit.quarantined {
            return Err(StateError::InvalidTransition);
        }
        let MintState::Authorized(old) = &mut deposit.state else {
            return Err(StateError::InvalidTransition);
        };
        if old.deadline != expected_deadline {
            return Err(StateError::Conflict);
        }
        old.deadline = deadline;
        old.signature = signature;
        Ok(())
    }

    /// Atomically journal the exact signed EVM bytes and advance the deposit before sending.
    /// The caller validates the signed transaction's calldata against the authorization.
    pub fn journal_mint(&mut self, id: Id, operation: EvmOperation) -> Result<(), StateError> {
        let index = self
            .deposits
            .iter()
            .position(|d| d.id == id)
            .ok_or(StateError::InvalidTransition)?;
        let deposit = &self.deposits[index];
        if deposit.quarantined {
            return Err(StateError::InvalidTransition);
        }
        let intent = self
            .intents
            .iter()
            .find(|i| i.id == deposit.intent_id)
            .ok_or(StateError::InvalidTransition)?;
        if operation.domain != intent.domain
            || operation.operation_id != id
            || operation.tx_hash.0 == [0; 32]
        {
            return Err(StateError::Conflict);
        }
        let authorization = match &deposit.state {
            MintState::Authorized(a) => a.clone(),
            MintState::Submitted {
                authorization,
                transaction,
            } if *transaction == operation.tx_hash => authorization.clone(),
            _ => return Err(StateError::InvalidTransition),
        };
        let transaction = operation.tx_hash;
        self.journal_evm(operation)?;
        self.deposits[index].state = MintState::Submitted {
            authorization,
            transaction,
        };
        Ok(())
    }

    /// Supply only a matched finalized receipt and its decrypted actual-result handle. A successful
    /// receipt alone does not establish the amount. Zero results remain recorded, never retried.
    pub fn confirm_mint(
        &mut self,
        id: Id,
        transaction: Id,
        actual: AtomicAmount,
        inclusion: ChainEvidence,
    ) -> Result<(), StateError> {
        let deposit = self
            .deposits
            .iter_mut()
            .find(|d| d.id == id)
            .ok_or(StateError::InvalidTransition)?;
        if deposit.quarantined {
            return Err(StateError::InvalidTransition);
        }
        if actual > deposit.amount || inclusion.block_hash.0 == [0; 32] {
            return Err(StateError::Conflict);
        }
        let authorization = match &deposit.state {
            MintState::Submitted {
                authorization,
                transaction: expected,
            } if *expected == transaction => authorization.clone(),
            MintState::Confirmed {
                transaction: old_tx,
                actual: old_actual,
                inclusion: old_inclusion,
                ..
            } if *old_tx == transaction && *old_actual == actual && *old_inclusion == inclusion => {
                return Ok(())
            }
            _ => return Err(StateError::InvalidTransition),
        };
        deposit.state = MintState::Confirmed {
            authorization,
            transaction,
            actual,
            inclusion,
        };
        Ok(())
    }

    /// Never delete an output identity on reorg: doing so could let a replay create a second mint.
    pub fn quarantine_deposit(&mut self, id: Id) -> Result<(), StateError> {
        let deposit = self
            .deposits
            .iter_mut()
            .find(|d| d.id == id)
            .ok_or(StateError::InvalidTransition)?;
        deposit.quarantined = true;
        Ok(())
    }
}
