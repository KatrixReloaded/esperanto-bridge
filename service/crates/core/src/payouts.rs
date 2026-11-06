//! Explicitly trusted, stagenet-only PoC state. Cooperative leases and encrypted storage do not
//! protect against malicious clones or rollback. Production authorize_broadcast remains closed.
use crate::{
    AtomicAmount, ChainEvidence, Domain, EvmOperation, Id, PayoutState, PreparedPayout, StateError,
    VaultState,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub struct StagenetPocPolicy {
    domain: Domain,
}
impl StagenetPocPolicy {
    /// Calling this constructor explicitly accepts ONE trusted operator, ONE active process,
    /// and NO database rollback for a stagenet/Sepolia test. It is never inferred from defaults.
    pub fn accept_single_operator_single_process_no_rollback(
        domain: Domain,
    ) -> Result<Self, StateError> {
        if domain.chain_id != 11_155_111 || domain.bridge == [0; 20] || domain.vault.0 == [0; 32] {
            return Err(StateError::Conflict);
        }
        Ok(Self { domain })
    }
    pub fn domain(&self) -> &Domain {
        &self.domain
    }
}

/// Serialized only inside Cipher's authenticated encrypted vault state. Never Debug/log this.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PocAttempt {
    pub payout: PreparedPayout,
    pub outgoing_key: [u8; 32],
    pub actual_burn: AtomicAmount,
    pub fee_terms_hash: Id,
    pub nonzero_handle: Id,
    pub request_observed: ChainEvidence,
    pub claim: Option<EvmOperation>,
    pub claim_attempted: bool,
    pub assignment: Option<ChainEvidence>,
    pub broadcast_attempted: bool,
    pub broadcast_from: Option<ChainEvidence>,
    pub inclusion: Option<ChainEvidence>,
    pub settlement: Option<EvmOperation>,
    pub settlement_attempted: bool,
    pub settled: Option<ChainEvidence>,
}
impl Drop for PocAttempt {
    fn drop(&mut self) {
        self.outgoing_key.zeroize();
    }
}

impl VaultState {
    pub fn poc_attempt(
        &self,
        policy: &StagenetPocPolicy,
        id: Id,
    ) -> Result<&PocAttempt, StateError> {
        self.poc_attempts
            .iter()
            .find(|a| {
                a.payout.reservation.domain == *policy.domain()
                    && a.payout.reservation.request_id == id
            })
            .ok_or(StateError::InvalidTransition)
    }
    fn poc_attempt_mut(
        &mut self,
        policy: &StagenetPocPolicy,
        id: Id,
    ) -> Result<&mut PocAttempt, StateError> {
        self.poc_attempts
            .iter_mut()
            .find(|a| {
                a.payout.reservation.domain == *policy.domain()
                    && a.payout.reservation.request_id == id
            })
            .ok_or(StateError::InvalidTransition)
    }
    /// Reservation, private outgoing key and exact signed bytes commit atomically before claim.
    pub fn prepare_poc(
        &mut self,
        policy: &StagenetPocPolicy,
        attempt: PocAttempt,
        spendable: AtomicAmount,
    ) -> Result<(), StateError> {
        let r = &attempt.payout.reservation;
        if r.domain != *policy.domain()
            || attempt.actual_burn.0 == 0
            || r.amount.0 == 0
            || r.amount
                .checked_add(r.fee_headroom)
                .is_none_or(|need| need > attempt.actual_burn)
            || attempt.payout.signed_transaction.is_empty()
            || attempt.payout.transaction_id.0 == [0; 32]
            || attempt.outgoing_key == [0; 32]
            || attempt.claim.is_some()
            || attempt.claim_attempted
            || attempt.assignment.is_some()
            || attempt.broadcast_attempted
            || attempt.broadcast_from.is_some()
            || attempt.inclusion.is_some()
            || attempt.settlement.is_some()
            || attempt.settlement_attempted
            || attempt.settled.is_some()
        {
            return Err(StateError::InvalidTransition);
        }
        if let Ok(old) = self.poc_attempt(policy, r.request_id) {
            return if old == &attempt {
                Ok(())
            } else {
                Err(StateError::Conflict)
            };
        }
        if self.poc_attempts.iter().any(|old| {
            old.outgoing_key == attempt.outgoing_key
                || old.payout.transaction_id == attempt.payout.transaction_id
        }) {
            return Err(StateError::Conflict);
        }
        // Confirmed inputs remain spent forever: never make them available by releasing a reservation.
        if self.payouts.iter().any(|old| {
            old.reservation()
                .input_ids
                .iter()
                .any(|id| r.input_ids.contains(id))
        }) {
            return Err(StateError::Conflict);
        }
        self.reserve(r.clone(), spendable)?;
        self.prepare(attempt.payout.clone())?;
        self.poc_attempts.push(attempt);
        Ok(())
    }
    pub fn journal_poc_claim(
        &mut self,
        policy: &StagenetPocPolicy,
        id: Id,
        operation: EvmOperation,
    ) -> Result<(), StateError> {
        let a = self.poc_attempt(policy, id)?;
        if operation.domain != *policy.domain() || a.claim.is_some() || a.broadcast_attempted {
            return Err(StateError::Conflict);
        }
        self.journal_evm(operation.clone())?;
        self.poc_attempt_mut(policy, id)?.claim = Some(operation);
        Ok(())
    }
    pub fn attempt_poc_claim(
        &mut self,
        policy: &StagenetPocPolicy,
        id: Id,
    ) -> Result<EvmOperation, StateError> {
        let a = self.poc_attempt_mut(policy, id)?;
        if a.claim_attempted {
            return Err(StateError::InvalidTransition);
        }
        let op = a.claim.clone().ok_or(StateError::InvalidTransition)?;
        a.claim_attempted = true;
        Ok(op)
    }
    /// Caller checked the exact finalized assignment via the explicitly trusted Sepolia node.
    pub fn observe_poc_assignment(
        &mut self,
        policy: &StagenetPocPolicy,
        id: Id,
        assignee: Id,
        evidence: ChainEvidence,
    ) -> Result<(), StateError> {
        if assignee != policy.domain().vault {
            return Err(StateError::Conflict);
        }
        let a = self.poc_attempt_mut(policy, id)?;
        if a.claim.is_none() || !a.claim_attempted || evidence.block_hash.0 == [0; 32] {
            return Err(StateError::InvalidTransition);
        }
        a.assignment = Some(evidence);
        Ok(())
    }
    /// Commit BEFORE the socket write. Even a crash before sending leaves an ambiguous attempt;
    /// reconcile this transaction, never construct a replacement or automatically refund it.
    pub fn attempt_poc_broadcast(
        &mut self,
        policy: &StagenetPocPolicy,
        id: Id,
        from: ChainEvidence,
    ) -> Result<PreparedPayout, StateError> {
        let a = self.poc_attempt_mut(policy, id)?;
        if a.assignment.is_none() || a.broadcast_attempted {
            return Err(StateError::InvalidTransition);
        }
        a.broadcast_attempted = true;
        a.broadcast_from = Some(from);
        let payout = a.payout.clone();
        if let Some(p) = self
            .payouts
            .iter_mut()
            .find(|p| p.reservation() == &payout.reservation)
        {
            *p = PayoutState::Broadcast(payout.clone());
        }
        Ok(payout)
    }
    pub fn confirm_poc_payment(
        &mut self,
        policy: &StagenetPocPolicy,
        id: Id,
        evidence: ChainEvidence,
    ) -> Result<(), StateError> {
        let a = self.poc_attempt_mut(policy, id)?;
        if !a.broadcast_attempted || evidence.block_hash.0 == [0; 32] {
            return Err(StateError::InvalidTransition);
        }
        if a.inclusion.as_ref().is_some_and(|old| old != &evidence) {
            return Err(StateError::Conflict);
        }
        a.inclusion = Some(evidence.clone());
        let payout = a.payout.clone();
        if let Some(p) = self
            .payouts
            .iter_mut()
            .find(|p| p.reservation() == &payout.reservation)
        {
            *p = PayoutState::Confirmed { payout, evidence };
        }
        Ok(())
    }
    pub fn journal_poc_settlement(
        &mut self,
        policy: &StagenetPocPolicy,
        id: Id,
        operation: EvmOperation,
    ) -> Result<(), StateError> {
        let a = self.poc_attempt(policy, id)?;
        if operation.domain != *policy.domain() || a.inclusion.is_none() || a.settlement.is_some() {
            return Err(StateError::InvalidTransition);
        }
        self.journal_evm(operation.clone())?;
        self.poc_attempt_mut(policy, id)?.settlement = Some(operation);
        Ok(())
    }
    pub fn attempt_poc_settlement(
        &mut self,
        policy: &StagenetPocPolicy,
        id: Id,
    ) -> Result<EvmOperation, StateError> {
        let a = self.poc_attempt_mut(policy, id)?;
        if a.settlement_attempted || a.inclusion.is_none() {
            return Err(StateError::InvalidTransition);
        }
        let op = a.settlement.clone().ok_or(StateError::InvalidTransition)?;
        a.settlement_attempted = true;
        Ok(op)
    }
    pub fn confirm_poc_settlement(
        &mut self,
        policy: &StagenetPocPolicy,
        id: Id,
        evidence: ChainEvidence,
    ) -> Result<(), StateError> {
        let a = self.poc_attempt_mut(policy, id)?;
        if !a.settlement_attempted || a.inclusion.is_none() {
            return Err(StateError::InvalidTransition);
        }
        a.settled = Some(evidence);
        Ok(())
    }
}
