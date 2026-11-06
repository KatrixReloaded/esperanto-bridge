//! Stagenet-only payout controller under explicitly accepted single-operator/single-process/no-
//! rollback assumptions. Trusted RPC observations are not independent consensus proofs. No
//! replacement, reassignment or refund path exists for an ambiguous outbound attempt.
use crate::attestation::{decode, Identity};
use alloy::{
    primitives::{keccak256, Address, Bytes, U256},
    sol_types::{SolCall, SolEvent},
};
use anyhow::{ensure, Context, Result};
use monero_wallet::{address::Network, WalletOutput};
use rand::RngCore;
use serde_json::json;
use zeroize::Zeroizing;
use zz_core::{
    deposits::MintState,
    payouts::{PocAttempt, StagenetPocPolicy},
    storage::PostgresStore,
    AtomicAmount, ChainEvidence, EvmOperation, Id, ReservedPayout, VaultState,
};
use zz_monero::{
    chain::{ChainStatus, ObservedOutput},
    stagenet::TrustedStagenet,
};
use zz_zama::{
    evm::{
        BlockObservation, Client as Evm, Finality, ReadMethod, SignedTransaction, SubmissionOutcome,
    },
    fhe::{Client as Fhe, Scope, Width},
    transaction::{Fees, PayoutCall},
    Bridge,
};

/// Explicit fee policy supplied by the operator, never an unchecked RPC amount.
pub struct PayoutConfig {
    pub fee_terms_hash: Id,
    pub fixed_fee: AtomicAmount,
    pub network_fee_cap: AtomicAmount,
    pub max_fee_per_weight: u64,
    pub monero_confirmations: u64,
    pub kms_context: U256,
}
pub struct Redemptions {
    store: PostgresStore,
    policy: StagenetPocPolicy,
    config: PayoutConfig,
}
struct Request {
    block: BlockObservation,
    data: Bridge::Redemption,
    eligible: bool,
}
fn evidence(block: &BlockObservation) -> ChainEvidence {
    ChainEvidence {
        block_hash: Id(block.hash.0),
        height: block.number,
    }
}
fn number(id: Id) -> U256 {
    U256::from_be_bytes(id.0)
}
fn operation_id(kind: &[u8], domain: &zz_core::Domain, request: Id) -> Id {
    Id(keccak256(
        [
            b"cwxmr/stagenet-payout/v1/".as_slice(),
            kind,
            &domain.chain_id.to_be_bytes(),
            &domain.bridge,
            &domain.vault.0,
            &request.0,
        ]
        .concat(),
    )
    .0)
}
fn validate_assignment(
    domain: &zz_core::Domain,
    attempt: &PocAttempt,
    data: &Bridge::Redemption,
) -> Result<()> {
    ensure!(
        data.status == 2
            && data.assignee.0 == domain.vault.0
            && data.nonzero.0 == attempt.nonzero_handle.0
            && data.feeTermsHash.0 == attempt.fee_terms_hash.0,
        "request is not assigned to this vault with the prepared terms"
    );
    Ok(())
}
/// Salted commitment avoids publicly disclosing the Monero transaction hash.
fn payment_commitment(a: &PocAttempt) -> Id {
    Id(keccak256(
        [
            b"cwxmr/stagenet-payment/v1".as_slice(),
            &a.outgoing_key,
            &a.payout.transaction_id.0,
            &a.payout.reservation.request_id.0,
            &a.payout.reservation.domain.vault.0,
        ]
        .concat(),
    )
    .0)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextAction {
    JournalClaim,
    SubmitClaim,
    WaitForAssignmentThenBroadcast,
    FindPayment,
    JournalSettlement,
    SubmitSettlement,
    ConfirmSettlement,
    Complete,
}
fn next_action(a: &PocAttempt) -> NextAction {
    if a.settled.is_some() {
        NextAction::Complete
    } else if a.settlement_attempted {
        NextAction::ConfirmSettlement
    } else if a.settlement.is_some() {
        NextAction::SubmitSettlement
    } else if a.inclusion.is_some() {
        NextAction::JournalSettlement
    } else if a.broadcast_attempted {
        NextAction::FindPayment
    } else if a.claim_attempted {
        NextAction::WaitForAssignmentThenBroadcast
    } else if a.claim.is_some() {
        NextAction::SubmitClaim
    } else {
        NextAction::JournalClaim
    }
}

impl Redemptions {
    /// Caller runs mint and payout work in ONE serialized loop. Do not sign another EVM
    /// operation while the previous signer nonce is unresolved. IDs contain no plaintext amount.
    pub fn pending(&mut self) -> Result<Vec<(Id, NextAction)>> {
        Ok(self
            .load()?
            .poc_attempts
            .iter()
            .filter(|a| a.payout.reservation.domain == *self.policy.domain() && a.settled.is_none())
            .map(|a| (a.payout.reservation.request_id, next_action(a)))
            .collect())
    }
    /// Bounded finalized-event discovery. The operator loop retains its scan cursor and must
    /// not advance past an unhandled candidate. The log alone does not authorize a payout.
    pub async fn discover(&mut self, evm: &Evm, from: u64, to: u64) -> Result<Vec<Id>> {
        self.lease()?;
        ensure!(to >= from && to - from < 256, "invalid discovery range");
        let head: BlockObservation = evm
            .read(ReadMethod::BlockByNumber, json!(["finalized", false]))
            .await?
            .result;
        ensure!(to <= head.number, "discovery exceeds finalized RPC head");
        let logs: Vec<zz_zama::evm::LogObservation> = evm.read(ReadMethod::Logs,json!([{"address":Address::from(self.policy.domain().bridge),"fromBlock":format!("0x{from:x}"),"toBlock":format!("0x{to:x}"),"topics":[Bridge::RedemptionRequested::SIGNATURE_HASH]}])).await?.result;
        ensure!(logs.len() <= 256, "too many requests in discovery batch");
        let mut result = Vec::new();
        for log in logs {
            ensure!(
                !log.removed
                    && log.address == Address::from(self.policy.domain().bridge)
                    && log.block_number >= from
                    && log.block_number <= to,
                "request log scope mismatch"
            );
            let event = Bridge::RedemptionRequested::decode_raw_log_validate(
                log.topics.iter().copied(),
                &log.data,
            )?;
            if event
                .eligibleVaults
                .iter()
                .any(|v| v.0 == self.policy.domain().vault.0)
            {
                result.push(Id(event.requestId.to_be_bytes()));
            }
        }
        result.sort_by_key(|id| id.0);
        result.dedup();
        Ok(result)
    }
    /// Scan at most eight sufficiently deep blocks for the exact persisted transaction. The
    /// returned cursor is a polling optimization only; absence never authorizes replacement/refund.
    pub async fn find_payment(
        &mut self,
        chain: &TrustedStagenet,
        id: Id,
        from: Option<u64>,
    ) -> Result<(Option<u64>, u64)> {
        let a = self.attempt(id)?;
        let start = a
            .broadcast_from
            .as_ref()
            .context("payout not attempted")?
            .height;
        let from = from.unwrap_or(start);
        ensure!(from >= start, "invalid payment scan cursor");
        let tip = chain
            .tip()
            .await
            .map_err(|_| anyhow::anyhow!("stagenet unavailable"))?;
        let Some(mature) = tip
            .height
            .checked_add(1)
            .and_then(|n| n.checked_sub(self.config.monero_confirmations))
        else {
            return Ok((None, from));
        };
        let to = mature.min(from.saturating_add(7));
        if from > to {
            return Ok((None, from));
        }
        for height in from..=to {
            if chain
                .includes_transaction(height, a.payout.transaction_id)
                .await
                .map_err(|_| anyhow::anyhow!("inclusion unavailable"))?
            {
                self.confirm_payment(chain, id, height).await?;
                return Ok((Some(height), height));
            }
        }
        Ok((None, to.checked_add(1).context("height overflow")?))
    }
    pub fn open(
        mut store: PostgresStore,
        policy: StagenetPocPolicy,
        config: PayoutConfig,
        identity: &Identity,
        _verified_stagenet: &TrustedStagenet,
    ) -> Result<Self> {
        ensure!(
            Id(decode(&identity.public()?.vault_id)?) == policy.domain().vault,
            "payout identity domain mismatch"
        );
        ensure!(
            config.fee_terms_hash.0 != [0; 32]
                && config.fixed_fee.0 > 0
                && config.network_fee_cap.0 > 0
                && config.network_fee_cap <= config.fixed_fee
                && config.max_fee_per_weight > 0
                && config.monero_confirmations >= 10,
            "invalid stagenet payout policy"
        );
        let state = store
            .load(policy.domain().vault)
            .map_err(|_| anyhow::anyhow!("vault state unavailable"))?;
        ensure!(
            state.intents.iter().all(|i| i.domain == *policy.domain())
                && state
                    .payouts
                    .iter()
                    .all(|a| a.reservation().domain == *policy.domain())
                && state
                    .evm_operations
                    .iter()
                    .all(|op| op.domain == *policy.domain()),
            "stored deployment domain mismatch"
        );
        store
            .acquire_stagenet_poc_lease(policy.domain().vault)
            .map_err(|_| anyhow::anyhow!("cooperative payout lease unavailable"))?;
        Ok(Self {
            store,
            policy,
            config,
        })
    }
    fn lease(&mut self) -> Result<()> {
        self.store
            .check_stagenet_poc_lease(self.policy.domain().vault)
            .map_err(|_| anyhow::anyhow!("payout lease lost; process must stop"))
    }
    fn load(&mut self) -> Result<VaultState> {
        self.lease()?;
        self.store
            .load(self.policy.domain().vault)
            .map_err(|_| anyhow::anyhow!("vault state unavailable"))
    }
    fn attempt(&mut self, id: Id) -> Result<PocAttempt> {
        Ok(self.load()?.poc_attempt(&self.policy, id)?.clone())
    }
    async fn request(&self, evm: &Evm, id: Id) -> Result<Request> {
        ensure!(id.0 != [0; 32], "invalid request id");
        let block: BlockObservation = evm
            .read(ReadMethod::BlockByNumber, json!(["finalized", false]))
            .await?
            .result;
        let call = Bridge::redemptionsCall { id: number(id) };
        let bytes: Bytes = evm.read(ReadMethod::Call, json!([{"to":Address::from(self.policy.domain().bridge),"data":Bytes::from(call.abi_encode())},{"blockHash":block.hash,"requireCanonical":true}])).await?.result;
        let data = Bridge::redemptionsCall::abi_decode_returns_validate(&bytes)?;
        let call = Bridge::eligibleCall {
            _0: number(id),
            _1: self.policy.domain().vault.0.into(),
        };
        let bytes: Bytes = evm.read(ReadMethod::Call, json!([{"to":Address::from(self.policy.domain().bridge),"data":Bytes::from(call.abi_encode())},{"blockHash":block.hash,"requireCanonical":true}])).await?.result;
        let eligible = Bridge::eligibleCall::abi_decode_returns_validate(&bytes)?;
        Ok(Request {
            block,
            data,
            eligible,
        })
    }
    /// Read and decrypt the ACTUAL encrypted burn plus all three destination words. The SDK uses
    /// the registered decrypt identity. Amount and destination never leave the enclave in logs.
    pub async fn prepare(
        &mut self,
        identity: &Identity,
        chain: &TrustedStagenet,
        evm: &Evm,
        fhe: &Fhe,
        id: Id,
    ) -> Result<Id> {
        let state = self.load()?;
        if let Ok(a) = state.poc_attempt(&self.policy, id) {
            return Ok(a.payout.transaction_id);
        }
        let request = self.request(evm, id).await?;
        ensure!(
            request.data.status == 1
                && request.eligible
                && request.data.feeTermsHash.0 == self.config.fee_terms_hash.0,
            "request unavailable or policy mismatch"
        );
        let decrypt = identity.decrypt_signer()?;
        let contract = Address::from(self.policy.domain().bridge);
        let scope = |handle, width| Scope {
            contract,
            user: decrypt.address(),
            handle,
            width,
        };
        let auth = fhe
            .prepare_decryption(scope(request.data.amount, Width::Uint64))
            .await?
            .authorize(&decrypt, self.config.kms_context)
            .await?;
        let actual = fhe.decrypt(auth).await?;
        ensure!(
            actual > self.config.fixed_fee.0,
            "zero or below-fee actual burn"
        );
        let mut encoded = Zeroizing::new([0u8; 96]);
        for (i, handle) in request.data.destination.iter().enumerate() {
            let auth = fhe
                .prepare_decryption(scope(*handle, Width::Uint256))
                .await?
                .authorize(&decrypt, self.config.kms_context)
                .await?;
            encoded[i * 32..i * 32 + 32]
                .copy_from_slice(&fhe.decrypt_u256(auth).await?.to_be_bytes::<32>());
        }
        let destination = zz_monero::destination::decode(Network::Stagenet, &encoded)
            .map_err(anyhow::Error::msg)?
            .to_string();
        let amount = AtomicAmount(actual - self.config.fixed_fee.0);
        let need = amount
            .checked_add(self.config.network_fee_cap)
            .context("payout overflow")?;
        let mut selected = Vec::new();
        let mut selected_amount = AtomicAmount(0);
        let mut total = AtomicAmount(0);
        let id_key = identity.deposit_id_key()?;
        for deposit in &state.deposits {
            if deposit.quarantined
                || !matches!(deposit.state,MintState::Confirmed { actual, .. } if actual.0 > 0)
            {
                continue;
            }
            let intent = state
                .intents
                .iter()
                .find(|i| i.id == deposit.intent_id && i.domain == *self.policy.domain())
                .context("deposit domain mismatch")?;
            let mut bytes = deposit.wallet_output.as_slice();
            let output = WalletOutput::read(&mut bytes)?;
            ensure!(
                bytes.is_empty()
                    && zz_monero::input_id(&output) == deposit.output_key
                    && output.transaction() == deposit.transaction.0
                    && output.index_in_transaction() == deposit.output_index
                    && zz_monero::observed_amount(&output) == deposit.amount
                    && output
                        .subaddress()
                        .is_some_and(|i| i.account() == 0 && i.address() == intent.subaddress_index)
                    && zz_monero::deposit_id(
                        &id_key,
                        self.policy.domain(),
                        output.transaction(),
                        output.index_in_transaction()
                    ) == deposit.id,
                "stored wallet output mismatch"
            );
            let observed = ObservedOutput {
                output,
                block: deposit.inclusion.clone(),
                coinbase: false,
            };
            let status = chain
                .status(&observed, self.config.monero_confirmations)
                .await
                .map_err(|_| anyhow::anyhow!("output status unavailable"))?;
            ensure!(
                status != ChainStatus::Reorganized,
                "deposit reorganized; quarantine required"
            );
            if status != ChainStatus::Mature {
                continue;
            }
            total = total
                .checked_add(deposit.amount)
                .context("wallet total overflow")?;
            if selected_amount >= need
                || state
                    .payouts
                    .iter()
                    .any(|p| p.reservation().input_ids.contains(&deposit.output_key))
            {
                continue;
            }
            ensure!(selected.len() < 16, "input cap exceeded");
            selected_amount = selected_amount
                .checked_add(deposit.amount)
                .context("input total overflow")?;
            selected.push(observed.output);
        }
        ensure!(
            selected_amount >= need,
            "insufficient mature unreserved local inputs"
        );
        let reservation = ReservedPayout {
            request_id: id,
            domain: self.policy.domain().clone(),
            amount,
            fee_headroom: self.config.network_fee_cap,
            input_ids: selected.iter().map(zz_monero::input_id).collect(),
            destination,
        };
        let (inputs, fee) = chain
            .payout_inputs(selected, self.config.max_fee_per_weight)
            .await
            .map_err(anyhow::Error::msg)?;
        let mut outgoing_key = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *outgoing_key);
        let payout = zz_monero::prepare_payout(
            &mut rand::rngs::OsRng,
            &identity.wallet_spend()?,
            outgoing_key.clone(),
            Network::Stagenet,
            &reservation,
            inputs,
            fee,
        )
        .map_err(anyhow::Error::msg)?;
        zz_monero::journaled_bytes(&payout).map_err(anyhow::Error::msg)?;
        let transaction = payout.transaction_id;
        let attempt = PocAttempt {
            payout,
            outgoing_key: *outgoing_key,
            actual_burn: AtomicAmount(actual),
            fee_terms_hash: self.config.fee_terms_hash,
            nonzero_handle: Id(request.data.nonzero.0),
            request_observed: evidence(&request.block),
            claim: None,
            claim_attempted: false,
            assignment: None,
            broadcast_attempted: false,
            broadcast_from: None,
            inclusion: None,
            settlement: None,
            settlement_attempted: false,
            settled: None,
        };
        self.lease()?;
        self.store
            .update(self.policy.domain().vault, |state| {
                state.prepare_poc(&self.policy, attempt, total)?;
                Ok(())
            })
            .map_err(|_| anyhow::anyhow!("payout preparation persistence failed"))?;
        Ok(transaction)
    }
    async fn journal_call(
        &mut self,
        identity: &Identity,
        evm: &Evm,
        id: Id,
        call: PayoutCall,
        fees: Fees,
        settle: bool,
    ) -> Result<SignedTransaction> {
        let signer = identity.mint_signer()?;
        let nonce: String = evm
            .read(
                ReadMethod::TransactionCount,
                json!([signer.address(), "pending"]),
            )
            .await?
            .result;
        let nonce = u64::from_str_radix(nonce.strip_prefix("0x").context("invalid nonce")?, 16)?;
        let transaction = zz_zama::transaction::sign_payout_transaction(
            &signer,
            self.policy.domain(),
            call,
            nonce,
            fees,
        )?;
        let op = EvmOperation {
            domain: self.policy.domain().clone(),
            operation_id: operation_id(
                if settle { b"settle" } else { b"claim" },
                self.policy.domain(),
                id,
            ),
            signer: signer.address().into_array(),
            nonce,
            signed_bytes: transaction.raw().to_vec(),
            tx_hash: Id(transaction.hash().0),
        };
        self.lease()?;
        self.store
            .update(self.policy.domain().vault, |state| {
                if settle {
                    state.journal_poc_settlement(&self.policy, id, op)?
                } else {
                    state.journal_poc_claim(&self.policy, id, op)?
                }
                Ok(())
            })
            .map_err(|_| anyhow::anyhow!("signed payout operation persistence failed"))?;
        Ok(transaction)
    }
    pub async fn journal_claim(
        &mut self,
        identity: &Identity,
        evm: &Evm,
        fhe: &Fhe,
        id: Id,
        deadline: u64,
        fees: Fees,
    ) -> Result<SignedTransaction> {
        let a = self.attempt(id)?;
        if let Some(op) = &a.claim {
            return SignedTransaction::restore(op.signed_bytes.clone().into(), op.tx_hash.0.into());
        }
        let r = self.request(evm, id).await?;
        ensure!(
            r.data.status == 1
                && r.eligible
                && r.data.nonzero.0 == a.nonzero_handle.0
                && r.data.feeTermsHash.0 == a.fee_terms_hash.0
                && deadline > r.block.timestamp
                && deadline <= r.block.timestamp.saturating_add(3600),
            "claim scope or deadline mismatch"
        );
        let proof = fhe.public_boolean(r.data.nonzero).await?;
        ensure!(proof.value, "actual burn is zero");
        self.journal_call(
            identity,
            evm,
            id,
            PayoutCall::Claim {
                request: number(id),
                deadline,
                nonzero_proof: proof.decryption_proof,
            },
            fees,
            false,
        )
        .await
    }
    pub async fn submit_claim(&mut self, evm: &Evm, id: Id) -> Result<SubmissionOutcome> {
        self.lease()?;
        let op = self
            .store
            .update(self.policy.domain().vault, |state| {
                Ok(state.attempt_poc_claim(&self.policy, id)?)
            })
            .map_err(|_| anyhow::anyhow!("claim already attempted or persistence failed"))?;
        let tx = SignedTransaction::restore(op.signed_bytes.clone().into(), op.tx_hash.0.into())?;
        Ok(evm.submit_journaled(&tx).await)
    }
    async fn assigned(&mut self, evm: &Evm, id: Id) -> Result<Request> {
        let a = self.attempt(id)?;
        let claim = a.claim.as_ref().context("claim not journaled")?;
        let receipt = evm.receipt(claim.tx_hash.0.into()).await?;
        ensure!(
            receipt.finality == Finality::Finalized
                && receipt.receipt.as_ref().is_some_and(|r| r.status == 1),
            "claim not successful at trusted finalized head"
        );
        let r = self.request(evm, id).await?;
        validate_assignment(self.policy.domain(), &a, &r.data)?;
        ensure!(
            r.block.number
                >= receipt
                    .receipt
                    .as_ref()
                    .context("claim receipt missing")?
                    .block_number,
            "assignment observation precedes claim receipt"
        );
        self.lease()?;
        self.store
            .update(self.policy.domain().vault, |s| {
                s.observe_poc_assignment(
                    &self.policy,
                    id,
                    Id(r.data.assignee.0),
                    evidence(&r.block),
                )?;
                Ok(())
            })
            .map_err(|_| anyhow::anyhow!("assignment persistence failed"))?;
        Ok(r)
    }
    async fn check_inputs(&mut self, chain: &TrustedStagenet, id: Id) -> Result<()> {
        let a = self.attempt(id)?;
        let state = self.load()?;
        for input in &a.payout.reservation.input_ids {
            let deposit = state
                .deposits
                .iter()
                .find(|d| d.output_key == *input && !d.quarantined)
                .context("reserved input unavailable")?;
            let mut bytes = deposit.wallet_output.as_slice();
            let output = WalletOutput::read(&mut bytes)?;
            ensure!(
                bytes.is_empty() && zz_monero::input_id(&output) == *input,
                "reserved input mismatch"
            );
            let observed = ObservedOutput {
                output,
                block: deposit.inclusion.clone(),
                coinbase: false,
            };
            ensure!(
                chain
                    .status(&observed, self.config.monero_confirmations)
                    .await
                    .map_err(|_| anyhow::anyhow!("reserved input status unavailable"))?
                    == ChainStatus::Mature,
                "reserved input no longer mature/canonical"
            );
        }
        Ok(())
    }
    /// A false return means the transport outcome is ambiguous, never that it is safe to replace.
    pub async fn broadcast(&mut self, chain: &TrustedStagenet, evm: &Evm, id: Id) -> Result<bool> {
        self.assigned(evm, id).await?;
        self.check_inputs(chain, id).await?;
        let tip = chain
            .tip()
            .await
            .map_err(|_| anyhow::anyhow!("stagenet unavailable"))?;
        self.lease()?;
        let payout = self
            .store
            .update(self.policy.domain().vault, |s| {
                Ok(s.attempt_poc_broadcast(&self.policy, id, tip)?)
            })
            .map_err(|_| anyhow::anyhow!("payout already attempted or persistence failed"))?;
        Ok(chain.broadcast_journaled(&payout).await.is_ok())
    }
    pub async fn confirm_payment(
        &mut self,
        chain: &TrustedStagenet,
        id: Id,
        height: u64,
    ) -> Result<()> {
        let a = self.attempt(id)?;
        ensure!(a.broadcast_attempted, "payout not attempted");
        let tip = chain
            .tip()
            .await
            .map_err(|_| anyhow::anyhow!("stagenet unavailable"))?;
        ensure!(
            tip.height
                .checked_sub(height)
                .and_then(|d| d.checked_add(1))
                .is_some_and(|d| d >= self.config.monero_confirmations),
            "payment lacks required depth"
        );
        let hash = chain
            .block_hash(height)
            .await
            .map_err(|_| anyhow::anyhow!("stagenet unavailable"))?;
        ensure!(
            chain
                .includes_transaction(height, a.payout.transaction_id)
                .await
                .map_err(|_| anyhow::anyhow!("inclusion unavailable"))?
                && chain
                    .block_hash(height)
                    .await
                    .map_err(|_| anyhow::anyhow!("stagenet unavailable"))?
                    == hash
                && chain
                    .block_hash(tip.height)
                    .await
                    .map_err(|_| anyhow::anyhow!("stagenet unavailable"))?
                    == tip.block_hash,
            "payment not included in consistent trusted chain view"
        );
        self.lease()?;
        self.store
            .update(self.policy.domain().vault, |s| {
                s.confirm_poc_payment(
                    &self.policy,
                    id,
                    ChainEvidence {
                        block_hash: hash,
                        height,
                    },
                )?;
                Ok(())
            })
            .map_err(|_| anyhow::anyhow!("payment inclusion persistence failed"))
    }
    pub async fn journal_settlement(
        &mut self,
        identity: &Identity,
        chain: &TrustedStagenet,
        evm: &Evm,
        id: Id,
        deadline: u64,
        fees: Fees,
    ) -> Result<SignedTransaction> {
        let a = self.attempt(id)?;
        if let Some(op) = &a.settlement {
            return SignedTransaction::restore(op.signed_bytes.clone().into(), op.tx_hash.0.into());
        }
        self.confirm_payment(
            chain,
            id,
            a.inclusion
                .as_ref()
                .context("payment not confirmed")?
                .height,
        )
        .await?;
        let r = self.assigned(evm, id).await?;
        ensure!(
            deadline > r.block.timestamp && deadline <= r.block.timestamp.saturating_add(3600),
            "invalid settlement deadline"
        );
        self.journal_call(
            identity,
            evm,
            id,
            PayoutCall::Settle {
                request: number(id),
                deadline,
                payment_commitment: payment_commitment(&a),
            },
            fees,
            true,
        )
        .await
    }
    pub async fn submit_settlement(
        &mut self,
        chain: &TrustedStagenet,
        evm: &Evm,
        id: Id,
    ) -> Result<SubmissionOutcome> {
        let a = self.attempt(id)?;
        self.confirm_payment(
            chain,
            id,
            a.inclusion
                .as_ref()
                .context("payment not confirmed")?
                .height,
        )
        .await?;
        self.assigned(evm, id).await?;
        self.lease()?;
        let op = self
            .store
            .update(self.policy.domain().vault, |s| {
                Ok(s.attempt_poc_settlement(&self.policy, id)?)
            })
            .map_err(|_| anyhow::anyhow!("settlement already attempted or persistence failed"))?;
        Ok(evm
            .submit_journaled(&SignedTransaction::restore(
                op.signed_bytes.clone().into(),
                op.tx_hash.0.into(),
            )?)
            .await)
    }
    pub async fn confirm_settlement(&mut self, evm: &Evm, id: Id) -> Result<()> {
        let a = self.attempt(id)?;
        let op = a.settlement.as_ref().context("settlement not journaled")?;
        let receipt = evm.receipt(op.tx_hash.0.into()).await?;
        ensure!(
            receipt.finality == Finality::Finalized
                && receipt.receipt.as_ref().is_some_and(|r| r.status == 1),
            "settlement not successful at trusted finalized head"
        );
        let r = self.request(evm, id).await?;
        ensure!(
            r.data.status == 3
                && r.data.assignee.0 == self.policy.domain().vault.0
                && r.data.paymentCommitment.0 == payment_commitment(&a).0,
            "settlement mismatch"
        );
        self.lease()?;
        self.store
            .update(self.policy.domain().vault, |s| {
                s.confirm_poc_settlement(&self.policy, id, evidence(&r.block))?;
                Ok(())
            })
            .map_err(|_| anyhow::anyhow!("settlement persistence failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn attempt() -> PocAttempt {
        PocAttempt {
            payout: zz_core::PreparedPayout {
                reservation: ReservedPayout {
                    request_id: Id([1; 32]),
                    domain: zz_core::Domain {
                        chain_id: 11155111,
                        bridge: [2; 20],
                        vault: Id([3; 32]),
                    },
                    amount: AtomicAmount(90),
                    fee_headroom: AtomicAmount(10),
                    input_ids: vec![Id([4; 32])],
                    destination: String::new(),
                },
                signed_transaction: vec![1],
                transaction_id: Id([5; 32]),
            },
            outgoing_key: [6; 32],
            actual_burn: AtomicAmount(100),
            fee_terms_hash: Id([7; 32]),
            nonzero_handle: Id([8; 32]),
            request_observed: ChainEvidence {
                height: 10,
                block_hash: Id([9; 32]),
            },
            claim: None,
            claim_attempted: false,
            assignment: None,
            broadcast_attempted: false,
            broadcast_from: None,
            inclusion: None,
            settlement: None,
            settlement_attempted: false,
            settled: None,
        }
    }
    #[test]
    fn rejects_lost_claim_race_cancelled_and_changed_terms() {
        let a = attempt();
        let d = &a.payout.reservation.domain;
        let mut r = Bridge::Redemption {
            user: Address::ZERO,
            amount: [11; 32].into(),
            destination: [[12; 32].into(); 3],
            nonzero: a.nonzero_handle.0.into(),
            feeTermsHash: a.fee_terms_hash.0.into(),
            cancelAfter: 0,
            status: 2,
            assignee: d.vault.0.into(),
            paymentCommitment: [0; 32].into(),
        };
        assert!(validate_assignment(d, &a, &r).is_ok());
        r.assignee = [33; 32].into();
        assert!(validate_assignment(d, &a, &r).is_err());
        r.assignee = d.vault.0.into();
        for status in [0, 1, 3, 4] {
            r.status = status;
            assert!(validate_assignment(d, &a, &r).is_err());
        }
        r.status = 2;
        r.nonzero = [55; 32].into();
        assert!(validate_assignment(d, &a, &r).is_err());
        r.nonzero = a.nonzero_handle.0.into();
        r.feeTermsHash = [66; 32].into();
        assert!(validate_assignment(d, &a, &r).is_err());
    }
    #[test]
    fn restart_stage_and_payment_commitment_bind_exact_attempt() {
        let mut a = attempt();
        assert_eq!(next_action(&a), NextAction::JournalClaim);
        let original = payment_commitment(&a);
        a.outgoing_key[0] ^= 1;
        assert_ne!(payment_commitment(&a), original);
        a.outgoing_key[0] ^= 1;
        a.broadcast_attempted = true;
        assert_eq!(next_action(&a), NextAction::FindPayment);
        let restored: PocAttempt =
            serde_json::from_slice(&serde_json::to_vec(&a).unwrap()).unwrap();
        assert_eq!(next_action(&restored), NextAction::FindPayment);
        assert_eq!(payment_commitment(&restored), original);
    }
}
