//! Serialized stagenet payouts. Every state-changing step uses the mint runner's deployment
//! pins and the same PostgreSQL session lease; missing receipts never trigger replacements.
use crate::{
    attestation::{decode, BindingDomain, Identity},
    deposits::Deposits,
    mints::Mints,
    redemptions::{NextAction, PayoutConfig, Redemptions},
};
use alloy::{primitives::B256, sol_types::SolCall};
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use serde_json::json;
use zz_core::{payouts::StagenetPocPolicy, AtomicAmount, Domain, Id};
use zz_monero::stagenet::TrustedStagenet;
use zz_zama::{
    evm::{self, Finality, ReadMethod},
    fhe,
    transaction::Fees,
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub assumption: String,
    pub fee_terms_hash: B256,
    pub fixed_fee_atomic: u64,
    pub network_fee_cap_atomic: u64,
    pub max_fee_per_weight: u64,
    pub confirmations: u64,
    pub evm_deployment_block: u64,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.assumption == "trusted-stagenet-single-operator-no-rollback"
                && !self.fee_terms_hash.is_zero()
                && self.fixed_fee_atomic > 0
                && self.network_fee_cap_atomic > 0
                && self.network_fee_cap_atomic <= self.fixed_fee_atomic
                && self.max_fee_per_weight > 0
                && self.confirmations >= 10
                && self.evm_deployment_block > 0,
            "invalid stagenet withdrawal policy"
        );
        Ok(())
    }
}

pub struct Withdrawals {
    controller: Redemptions,
    evm: evm::Client,
    fhe: fhe::Client,
    fees: Fees,
    cursor: u64,
    payment_cursor: Option<u64>,
}

alloy::sol! { function getCurrentKmsContextId() view returns(uint256); }

impl Withdrawals {
    pub async fn new(
        config: Config,
        fees: Fees,
        deposits: &mut Deposits,
        identity: &Identity,
        binding: &BindingDomain,
        chain: &TrustedStagenet,
    ) -> Result<Self> {
        config.validate()?;
        let domain = Domain {
            chain_id: binding.chain_id,
            bridge: decode(&binding.bridge)?,
            vault: Id(decode(&identity.public()?.vault_id)?),
        };
        let policy = StagenetPocPolicy::accept_single_operator_single_process_no_rollback(domain)?;
        let evm = evm::Client::new("http://127.0.0.1:8788")?;
        let head: evm::BlockObservation = evm
            .read(ReadMethod::BlockByNumber, json!(["finalized", false]))
            .await?
            .result;
        ensure!(
            config.evm_deployment_block <= head.number,
            "withdrawal discovery starts after finalized head"
        );
        let context = evm
            .call(
                zz_zama::SEPOLIA_KMS_VERIFIER,
                getCurrentKmsContextIdCall {}.abi_encode().into(),
                head.hash,
            )
            .await?
            .result;
        let controller = Redemptions::with_lease(
            deposits.payout_store()?,
            policy,
            PayoutConfig {
                fee_terms_hash: Id(config.fee_terms_hash.0),
                fixed_fee: AtomicAmount(config.fixed_fee_atomic),
                network_fee_cap: AtomicAmount(config.network_fee_cap_atomic),
                max_fee_per_weight: config.max_fee_per_weight,
                monero_confirmations: config.confirmations,
                kms_context: getCurrentKmsContextIdCall::abi_decode_returns_validate(&context)?,
            },
            identity,
            chain,
        )?;
        Ok(Self {
            controller,
            evm,
            fhe: fhe::Client::new("http://127.0.0.1:8788")?,
            fees,
            cursor: config.evm_deployment_block,
            payment_cursor: None,
        })
    }

    pub fn has_pending(&mut self) -> Result<bool> {
        Ok(!self.controller.pending()?.is_empty())
    }

    async fn finalized_success(&self, id: Id) -> Result<bool> {
        let observation = self.evm.receipt(id.0.into()).await?;
        if observation.finality != Finality::Finalized {
            return Ok(false);
        }
        ensure!(
            observation.receipt.is_some_and(|r| r.status == 1),
            "payout transaction reverted; explicit reconciliation required"
        );
        Ok(true)
    }

    /// Caller holds the shared runtime mutex and resolves submitted mints before entering.
    pub async fn step(
        &mut self,
        identity: &Identity,
        binding: &BindingDomain,
        chain: &TrustedStagenet,
        mints: &Mints,
    ) -> Result<()> {
        if let Some((id, action)) = self.controller.pending()?.first().copied() {
            mints.verify(identity, binding).await?;
            match action {
                NextAction::JournalClaim | NextAction::JournalSettlement => {
                    let head: evm::BlockObservation = self
                        .evm
                        .read(ReadMethod::BlockByNumber, json!(["latest", false]))
                        .await?
                        .result;
                    let deadline = head
                        .timestamp
                        .checked_add(600)
                        .context("payout deadline overflow")?;
                    if action == NextAction::JournalClaim {
                        self.controller
                            .journal_claim(identity, &self.evm, &self.fhe, id, deadline, self.fees)
                            .await?;
                    } else {
                        self.controller
                            .journal_settlement(identity, chain, &self.evm, id, deadline, self.fees)
                            .await?;
                    }
                }
                NextAction::SubmitClaim => {
                    self.controller.submit_claim(&self.evm, id).await?;
                }
                NextAction::WaitForAssignmentThenBroadcast => {
                    let hash = self
                        .controller
                        .pending_hash(id)?
                        .context("claim hash missing")?;
                    if self.finalized_success(hash).await? {
                        self.controller.broadcast(chain, &self.evm, id).await?;
                    }
                }
                NextAction::FindPayment => {
                    let (found, next) = self
                        .controller
                        .find_payment(chain, id, self.payment_cursor)
                        .await?;
                    self.payment_cursor = if found.is_some() { None } else { Some(next) };
                }
                NextAction::SubmitSettlement => {
                    self.controller
                        .submit_settlement(chain, &self.evm, id)
                        .await?;
                }
                NextAction::ConfirmSettlement => {
                    let hash = self
                        .controller
                        .pending_hash(id)?
                        .context("settlement hash missing")?;
                    if self.finalized_success(hash).await? {
                        self.controller.confirm_settlement(&self.evm, id).await?;
                    }
                }
                NextAction::Complete => {}
            }
            return Ok(());
        }
        let head: evm::BlockObservation = self
            .evm
            .read(ReadMethod::BlockByNumber, json!(["finalized", false]))
            .await?
            .result;
        if self.cursor > head.number {
            return Ok(());
        }
        let to = head.number.min(self.cursor.saturating_add(255));
        for id in self.controller.discover(&self.evm, self.cursor, to).await? {
            mints.verify(identity, binding).await?;
            self.controller
                .prepare(identity, chain, &self.evm, &self.fhe, id)
                .await?;
            if self.has_pending()? {
                return Ok(());
            }
        }
        self.cursor = to.checked_add(1).context("withdrawal cursor overflow")?;
        Ok(())
    }
}
