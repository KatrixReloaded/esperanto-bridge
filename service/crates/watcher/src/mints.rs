//! One serialized mint step. The caller owns the single active vault process and must not
//! schedule another Ethereum operation while a previous mint remains unresolved.
use crate::{
    attestation::{decode, BindingDomain, Identity},
    deposits::Deposits,
    prover::Prover,
};
use anyhow::{ensure, Result};
use serde::Deserialize;
use zz_monero::stagenet::TrustedStagenet;
use zz_zama::{evm, fhe, transaction::Fees};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub confirmations: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.confirmations >= 10
                && self.gas_limit > 0
                && self.gas_limit <= 10_000_000
                && self.max_fee_per_gas > 0
                && self.max_priority_fee_per_gas <= self.max_fee_per_gas,
            "invalid stagenet mint policy"
        );
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Progress {
    Idle,
    /// The exact signed transaction remains pending. Do not schedule another EVM operation.
    Pending,
    Confirmed,
}

pub struct Mints {
    config: Config,
    prover: Prover,
    fhe: fhe::Client,
    evm: evm::Client,
}

impl Mints {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            prover: Prover::new()?,
            fhe: fhe::Client::new("http://127.0.0.1:8788")?,
            evm: evm::Client::new("http://127.0.0.1:8788")?,
        })
    }

    /// No implicit retry of a submitted transaction: restart resumes receipt reconciliation.
    /// A crash between journal and send requires explicit operator reconciliation/resubmission
    /// of those same bytes. No alternate authorization or replacement transaction is created.
    pub async fn step(
        &self,
        deposits: &mut Deposits,
        identity: &Identity,
        binding: &BindingDomain,
        chain: &TrustedStagenet,
    ) -> Result<Progress> {
        ensure!(
            binding.chain_id == evm::CHAIN_ID,
            "mint driver is Sepolia-only"
        );
        for (id, submitted) in deposits.pending_mints()? {
            if submitted {
                return Ok(
                    if deposits
                        .reconcile_mint(identity, &self.evm, &self.fhe, id)
                        .await?
                    {
                        Progress::Confirmed
                    } else {
                        Progress::Pending
                    },
                );
            }
            let Some((request, document)) = deposits
                .prepare_mint(
                    identity,
                    binding,
                    chain,
                    &self.fhe,
                    &self.evm,
                    id,
                    self.config.confirmations,
                    600,
                )
                .await?
            else {
                continue;
            };
            let calldata = self
                .prover
                .candidate(decode::<20>(&binding.bridge)?.into(), request, &document)
                .await?;
            deposits
                .journal_mint_transaction(
                    identity,
                    chain,
                    &self.evm,
                    id,
                    self.config.confirmations,
                    calldata,
                    Fees {
                        gas_limit: self.config.gas_limit,
                        max_fee_per_gas: u128::from(self.config.max_fee_per_gas),
                        max_priority_fee_per_gas: u128::from(self.config.max_priority_fee_per_gas),
                    },
                )
                .await?;
            // Either outcome requires reconciliation. Never treat an RPC acknowledgement as a mint.
            let _ = deposits
                .submit_mint(chain, &self.evm, id, self.config.confirmations)
                .await?;
            return Ok(Progress::Pending);
        }
        Ok(Progress::Idle)
    }
}
