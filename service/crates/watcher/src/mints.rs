//! One serialized mint step. The caller owns the single active vault process and must not
//! schedule another Ethereum operation while a previous mint remains unresolved.
use crate::{
    attestation::{decode, BindingDomain, Identity},
    deposits::Deposits,
    prover::Prover,
};
use alloy::{
    primitives::{keccak256, Address, Bytes, B256},
    sol_types::SolCall,
};
use anyhow::{ensure, Result};
use serde::Deserialize;
use zz_monero::stagenet::TrustedStagenet;
use zz_zama::{evm, fhe, transaction::Fees};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub assumption: String,
    pub expected_vault_id: B256,
    pub bridge_code_hash: B256,
    pub registry_code_hash: B256,
    pub adapter: Address,
    pub adapter_code_hash: B256,
    pub confirmations: u64,
    #[serde(default)]
    pub demo_mint_confirmations: Option<u64>,
    pub gas_limit: u64,
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
    #[serde(default)]
    pub retry_expired_mint: Option<ExpiredMintRetry>,
    #[serde(default)]
    pub retry_reverted_mint: Option<RevertedMintRetry>,
}

/// One operator-reviewed failed authorization, pinned in the measured configuration.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpiredMintRetry {
    pub deposit_id: B256,
    pub expired_deadline: u64,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevertedMintRetry {
    pub deposit_id: B256,
    pub transaction_hash: B256,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.retry_expired_mint.is_none() || self.retry_reverted_mint.is_none(),
            "select only one explicit mint recovery"
        );
        if let Some(retry) = &self.retry_reverted_mint {
            ensure!(
                !retry.deposit_id.is_zero() && !retry.transaction_hash.is_zero(),
                "invalid explicit reverted-mint retry"
            );
        }
        if let Some(retry) = &self.retry_expired_mint {
            ensure!(
                !retry.deposit_id.is_zero() && retry.expired_deadline > 0,
                "invalid explicit expired-mint retry"
            );
        }
        ensure!(
            self.assumption == "trusted-stagenet-single-operator-no-rollback"
                && !self.expected_vault_id.is_zero()
                && !self.bridge_code_hash.is_zero()
                && !self.registry_code_hash.is_zero()
                && !self.adapter.is_zero()
                && !self.adapter_code_hash.is_zero()
                && self.confirmations >= 10
                && self.demo_mint_confirmations.is_none_or(|n| n >= 3)
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

alloy::sol! { interface MintPins {
    function registry() view returns(address);
    function bridge() view returns(address);
    function adapter() view returns(address);
    function configurationValid() view returns(bool);
    function approvedPcrTuples(uint64 version,bytes32 tuple) view returns(bool);
} }

async fn read<C: SolCall>(
    evm: &evm::Client,
    to: Address,
    block: B256,
    call: C,
) -> Result<C::Return> {
    Ok(C::abi_decode_returns_validate(
        &evm.call(to, call.abi_encode().into(), block).await?.result,
    )?)
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

    /// Pinned adapter bytecode commits to its real verifier and ZK route. Its configuration
    /// check verifies those immutable pins again; the unsafe test adapter has a different hash.
    pub async fn verify(&self, identity: &Identity, binding: &BindingDomain) -> Result<()> {
        ensure!(
            binding.chain_id == evm::CHAIN_ID,
            "mint driver is Sepolia-only"
        );
        ensure!(
            B256::from(decode::<32>(&identity.public()?.vault_id)?)
                == self.config.expected_vault_id,
            "restored vault differs from approved identity"
        );
        let bridge = Address::from(decode::<20>(&binding.bridge)?);
        let registry = Address::from(decode::<20>(&binding.registry)?);
        let head: evm::BlockObservation = self
            .evm
            .read(
                evm::ReadMethod::BlockByNumber,
                serde_json::json!(["latest", false]),
            )
            .await?
            .result;
        for (address, hash) in [
            (bridge, self.config.bridge_code_hash),
            (registry, self.config.registry_code_hash),
            (self.config.adapter, self.config.adapter_code_hash),
        ] {
            let code: Bytes = self
                .evm
                .read(
                    evm::ReadMethod::Code,
                    serde_json::json!([address,{"blockHash":head.hash,"requireCanonical":true}]),
                )
                .await?
                .result;
            ensure!(
                !code.is_empty() && keccak256(&code) == hash,
                "mint deployment bytecode changed"
            );
        }
        ensure!(
            read(&self.evm, bridge, head.hash, MintPins::registryCall {}).await? == registry
                && read(&self.evm, registry, head.hash, MintPins::bridgeCall {}).await? == bridge
                && read(&self.evm, registry, head.hash, MintPins::adapterCall {}).await?
                    == self.config.adapter
                && read(
                    &self.evm,
                    self.config.adapter,
                    head.hash,
                    MintPins::configurationValidCall {}
                )
                .await?,
            "mint deployment links or verifier configuration changed"
        );
        ensure!(
            read(
                &self.evm,
                registry,
                head.hash,
                MintPins::approvedPcrTuplesCall {
                    version: binding.policy_version,
                    tuple: crate::attestation::current_pcr_tuple()?,
                }
            )
            .await?,
            "current enclave image is not approved for minting"
        );
        Ok(())
    }

    /// No implicit retry: recovery requires a specific finalized revert selected in measured config.
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
            deposits.check_mint_lease()?;
            self.verify(identity, binding).await?;
            let recovered = if submitted {
                if let Some(retry) = self
                    .config
                    .retry_reverted_mint
                    .as_ref()
                    .filter(|r| r.deposit_id.0 == id.0)
                {
                    deposits
                        .recover_reverted_mint(
                            identity,
                            chain,
                            &self.evm,
                            id,
                            zz_core::Id(retry.transaction_hash.0),
                            self.config.confirmations,
                        )
                        .await?
                } else {
                    false
                }
            } else {
                false
            };
            if submitted && !recovered {
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
            if let Some(retry) = &self.config.retry_expired_mint {
                if retry.deposit_id.0 == id.0 {
                    deposits
                        .renew_expired_mint(
                            identity,
                            chain,
                            &self.evm,
                            id,
                            retry.expired_deadline,
                            self.config.confirmations,
                        )
                        .await?;
                }
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
            deposits.check_mint_lease()?;
            self.verify(identity, binding).await?;
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
            deposits.check_mint_lease()?;
            let _ = deposits
                .submit_mint(chain, &self.evm, id, self.config.confirmations)
                .await?;
            return Ok(Progress::Pending);
        }
        Ok(Progress::Idle)
    }
}
