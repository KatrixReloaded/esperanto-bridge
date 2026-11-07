//! Enclave-local deposit issuance and scan persistence. No RPC observation directly signs a mint.
use crate::attestation::{decode, BindingDomain, Identity};
use alloy::primitives::{keccak256, Address, U256};
use alloy::sol_types::{SolCall, SolEvent};
use anyhow::{ensure, Result};
use monero_wallet::{address::Network, Scanner, ViewPair};
use serde_json::json;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;
use zz_core::{
    deposits::{Deposit, MintState},
    storage::PostgresStore,
    ChainEvidence, DepositIntent, Domain, Id,
};
use zz_monero::chain::ObservedOutput;
use zz_monero::{chain::ChainStatus, stagenet::TrustedStagenet};

alloy::sol! { function getCurrentKmsContextId() external view returns (uint256); }
alloy::sol! { interface RetryPins {
    function consumedDeposits(bytes32 depositId) view returns (bool);
    function usedMintNonces(bytes32 vaultId,uint256 nonce) view returns (bool);
} }

enum MintRecovery {
    Expired(u64),
    Reverted(Id),
}

pub struct Deposits {
    store: PostgresStore,
    domain: Domain,
    pair: ViewPair,
    id_key: Zeroizing<[u8; 32]>,
}

pub(crate) struct PreparedMint {
    pub request: zz_zama::mint::Mint,
    #[cfg(feature = "unsafe-test")]
    pub input_proof: alloy::primitives::Bytes,
    pub signature: alloy::primitives::Bytes,
    pub proof_request: serde_json::Value,
}

#[derive(Debug)]
pub struct ChainUnavailable;
impl std::fmt::Display for ChainUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("trusted chain unavailable")
    }
}
impl std::error::Error for ChainUnavailable {}

impl Deposits {
    /// Cooperative single-process fence for the explicitly trusted stagenet mint runner.
    /// It does not protect against a malicious PostgreSQL operator or cloned database.
    pub fn acquire_mint_lease(&mut self) -> Result<()> {
        self.store
            .acquire_stagenet_poc_lease(self.domain.vault)
            .map_err(|_| anyhow::anyhow!("cooperative mint lease unavailable"))
    }

    pub fn check_mint_lease(&mut self) -> Result<()> {
        self.store
            .check_stagenet_poc_lease(self.domain.vault)
            .map_err(|_| anyhow::anyhow!("cooperative mint lease lost"))
    }

    /// Public identifiers only, with unresolved submitted transactions first. A quarantined
    /// unfinished mint blocks new authorizations until an operator reconciles the journal.
    pub fn pending_mints(&mut self) -> Result<Vec<(Id, bool)>> {
        let state = self
            .store
            .load(self.domain.vault)
            .map_err(|_| anyhow::anyhow!("vault state unavailable"))?;
        ensure!(
            !state
                .deposits
                .iter()
                .any(|d| d.quarantined && !matches!(d.state, MintState::Confirmed { .. })),
            "quarantined mint requires reconciliation"
        );
        let mut pending: Vec<_> = state
            .deposits
            .iter()
            .filter(|d| !d.quarantined && !matches!(d.state, MintState::Confirmed { .. }))
            .map(|d| (d.id, matches!(d.state, MintState::Submitted { .. })))
            .collect();
        pending.sort_by_key(|(_, submitted)| !submitted);
        Ok(pending)
    }
    /// Reconcile only the exact finalized mint receipt and its scoped decrypted actual amount.
    /// Nothing is credited from an RPC acknowledgement, unfinalized receipt or requested amount.
    pub async fn reconcile_mint(
        &mut self,
        identity: &Identity,
        evm: &zz_zama::evm::Client,
        fhe: &zz_zama::fhe::Client,
        id: Id,
    ) -> Result<bool> {
        let state = self
            .store
            .load(self.domain.vault)
            .map_err(|_| anyhow::anyhow!("vault state unavailable"))?;
        let deposit = state
            .deposits
            .iter()
            .find(|d| d.id == id)
            .ok_or_else(|| anyhow::anyhow!("unknown deposit"))?;
        ensure!(!deposit.quarantined, "deposit quarantined");
        let transaction = match deposit.state {
            MintState::Submitted { transaction, .. } => transaction,
            MintState::Confirmed { .. } => return Ok(true),
            _ => anyhow::bail!("mint not submitted"),
        };
        let intent = state
            .intents
            .iter()
            .find(|i| i.id == deposit.intent_id && i.domain == self.domain)
            .ok_or_else(|| anyhow::anyhow!("intent domain mismatch"))?;
        let observation = evm.receipt(transaction.0.into()).await?;
        if observation.finality != zz_zama::evm::Finality::Finalized {
            return Ok(false);
        }
        let receipt = observation
            .receipt
            .ok_or_else(|| anyhow::anyhow!("finalized receipt missing"))?;
        if receipt.status != 1 {
            self.store
                .update(self.domain.vault, |state| {
                    state.quarantine_deposit(id)?;
                    Ok(())
                })
                .map_err(|_| anyhow::anyhow!("reverted mint persistence failed"))?;
            anyhow::bail!("mint reverted; reconciliation required");
        }
        let handle = mint_event_handle(&receipt.logs, &self.domain, id, intent.recipient)?;
        let head = observation
            .finalized_head
            .ok_or_else(|| anyhow::anyhow!("finalized head missing"))?;
        let read = zz_zama::Bridge::mintedAmountsCall(id.0.into());
        let stored = evm
            .call(
                Address::from(self.domain.bridge),
                read.abi_encode().into(),
                head.hash,
            )
            .await?
            .result;
        ensure!(
            zz_zama::Bridge::mintedAmountsCall::abi_decode_returns_validate(&stored)? == handle,
            "mint amount handle mismatch"
        );
        let kms = zz_zama::SEPOLIA_KMS_VERIFIER;
        let context = evm
            .call(
                kms,
                getCurrentKmsContextIdCall {}.abi_encode().into(),
                head.hash,
            )
            .await?
            .result;
        let context = getCurrentKmsContextIdCall::abi_decode_returns_validate(&context)?;
        let signer = identity.decrypt_signer()?;
        let scope = zz_zama::fhe::Scope {
            contract: Address::from(self.domain.bridge),
            user: signer.address(),
            handle,
            width: zz_zama::fhe::Width::Uint64,
        };
        let permit = fhe
            .prepare_decryption(scope)
            .await?
            .authorize(&signer, context)
            .await?;
        let actual = zz_core::AtomicAmount(fhe.decrypt(permit).await?);
        ensure!(actual <= deposit.amount, "actual mint exceeds backing");
        let after = evm.receipt(transaction.0.into()).await?;
        ensure!(
            after.finality == zz_zama::evm::Finality::Finalized
                && after
                    .receipt
                    .as_ref()
                    .is_some_and(|r| r.block_hash == receipt.block_hash && r.status == 1),
            "receipt changed during decryption"
        );
        self.store
            .update(self.domain.vault, |state| {
                state.confirm_mint(
                    id,
                    transaction,
                    actual,
                    ChainEvidence {
                        height: receipt.block_number,
                        block_hash: Id(receipt.block_hash.0),
                    },
                )?;
                if actual.0 != 0 {
                    state.record_mint_result(id, actual)?;
                }
                Ok(())
            })
            .map_err(|_| anyhow::anyhow!("mint confirmation persistence failed"))?;
        Ok(true)
    }
    /// Recover exactly the expired authorization selected by measured operator configuration.
    /// No transaction may have been journaled. The old proof/request must be reconciled separately.
    pub async fn renew_expired_mint(
        &mut self,
        identity: &Identity,
        chain: &TrustedStagenet,
        evm: &zz_zama::evm::Client,
        id: Id,
        expected_deadline: u64,
        confirmations: u64,
    ) -> Result<()> {
        self.recover_mint(
            identity,
            chain,
            evm,
            id,
            MintRecovery::Expired(expected_deadline),
            confirmations,
        )
        .await?;
        Ok(())
    }

    /// Only the exact transaction selected in the measured image may enter this recovery path.
    pub async fn recover_reverted_mint(
        &mut self,
        identity: &Identity,
        chain: &TrustedStagenet,
        evm: &zz_zama::evm::Client,
        id: Id,
        transaction: Id,
        confirmations: u64,
    ) -> Result<bool> {
        self.recover_mint(
            identity,
            chain,
            evm,
            id,
            MintRecovery::Reverted(transaction),
            confirmations,
        )
        .await
    }

    async fn recover_mint(
        &mut self,
        identity: &Identity,
        chain: &TrustedStagenet,
        evm: &zz_zama::evm::Client,
        id: Id,
        recovery: MintRecovery,
        confirmations: u64,
    ) -> Result<bool> {
        let state = self
            .store
            .load(self.domain.vault)
            .map_err(|_| anyhow::anyhow!("vault state unavailable"))?;
        let deposit = state
            .deposits
            .iter()
            .find(|d| d.id == id)
            .ok_or_else(|| anyhow::anyhow!("unknown retry deposit"))?;
        ensure!(!deposit.quarantined, "quarantined mint cannot be recovered");
        let (old, reverted) = match (&recovery, &deposit.state) {
            (MintRecovery::Expired(expected), MintState::Authorized(old)) => {
                if old.deadline != *expected {
                    ensure!(old.deadline > *expected, "unexpected retry authorization");
                    return Ok(false);
                }
                ensure!(
                    !state.evm_operations.iter().any(|op| op.operation_id == id),
                    "journaled mint cannot be renewed"
                );
                (old, None)
            }
            (
                MintRecovery::Reverted(expected),
                MintState::Submitted {
                    authorization,
                    transaction,
                },
            ) => {
                if transaction != expected {
                    return Ok(false);
                }
                let observation = evm.receipt(transaction.0.into()).await?;
                let Some(inclusion) = observation.finalized_revert(transaction.0.into())? else {
                    return Ok(false);
                };
                (authorization, Some((*transaction, inclusion)))
            }
            _ => anyhow::bail!("mint state does not permit selected recovery"),
        };
        ensure!(
            self.eligible(chain, id, confirmations).await?.is_some(),
            "retry deposit is not eligible"
        );
        let head: zz_zama::evm::BlockObservation = evm
            .read(
                zz_zama::evm::ReadMethod::BlockByNumber,
                json!(["latest", false]),
            )
            .await?
            .result;
        ensure!(
            head.timestamp > old.deadline,
            "retry authorization has not expired"
        );
        let bridge = Address::from(self.domain.bridge);
        let consumed = evm
            .call(
                bridge,
                RetryPins::consumedDepositsCall {
                    depositId: id.0.into(),
                }
                .abi_encode()
                .into(),
                head.hash,
            )
            .await?
            .result;
        let used = evm
            .call(
                bridge,
                RetryPins::usedMintNoncesCall {
                    vaultId: self.domain.vault.0.into(),
                    nonce: U256::from(old.nonce),
                }
                .abi_encode()
                .into(),
                head.hash,
            )
            .await?
            .result;
        ensure!(
            !RetryPins::consumedDepositsCall::abi_decode_returns_validate(&consumed)?
                && !RetryPins::usedMintNoncesCall::abi_decode_returns_validate(&used)?,
            "mint already consumed; reconcile instead of renewing"
        );
        let intent = state
            .intents
            .iter()
            .find(|i| i.id == deposit.intent_id && i.domain == self.domain)
            .ok_or_else(|| anyhow::anyhow!("retry intent missing"))?;
        let deadline = head
            .timestamp
            .checked_add(600)
            .ok_or_else(|| anyhow::anyhow!("retry deadline overflow"))?;
        let signature = zz_zama::mint::sign_mint(
            &identity.mint_signer()?,
            &self.domain,
            id,
            intent.recipient,
            old.amount_handle.0,
            &old.input_proof,
            old.nonce,
            deadline,
        )
        .map_err(anyhow::Error::msg)?;
        if let Some((transaction, inclusion)) = &reverted {
            let after = evm.receipt(transaction.0.into()).await?;
            ensure!(
                after.finalized_revert(transaction.0.into())?.as_ref() == Some(inclusion),
                "finalized reverted receipt changed during recovery"
            );
        }
        self.check_mint_lease()?;
        self.store
            .update(self.domain.vault, |state| {
                if let Some((transaction, inclusion)) = reverted {
                    state.recover_reverted_mint(
                        id,
                        transaction,
                        inclusion,
                        head.timestamp,
                        deadline,
                        signature,
                    )?;
                } else {
                    state.renew_expired_mint(
                        id,
                        old.deadline,
                        head.timestamp,
                        deadline,
                        signature,
                    )?;
                }
                Ok(())
            })
            .map_err(|_| anyhow::anyhow!("retry authorization persistence failed"))?;
        Ok(true)
    }

    /// Validate the prover's calldata against the durable authorization, then persist the exact
    /// signed envelope before handing it to any network transport. No transaction is sent here.
    pub async fn journal_mint_transaction(
        &mut self,
        identity: &Identity,
        chain: &TrustedStagenet,
        evm: &zz_zama::evm::Client,
        id: Id,
        confirmations: u64,
        calldata: Vec<u8>,
        fees: zz_zama::transaction::Fees,
    ) -> Result<zz_zama::evm::SignedTransaction> {
        ensure!(
            self.eligible(chain, id, confirmations).await?.is_some(),
            "deposit not eligible"
        );
        let state = self
            .store
            .load(self.domain.vault)
            .map_err(|_| anyhow::anyhow!("vault state unavailable"))?;
        if let Some(operation) = state
            .evm_operations
            .iter()
            .find(|op| op.operation_id == id && op.domain == self.domain)
        {
            return zz_zama::evm::SignedTransaction::restore(
                operation.signed_bytes.clone().into(),
                operation.tx_hash.0.into(),
            );
        }
        let deposit = state
            .deposits
            .iter()
            .find(|d| d.id == id)
            .ok_or_else(|| anyhow::anyhow!("unknown deposit"))?;
        let intent = state
            .intents
            .iter()
            .find(|i| i.id == deposit.intent_id && i.domain == self.domain)
            .ok_or_else(|| anyhow::anyhow!("intent domain mismatch"))?;
        let MintState::Authorized(authorization) = &deposit.state else {
            anyhow::bail!("deposit not authorized");
        };
        let signer = identity.mint_signer()?;
        let sender = signer.address();
        // Treat operator/prover output as untrusted. Simulate the exact complete call through
        // the enclave's Nym transport, including the actual FHE input sender, before signing gas.
        let head: zz_zama::evm::BlockObservation = evm
            .read(
                zz_zama::evm::ReadMethod::BlockByNumber,
                json!(["latest", false]),
            )
            .await?
            .result;
        ensure!(
            head.timestamp <= authorization.deadline,
            "mint authorization expired"
        );
        let nonce: String = evm
            .read(
                zz_zama::evm::ReadMethod::TransactionCount,
                json!([sender, "pending"]),
            )
            .await?
            .result;
        let nonce = u64::from_str_radix(
            nonce
                .strip_prefix("0x")
                .ok_or_else(|| anyhow::anyhow!("invalid nonce"))?,
            16,
        )?;
        let request = zz_zama::mint::Mint {
            vaultId: self.domain.vault.0.into(),
            depositId: id.0.into(),
            recipient: intent.recipient.into(),
            amountHandle: authorization.amount_handle.0.into(),
            inputProofHash: keccak256(&authorization.input_proof),
            nonce: U256::from(authorization.nonce),
            deadline: authorization.deadline,
        };
        let transaction = zz_zama::transaction::sign_mint_transaction(
            &signer,
            &self.domain,
            &request,
            &authorization.input_proof,
            &authorization.signature,
            calldata.into(),
            nonce,
            fees,
        )?;
        let _: zz_zama::evm::Observation<String> = evm
            .read(
                zz_zama::evm::ReadMethod::Call,
                json!([transaction.simulation_call()?,
                    {"blockHash":head.hash,"requireCanonical":true}]),
            )
            .await?;
        let operation = zz_core::EvmOperation {
            domain: self.domain.clone(),
            operation_id: id,
            signer: sender.into_array(),
            nonce,
            signed_bytes: transaction.raw().to_vec(),
            tx_hash: Id(transaction.hash().0),
        };
        self.store
            .update(self.domain.vault, |state| {
                state.journal_mint(id, operation)?;
                Ok(())
            })
            .map_err(|_| anyhow::anyhow!("signed mint persistence failed"))?;
        Ok(transaction)
    }

    /// An explicit retry can only send the original journaled bytes, after a fresh source check.
    /// Ambiguous outcomes stay Submitted; absence of a receipt never permits a replacement.
    pub async fn submit_mint(
        &mut self,
        chain: &TrustedStagenet,
        evm: &zz_zama::evm::Client,
        id: Id,
        confirmations: u64,
    ) -> Result<zz_zama::evm::SubmissionOutcome> {
        ensure!(
            self.eligible(chain, id, confirmations).await?.is_some(),
            "deposit not eligible"
        );
        let state = self
            .store
            .load(self.domain.vault)
            .map_err(|_| anyhow::anyhow!("vault state unavailable"))?;
        let deposit = state
            .deposits
            .iter()
            .find(|d| d.id == id)
            .ok_or_else(|| anyhow::anyhow!("unknown deposit"))?;
        let MintState::Submitted {
            transaction: expected,
            ..
        } = deposit.state
        else {
            anyhow::bail!("mint not pending");
        };
        let operation = state
            .evm_operations
            .iter()
            .find(|op| op.domain == self.domain && op.operation_id == id && op.tx_hash == expected)
            .ok_or_else(|| anyhow::anyhow!("signed transaction missing"))?;
        let signed = zz_zama::evm::SignedTransaction::restore(
            operation.signed_bytes.clone().into(),
            expected.0.into(),
        )?;
        Ok(evm.submit_journaled(&signed).await)
    }
    pub fn get(&mut self, intent_id: Id) -> Result<serde_json::Value> {
        let state = self
            .store
            .load(self.domain.vault)
            .map_err(|_| anyhow::anyhow!("vault state unavailable"))?;
        let intent = state
            .intents
            .iter()
            .find(|i| i.id == intent_id && i.domain == self.domain)
            .ok_or_else(|| anyhow::anyhow!("unknown intent"))?;
        let deposits = state
            .deposits
            .iter()
            .filter(|d| d.intent_id == intent_id)
            .collect::<Vec<_>>();
        let status = if deposits.iter().any(|d| d.quarantined) {
            "quarantined"
        } else if deposits
            .iter()
            .any(|d| matches!(d.state, MintState::Submitted { .. }))
        {
            "minting"
        } else if deposits
            .iter()
            .any(|d| matches!(d.state, MintState::Authorized(_)))
        {
            "proving"
        } else if deposits
            .iter()
            .any(|d| matches!(d.state, MintState::Observed))
        {
            "confirming"
        } else if deposits.iter().any(|d| {
            matches!(
                d.state,
                MintState::Confirmed {
                    actual: zz_core::AtomicAmount(0),
                    ..
                }
            )
        }) {
            "failed"
        } else if deposits.is_empty() {
            "awaiting_deposit"
        } else {
            "minted"
        };
        Ok(json!({"intentId":format!("0x{}",hex::encode(intent.id.0)),
            "vaultId":format!("0x{}",hex::encode(intent.domain.vault.0)),
            "recipient":format!("0x{}",hex::encode(intent.recipient)),
            "depositAddress":intent.subaddress,"network":"stagenet","status":status}))
    }
    /// Prepare a real request-bound NSM document only after a fresh trusted-node maturity check.
    /// The returned data is public proof material; wallet keys and plaintext amount stay internal.
    /// No native-development attestation substitute exists. This is not a public signing endpoint.
    pub async fn prepare_mint(
        &mut self,
        identity: &Identity,
        binding: &BindingDomain,
        chain: &TrustedStagenet,
        fhe: &zz_zama::fhe::Client,
        evm: &zz_zama::evm::Client,
        id: Id,
        confirmations: u64,
        lifetime: u64,
    ) -> Result<Option<(serde_json::Value, Vec<u8>)>> {
        let Some(prepared) = self
            .prepare_mint_authorization(
                identity,
                binding,
                chain,
                fhe,
                evm,
                id,
                confirmations,
                lifetime,
            )
            .await?
        else {
            return Ok(None);
        };
        // Normal path ALWAYS requires real NSM, including when unsafe-test was compiled.
        let document = identity.attest_mint(binding, &prepared.request, &prepared.signature)?;
        Ok(Some((prepared.proof_request, document)))
    }
    pub(crate) async fn prepare_mint_authorization(
        &mut self,
        identity: &Identity,
        binding: &BindingDomain,
        chain: &TrustedStagenet,
        fhe: &zz_zama::fhe::Client,
        evm: &zz_zama::evm::Client,
        id: Id,
        confirmations: u64,
        lifetime: u64,
    ) -> Result<Option<PreparedMint>> {
        ensure!(
            lifetime > 0 && lifetime <= 600,
            "mint lifetime exceeds attestation policy"
        );
        let public = identity.public()?;
        ensure!(
            binding.chain_id == self.domain.chain_id
                && decode::<20>(&binding.bridge)? == self.domain.bridge
                && decode::<32>(&public.vault_id)? == self.domain.vault.0,
            "mint domain mismatch"
        );
        let Some(deposit) = self.eligible(chain, id, confirmations).await? else {
            return Ok(None);
        };
        let state = self
            .store
            .load(self.domain.vault)
            .map_err(|_| anyhow::anyhow!("vault state unavailable"))?;
        let intent = state
            .intents
            .iter()
            .find(|i| i.id == deposit.intent_id && i.domain == self.domain)
            .ok_or_else(|| anyhow::anyhow!("intent missing"))?;
        let authorization = match deposit.state {
            MintState::Observed => {
                let nonce = state
                    .deposits
                    .iter()
                    .filter_map(|d| match &d.state {
                        MintState::Authorized(a)
                        | MintState::Submitted {
                            authorization: a, ..
                        }
                        | MintState::Confirmed {
                            authorization: a, ..
                        } => Some(a.nonce),
                        _ => None,
                    })
                    .max()
                    .map(|n| n.checked_add(1))
                    .unwrap_or(Some(0))
                    .ok_or_else(|| anyhow::anyhow!("nonce overflow"))?;
                let encrypted = fhe
                    .encrypt(
                        Address::from(self.domain.bridge),
                        Address::from(decode::<20>(&public.signing_key)?),
                        deposit.amount.0,
                    )
                    .await?;
                let clock: zz_zama::evm::BlockObservation = evm
                    .read(
                        zz_zama::evm::ReadMethod::BlockByNumber,
                        json!(["latest", false]),
                    )
                    .await?
                    .result;
                let deadline = clock
                    .timestamp
                    .checked_add(lifetime)
                    .ok_or_else(|| anyhow::anyhow!("deadline overflow"))?;
                let signature = zz_zama::mint::sign_mint(
                    &identity.mint_signer()?,
                    &self.domain,
                    id,
                    intent.recipient,
                    encrypted.handle.0,
                    &encrypted.input_proof,
                    nonce,
                    deadline,
                )
                .map_err(anyhow::Error::msg)?;
                let a = zz_core::deposits::MintAuthorization {
                    amount_handle: Id(encrypted.handle.0),
                    input_proof: encrypted.input_proof.to_vec(),
                    nonce,
                    deadline,
                    signature,
                };
                self.store
                    .update(self.domain.vault, |state| {
                        state.authorize_mint(id, a.clone())?;
                        Ok(())
                    })
                    .map_err(|_| anyhow::anyhow!("mint authorization persistence failed"))?;
                a
            }
            MintState::Authorized(a) => a,
            _ => anyhow::bail!("mint already journaled or confirmed"),
        };
        let request = zz_zama::mint::Mint {
            vaultId: self.domain.vault.0.into(),
            depositId: id.0.into(),
            recipient: intent.recipient.into(),
            amountHandle: authorization.amount_handle.0.into(),
            inputProofHash: keccak256(&authorization.input_proof),
            nonce: U256::from(authorization.nonce),
            deadline: authorization.deadline,
        };
        // Encryption can take time. Check the source again before releasing the attestation.
        ensure!(
            self.eligible(chain, id, confirmations).await?.is_some(),
            "deposit is no longer eligible"
        );
        let clock: zz_zama::evm::BlockObservation = evm
            .read(
                zz_zama::evm::ReadMethod::BlockByNumber,
                json!(["latest", false]),
            )
            .await?
            .result;
        ensure!(
            clock.timestamp <= authorization.deadline,
            "authorization expired; reconciliation required"
        );
        let hex = |bytes: &[u8]| format!("0x{}", hex::encode(bytes));
        Ok(Some(PreparedMint {
            proof_request: json!({
                "schema":"cwxmr-mint-proof-request-v1",
                "domain":{"name":"CWXMRBridge","version":"1","chainId":binding.chain_id,"verifyingContract":hex(&self.domain.bridge)},
                "registry":hex(&decode::<20>(&binding.registry)?),
                "authorization":{"vaultId":hex(&self.domain.vault.0),"depositId":hex(&id.0),"recipient":hex(&intent.recipient),
                    "amountHandle":hex(&authorization.amount_handle.0),"inputProofHash":hex(keccak256(&authorization.input_proof).as_slice()),
                    "nonce":authorization.nonce.to_string(),"deadline":authorization.deadline.to_string()},
                "keys":{"decryptKey":hex(&decode::<20>(&public.decrypt_key)?),"tlsKeyHash":hex(&decode::<32>(&public.tls_key_hash)?),
                    "authKeyHash":hex(&decode::<32>(&public.auth_key_hash)?)},
                "policyVersion":binding.policy_version.to_string(),"publicKey":hex(&decode::<64>(&public.public_key)?),
                "inputProof":hex(&authorization.input_proof),"signature":hex(&authorization.signature)
            }),
            request,
            #[cfg(feature = "unsafe-test")]
            input_proof: authorization.input_proof.into(),
            signature: authorization.signature.into(),
        }))
    }
    /// Scan one block per iteration so the supervisor can apply backpressure and stop promptly.
    /// The caller supplies the wallet birth height; persisted cursors always take precedence.
    pub async fn sync_once(&mut self, chain: &TrustedStagenet, birth_height: u64) -> Result<bool> {
        let state = self
            .store
            .load(self.domain.vault)
            .map_err(|_| anyhow::anyhow!("vault state unavailable"))?;
        let next = if let Some(cursor) = &state.monero_cursor {
            if chain
                .block_hash(cursor.height)
                .await
                .map_err(|_| ChainUnavailable)?
                != cursor.block_hash
            {
                self.store
                    .update(self.domain.vault, |state| {
                        for deposit in &mut state.deposits {
                            deposit.quarantined = true;
                        }
                        Ok(())
                    })
                    .map_err(|_| anyhow::anyhow!("quarantine persistence failed"))?;
                anyhow::bail!("scan anchor reorganized; manual reconciliation required");
            }
            cursor
                .height
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("height overflow"))?
        } else {
            birth_height
        };
        let tip = chain.tip().await.map_err(|_| ChainUnavailable)?;
        if next > tip.height {
            return Ok(false);
        }
        let mut scanner = self.scanner()?;
        let block = chain
            .scan_height(&mut scanner, next)
            .await
            .map_err(|_| ChainUnavailable)?;
        self.observe_block(block.block, block.parent, &block.outputs)?;
        Ok(true)
    }

    /// Recheck the saved scanner output against the explicitly trusted stagenet node. No secret
    /// metadata leaves the enclave. Reorgs permanently quarantine the deposit pending review.
    pub async fn eligible(
        &mut self,
        chain: &TrustedStagenet,
        id: Id,
        confirmations: u64,
    ) -> Result<Option<Deposit>> {
        let state = self
            .store
            .load(self.domain.vault)
            .map_err(|_| anyhow::anyhow!("vault state unavailable"))?;
        let deposit = state
            .deposits
            .into_iter()
            .find(|d| d.id == id)
            .ok_or_else(|| anyhow::anyhow!("unknown deposit"))?;
        ensure!(!deposit.quarantined, "deposit quarantined");
        let intent = state
            .intents
            .iter()
            .find(|i| i.id == deposit.intent_id && i.domain == self.domain)
            .ok_or_else(|| anyhow::anyhow!("deposit domain mismatch"))?;
        let mut bytes = deposit.wallet_output.as_slice();
        let output = monero_wallet::WalletOutput::read(&mut bytes)?;
        ensure!(
            bytes.is_empty()
                && zz_monero::input_id(&output) == deposit.output_key
                && output.transaction() == deposit.transaction.0
                && output.index_in_transaction() == deposit.output_index
                && zz_monero::observed_amount(&output) == deposit.amount
                && output.subaddress().is_some_and(
                    |index| index.account() == 0 && index.address() == intent.subaddress_index
                )
                && zz_monero::deposit_id(
                    &self.id_key,
                    &self.domain,
                    output.transaction(),
                    output.index_in_transaction()
                ) == id,
            "saved output mismatch"
        );
        let observed = ObservedOutput {
            output,
            block: deposit.inclusion.clone(),
            coinbase: false,
        };
        match chain
            .mint_status(&observed, confirmations)
            .await
            .map_err(|_| anyhow::anyhow!("chain status unavailable"))?
        {
            ChainStatus::Pending => Ok(None),
            ChainStatus::Mature => Ok(Some(deposit)),
            ChainStatus::Reorganized => {
                self.store
                    .update(self.domain.vault, |state| {
                        state.quarantine_deposit(id)?;
                        Ok(())
                    })
                    .map_err(|_| anyhow::anyhow!("quarantine persistence failed"))?;
                anyhow::bail!("deposit reorganized");
            }
        }
    }
    /// Existing encrypted state is mandatory. Initialization is a separate operator action.
    pub fn open(
        mut store: PostgresStore,
        identity: &Identity,
        domain: &BindingDomain,
    ) -> Result<Self> {
        ensure!(
            domain.chain_id == 11155111,
            "PoC requires Sepolia and Monero stagenet"
        );
        let domain = Domain {
            chain_id: domain.chain_id,
            bridge: decode(&domain.bridge)?,
            vault: Id(decode(&identity.public()?.vault_id)?),
        };
        ensure!(domain.bridge != [0; 20], "bridge required");
        let state = store
            .load(domain.vault)
            .map_err(|_| anyhow::anyhow!("encrypted vault state unavailable"))?;
        ensure!(
            state.intents.iter().all(|i| i.domain == domain)
                && state.evm_operations.iter().all(|op| op.domain == domain),
            "stored deployment domain mismatch"
        );
        Ok(Self {
            store,
            domain,
            pair: identity.wallet_view_pair()?,
            id_key: identity.deposit_id_key()?,
        })
    }

    /// Commit the recipient/nonce/subaddress binding before returning a public deposit address.
    pub fn issue(&mut self, recipient: [u8; 20], nonce: Id) -> Result<DepositIntent> {
        ensure!(
            recipient != [0; 20] && nonce.0 != [0; 32],
            "recipient and nonce required"
        );
        let mut hash = Keccak256::new();
        hash.update(b"cwxmr/deposit-intent/v1");
        hash.update(self.domain.chain_id.to_be_bytes());
        hash.update(self.domain.bridge);
        hash.update(self.domain.vault.0);
        hash.update(recipient);
        hash.update(nonce.0);
        let id = Id(hash.finalize().into());
        self.store
            .update(self.domain.vault, |state| {
                Ok(zz_monero::allocate_intent(
                    state,
                    &self.pair,
                    Network::Stagenet,
                    self.domain.clone(),
                    id,
                    recipient,
                    nonce,
                )?)
            })
            .map_err(|_| anyhow::anyhow!("deposit intent transaction failed"))
    }

    pub fn scanner(&mut self) -> Result<Scanner> {
        let state = self
            .store
            .load(self.domain.vault)
            .map_err(|_| anyhow::anyhow!("vault state unavailable"))?;
        let indices = state
            .intents
            .iter()
            .filter(|i| i.domain == self.domain)
            .map(|i| i.subaddress_index)
            .collect::<Vec<_>>();
        zz_monero::scanner(self.pair.clone(), &indices).map_err(anyhow::Error::msg)
    }

    /// One database transaction for the complete scanned block. Primary-address/change and
    /// coinbase outputs cannot create deposit records; previously recorded output keys are ignored.
    pub fn observe_block(
        &mut self,
        block: ChainEvidence,
        parent: Id,
        outputs: &[ObservedOutput],
    ) -> Result<Vec<Id>> {
        ensure!(
            block.block_hash.0 != [0; 32] && outputs.iter().all(|o| o.block == block),
            "block observation mismatch"
        );
        self.store
            .update(self.domain.vault, |state| {
                if let Some(cursor) = &state.monero_cursor {
                    if *cursor == block {
                        return Ok(Vec::new());
                    }
                    if cursor.height.checked_add(1) != Some(block.height)
                        || cursor.block_hash != parent
                    {
                        return Err(
                            "scan continuity failed; reconcile reorg before proceeding".into()
                        );
                    }
                }
                let mut ids = Vec::new();
                for observed in outputs {
                    if observed.coinbase {
                        continue;
                    }
                    let Some(index) = observed.output.subaddress() else {
                        continue;
                    };
                    if index.account() != 0 {
                        continue;
                    }
                    let Some(intent) = state
                        .intents
                        .iter()
                        .find(|i| i.domain == self.domain && i.subaddress_index == index.address())
                    else {
                        continue;
                    };
                    let output = &observed.output;
                    // A duplicate output key can never create additional backing. Ignore it
                    // without rolling back the block, so an attacker cannot stall wallet sync.
                    if state
                        .deposits
                        .iter()
                        .any(|d| d.output_key == zz_monero::input_id(output))
                    {
                        continue;
                    }
                    let id = zz_monero::deposit_id(
                        &self.id_key,
                        &self.domain,
                        output.transaction(),
                        output.index_in_transaction(),
                    );
                    let amount = zz_monero::observed_amount(output);
                    if amount.0 == 0 {
                        continue;
                    }
                    state.observe_deposit(Deposit {
                        id,
                        intent_id: intent.id,
                        output_key: zz_monero::input_id(output),
                        transaction: Id(output.transaction()),
                        output_index: output.index_in_transaction(),
                        amount,
                        wallet_output: output.serialize(),
                        inclusion: observed.block.clone(),
                        state: MintState::Observed,
                        quarantined: false,
                    })?;
                    ids.push(id);
                }
                state.monero_cursor = Some(block);
                Ok(ids)
            })
            .map_err(|_| anyhow::anyhow!("deposit observation transaction failed"))
    }
}

fn mint_event_handle(
    logs: &[zz_zama::evm::LogObservation],
    domain: &Domain,
    id: Id,
    recipient: [u8; 20],
) -> Result<alloy::primitives::B256> {
    let mut matched = None;
    for log in logs {
        if log.address != Address::from(domain.bridge)
            || log.topics.first() != Some(&zz_zama::Bridge::DepositMinted::SIGNATURE_HASH)
        {
            continue;
        }
        let event = zz_zama::Bridge::DepositMinted::decode_raw_log_validate(
            log.topics.iter().copied(),
            &log.data,
        )?;
        ensure!(
            !log.removed
                && event.depositId.0 == id.0
                && event.vaultId.0 == domain.vault.0
                && event.recipient == Address::from(recipient)
                && matched.is_none(),
            "mint receipt scope mismatch"
        );
        matched = Some(event.actualAmount);
    }
    matched.ok_or_else(|| anyhow::anyhow!("expected one exact mint event"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn host_kms_context_target_is_distinct_from_gateway_permit_domain() {
        use alloy::{
            primitives::{address, Address, Bytes, U256},
            sol_types::SolCall,
        };
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../zama/src/permit-v1.json")).unwrap();
        let gateway: Address = fixture["typedData"]["domain"]["verifyingContract"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            gateway,
            address!("5D8BD78e2ea6bbE41f26dFe9fdaEAa349e077478")
        );
        assert_eq!(
            zz_zama::SEPOLIA_KMS_VERIFIER,
            address!("bE0E383937d564D7FF0BC3b46c51f0bF8d5C311A")
        );
        assert_ne!(zz_zama::SEPOLIA_KMS_VERIFIER, gateway);
        let encoded: Bytes = fixture["context"].as_str().unwrap().parse().unwrap();
        let context =
            super::getCurrentKmsContextIdCall::abi_decode_returns_validate(&encoded).unwrap();
        assert_eq!(context, U256::from_be_slice(&encoded));
        assert!(context > U256::from(u64::MAX));
        // The gateway's observed empty eth_call result must not become a zero/default context.
        assert!(super::getCurrentKmsContextIdCall::abi_decode_returns_validate(&[]).is_err());
    }
    use super::*;
    use zz_core::storage::{Cipher, DataKeySource};
    #[test]
    fn receipt_requires_one_matching_bridge_vault_deposit_and_recipient() {
        let domain = Domain {
            chain_id: 11155111,
            bridge: [1; 20],
            vault: Id([2; 32]),
        };
        let id = Id([3; 32]);
        let recipient = [4; 20];
        let event = zz_zama::Bridge::DepositMinted {
            depositId: id.0.into(),
            vaultId: domain.vault.0.into(),
            recipient: recipient.into(),
            actualAmount: [5; 32].into(),
        }
        .encode_log_data();
        let log = zz_zama::evm::LogObservation {
            address: domain.bridge.into(),
            topics: event.topics().to_vec(),
            data: event.data,
            block_hash: [6; 32].into(),
            block_number: 7,
            transaction_hash: [8; 32].into(),
            transaction_index: 0,
            log_index: 0,
            removed: false,
        };
        assert_eq!(
            mint_event_handle(&[log.clone()], &domain, id, recipient).unwrap(),
            alloy::primitives::B256::from([5; 32])
        );
        assert!(mint_event_handle(&[], &domain, id, recipient).is_err());
        assert!(mint_event_handle(&[log.clone(), log.clone()], &domain, id, recipient).is_err());
        assert!(mint_event_handle(&[log.clone()], &domain, id, [9; 20]).is_err());
        assert!(mint_event_handle(&[log.clone()], &domain, Id([9; 32]), recipient).is_err());
        let mut wrong = domain.clone();
        wrong.vault = Id([9; 32]);
        assert!(mint_event_handle(&[log.clone()], &wrong, id, recipient).is_err());
        wrong = domain;
        wrong.bridge = [9; 20];
        assert!(mint_event_handle(&[log], &wrong, id, recipient).is_err());
    }
    struct Key;
    impl DataKeySource for Key {
        fn data_key(
            &self,
        ) -> std::result::Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
            Ok([91; 32])
        }
    }
    fn store(url: &str) -> PostgresStore {
        PostgresStore::new(
            postgres::Client::connect(url, postgres::NoTls).unwrap(),
            Cipher::new(&Key).unwrap(),
        )
    }
    #[test]
    fn postgres_intent_survives_restart_and_does_not_rebind_recipient() {
        let Ok(url) = std::env::var("CWXMR_TEST_DATABASE_URL") else {
            return;
        };
        let identity = Identity::generate().unwrap();
        let domain = BindingDomain {
            chain_id: 11155111,
            registry: "11".repeat(20),
            bridge: "22".repeat(20),
            policy_version: 1,
        };
        let vault = Id(decode(&identity.public().unwrap().vault_id).unwrap());
        let mut db = store(&url);
        db.migrate().unwrap();
        db.initialize(vault).unwrap();
        let mut deposits = Deposits::open(db, &identity, &domain).unwrap();
        let first = deposits.issue([1; 20], Id([2; 32])).unwrap();
        assert!(first.subaddress.starts_with('7'));
        assert!(deposits.issue([0; 20], Id([3; 32])).is_err());
        drop(deposits);
        let mut restarted = Deposits::open(store(&url), &identity, &domain).unwrap();
        assert!(restarted.issue([1; 20], Id([2; 32])).unwrap() == first);
        assert!(restarted.issue([3; 20], Id([2; 32])).is_err());
        let next = restarted.issue([1; 20], Id([4; 32])).unwrap();
        assert_ne!(first.subaddress, next.subaddress);
        assert_eq!(next.subaddress_index, first.subaddress_index + 1);
        assert!(Deposits::open(store(&url), &Identity::generate().unwrap(), &domain).is_err());
        let mut other_domain = domain;
        other_domain.bridge = "33".repeat(20);
        assert!(Deposits::open(store(&url), &identity, &other_domain).is_err());
    }
}
