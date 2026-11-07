//! Bounded signing of the already authorized mint call. Keys remain in the enclave caller.
use crate::{
    evm::SignedTransaction,
    mint::{verify_mint_signature, Mint},
    Bridge,
};
use alloy::{
    consensus::{SignableTransaction, TxEip1559, TxEnvelope},
    eips::eip2718::Encodable2718,
    primitives::{keccak256, Address, Bytes, TxKind, U256},
    signers::{local::PrivateKeySigner, SignerSync},
    sol_types::SolCall,
};
use anyhow::{ensure, Result};
use zz_core::Domain;

/// Operator-chosen limits, not unbounded fees accepted from the RPC provider.
#[derive(Clone, Copy)]
pub struct Fees {
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

pub fn sign_mint_transaction(
    signer: &PrivateKeySigner,
    domain: &Domain,
    expected: &Mint,
    input_proof: &[u8],
    signature: &[u8],
    calldata: Bytes,
    nonce: u64,
    fees: Fees,
) -> Result<SignedTransaction> {
    ensure!(
        domain.chain_id == crate::evm::CHAIN_ID
            && fees.gas_limit > 0
            && fees.gas_limit <= 10_000_000
            && fees.max_fee_per_gas > 0
            && fees.max_priority_fee_per_gas <= fees.max_fee_per_gas,
        "invalid transaction policy"
    );
    verify_mint_signature(domain, expected, signature).map_err(anyhow::Error::msg)?;
    ensure!(
        keccak256(input_proof) == expected.inputProofHash,
        "input proof mismatch"
    );
    let call = Bridge::confidentialMintCall::abi_decode_validate(&calldata)?;
    ensure!(
        call.abi_encode() == calldata.as_ref(),
        "noncanonical calldata"
    );
    let a = &call.a;
    ensure!(
        a.vaultId == expected.vaultId
            && a.depositId == expected.depositId
            && a.recipient == expected.recipient
            && a.amountHandle == expected.amountHandle
            && a.inputProofHash == expected.inputProofHash
            && a.nonce == expected.nonce
            && a.deadline == expected.deadline
            && call.inputProof.as_ref() == input_proof
            && call.signature.as_ref() == signature,
        "mint calldata differs from durable authorization"
    );
    ensure!(
        signer.address().as_slice() == &domain.vault.0[12..],
        "transaction sender differs from FHE input user"
    );
    let transaction = TxEip1559 {
        chain_id: domain.chain_id,
        nonce,
        gas_limit: fees.gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        to: TxKind::Call(Address::from(domain.bridge)),
        value: U256::ZERO,
        access_list: Default::default(),
        input: calldata,
    };
    let sig = signer.sign_hash_sync(&transaction.signature_hash())?;
    let signed = TxEnvelope::Eip1559(transaction.into_signed(sig));
    SignedTransaction::from_signed_bytes(signed.encoded_2718().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::sign_mint;
    use zz_core::Id;

    #[test]
    fn signs_only_exact_authorized_call_and_persists_replayable_envelope() {
        let signer = PrivateKeySigner::random();
        let key = signer.credential().verifying_key().to_encoded_point(false);
        let domain = Domain {
            chain_id: 11155111,
            bridge: [2; 20],
            vault: Id(keccak256(&key.as_bytes()[1..]).0),
        };
        let request = Mint {
            vaultId: domain.vault.0.into(),
            depositId: [3; 32].into(),
            recipient: [4; 20].into(),
            amountHandle: [5; 32].into(),
            inputProofHash: keccak256([6]),
            nonce: U256::from(7),
            deadline: 100,
        };
        let signature = sign_mint(
            &signer,
            &domain,
            Id([3; 32]),
            [4; 20],
            [5; 32],
            &[6],
            7,
            100,
        )
        .unwrap();
        // Empty evidence is intentional: this tests signing, never on-chain proof validity.
        let mut call = Bridge::confidentialMintCall {
            a: (
                request.vaultId,
                request.depositId,
                request.recipient,
                request.amountHandle,
                request.inputProofHash,
                request.nonce,
                request.deadline,
            )
                .into(),
            inputProof: vec![6].into(),
            signature: signature.clone().into(),
            evidence: (
                (
                    Address::ZERO,
                    alloy::primitives::B256::ZERO,
                    alloy::primitives::B256::ZERO,
                )
                    .into(),
                1u64,
                Bytes::new(),
                Bytes::new(),
            )
                .into(),
        };
        call.a.vaultId = request.vaultId;
        call.a.depositId = request.depositId;
        call.a.recipient = request.recipient;
        call.a.amountHandle = request.amountHandle;
        call.a.inputProofHash = request.inputProofHash;
        call.a.nonce = request.nonce;
        call.a.deadline = request.deadline;
        call.inputProof = vec![6].into();
        call.signature = signature.clone().into();
        let fees = || Fees {
            gas_limit: 1_000_000,
            max_fee_per_gas: 10_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
        };
        let tx = sign_mint_transaction(
            &signer,
            &domain,
            &request,
            &[6],
            &signature,
            call.abi_encode().into(),
            8,
            fees(),
        )
        .unwrap();
        assert_eq!(
            tx.simulation_call().unwrap(),
            serde_json::json!({
                "from": signer.address(), "to": Address::from(domain.bridge),
                "data": Bytes::from(call.abi_encode()), "value": "0x0",
                "gas": "0xf4240", "maxFeePerGas": "0x2540be400",
                "maxPriorityFeePerGas": "0x3b9aca00",
            })
        );
        assert_eq!(
            SignedTransaction::restore(tx.raw().clone(), tx.hash())
                .unwrap()
                .hash(),
            tx.hash()
        );
        call.a.recipient = Address::from([9; 20]);
        assert!(sign_mint_transaction(
            &signer,
            &domain,
            &request,
            &[6],
            &signature,
            call.abi_encode().into(),
            8,
            fees()
        )
        .is_err());
        call.a.recipient = request.recipient;
        let mut noncanonical = call.abi_encode();
        noncanonical.push(0);
        assert!(sign_mint_transaction(
            &signer,
            &domain,
            &request,
            &[6],
            &signature,
            noncanonical.into(),
            8,
            fees()
        )
        .is_err());
        assert!(sign_mint_transaction(
            &PrivateKeySigner::random(),
            &domain,
            &request,
            &[6],
            &signature,
            call.abi_encode().into(),
            8,
            fees()
        )
        .is_err());
    }
}

/// Only the two payout calls; no arbitrary target/calldata signer is exposed.
pub enum PayoutCall {
    Claim {
        request: U256,
        deadline: u64,
        nonzero_proof: Bytes,
    },
    Settle {
        request: U256,
        deadline: u64,
        payment_commitment: zz_core::Id,
    },
}
pub fn sign_payout_transaction(
    signer: &PrivateKeySigner,
    domain: &Domain,
    call: PayoutCall,
    nonce: u64,
    fees: Fees,
) -> Result<SignedTransaction> {
    let public_key = signer.credential().verifying_key().to_encoded_point(false);
    ensure!(
        domain.chain_id == crate::evm::CHAIN_ID
            && domain.bridge != [0; 20]
            && keccak256(&public_key.as_bytes()[1..]).0 == domain.vault.0
            && fees.gas_limit > 0
            && fees.gas_limit <= 10_000_000
            && fees.max_fee_per_gas > 0
            && fees.max_priority_fee_per_gas <= fees.max_fee_per_gas,
        "invalid payout signing policy"
    );
    let calldata = match call {
        PayoutCall::Claim {
            request,
            deadline,
            nonzero_proof,
        } => {
            ensure!(
                !request.is_zero()
                    && !nonzero_proof.is_empty()
                    && nonzero_proof.len() <= 128 * 1024,
                "invalid claim"
            );
            let signature = crate::mint::sign_claim(signer, domain, request, deadline)
                .map_err(anyhow::Error::msg)?;
            Bridge::claimCall {
                id: request,
                vaultId: domain.vault.0.into(),
                deadline,
                signature: signature.into(),
                nonzeroProof: nonzero_proof,
            }
            .abi_encode()
        }
        PayoutCall::Settle {
            request,
            deadline,
            payment_commitment,
        } => {
            ensure!(!request.is_zero(), "invalid settlement");
            let signature =
                crate::mint::sign_settle(signer, domain, request, payment_commitment, deadline)
                    .map_err(anyhow::Error::msg)?;
            Bridge::settleCall {
                id: request,
                vaultId: domain.vault.0.into(),
                paymentCommitment: payment_commitment.0.into(),
                deadline,
                signature: signature.into(),
            }
            .abi_encode()
        }
    };
    let transaction = TxEip1559 {
        chain_id: domain.chain_id,
        nonce,
        gas_limit: fees.gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        to: TxKind::Call(Address::from(domain.bridge)),
        value: U256::ZERO,
        access_list: Default::default(),
        input: calldata.into(),
    };
    let signature = signer.sign_hash_sync(&transaction.signature_hash())?;
    SignedTransaction::from_signed_bytes(
        TxEnvelope::Eip1559(transaction.into_signed(signature))
            .encoded_2718()
            .into(),
    )
}

#[cfg(test)]
mod payout_tests {
    use super::*;
    use alloy::{consensus::Transaction, eips::eip2718::Decodable2718};
    #[test]
    fn exact_claim_settle_scope_and_signer_domain() {
        let signer = PrivateKeySigner::random();
        let public = signer.credential().verifying_key().to_encoded_point(false);
        let mut domain = Domain {
            chain_id: 11155111,
            bridge: [2; 20],
            vault: zz_core::Id(keccak256(&public.as_bytes()[1..]).0),
        };
        let fees = || Fees {
            gas_limit: 1_000_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1,
        };
        let claim = || PayoutCall::Claim {
            request: U256::from(4),
            deadline: 100,
            nonzero_proof: vec![1, 2].into(),
        };
        let signed = sign_payout_transaction(&signer, &domain, claim(), 7, fees()).unwrap();
        let tx = TxEnvelope::decode_2718_exact(signed.raw()).unwrap();
        assert_eq!(tx.nonce(), 7);
        assert_eq!(tx.chain_id(), Some(11155111));
        assert_eq!(tx.value(), U256::ZERO);
        let call = Bridge::claimCall::abi_decode_validate(tx.input()).unwrap();
        assert_eq!(call.id, U256::from(4));
        assert_eq!(call.vaultId.0, domain.vault.0);
        assert_eq!(call.nonzeroProof.as_ref(), [1, 2]);
        assert_eq!(
            call.signature.to_vec(),
            crate::mint::sign_claim(&signer, &domain, U256::from(4), 100).unwrap()
        );
        let commitment = zz_core::Id([8; 32]);
        let signed = sign_payout_transaction(
            &signer,
            &domain,
            PayoutCall::Settle {
                request: U256::from(4),
                deadline: 200,
                payment_commitment: commitment,
            },
            8,
            fees(),
        )
        .unwrap();
        let tx = TxEnvelope::decode_2718_exact(signed.raw()).unwrap();
        let call = Bridge::settleCall::abi_decode_validate(tx.input()).unwrap();
        assert_eq!(call.paymentCommitment.0, commitment.0);
        assert_eq!(call.deadline, 200);
        assert!(
            sign_payout_transaction(&PrivateKeySigner::random(), &domain, claim(), 9, fees())
                .is_err()
        );
        domain.chain_id = 1;
        assert!(sign_payout_transaction(&signer, &domain, claim(), 9, fees()).is_err());
    }
}
