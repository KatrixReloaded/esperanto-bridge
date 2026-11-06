//! FORGED attestation journal for the explicitly marked unsafe verifier. Never an NSM document.
use crate::{
    attestation::{decode, BindingDomain, Identity},
    deposits::PreparedMint,
};
use alloy::{
    primitives::{keccak256, Address, Bytes, B256},
    sol_types::{SolCall, SolValue},
};
use anyhow::{ensure, Result};
use zz_zama::Bridge;
alloy::sol! {
    struct TestBytes48 { bytes32 first; bytes16 second; }
    struct TestPcr { uint64 index; TestBytes48 value; }
    struct TestJournal { uint8 result; uint8 trustedCertsPrefixLen; uint64 timestamp; bytes32[] certs; bytes userData; bytes nonce; bytes publicKey; TestPcr[] pcrs; string moduleId; }
}
pub(super) fn root() -> B256 {
    keccak256(b"CWXMR_UNSAFE_TEST_ROOT")
}
pub(super) fn program() -> B256 {
    keccak256(b"CWXMR_UNSAFE_TEST_PROGRAM")
}
pub(super) fn pcr_tuple() -> B256 {
    keccak256([[0x11u8; 48], [0x22; 48], [0x33; 48]].concat())
}
pub(super) fn calldata(
    identity: &Identity,
    binding: &BindingDomain,
    prepared: &PreparedMint,
    timestamp: u64,
) -> Result<Bytes> {
    ensure!(
        binding.chain_id == 11155111 && binding.policy_version == 1 && timestamp > 0,
        "unsafe test domain mismatch"
    );
    let public = identity.public()?;
    zz_zama::mint::verify_mint_signature(
        &zz_core::Domain {
            chain_id: 11155111,
            bridge: decode(&binding.bridge)?,
            vault: zz_core::Id(decode(&public.vault_id)?),
        },
        &prepared.request,
        &prepared.signature,
    )
    .map_err(anyhow::Error::msg)?;
    let output = TestJournal {
        result: 0,
        trustedCertsPrefixLen: 1,
        timestamp: timestamp
            .checked_mul(1000)
            .ok_or_else(|| anyhow::anyhow!("timestamp overflow"))?,
        certs: vec![root()],
        userData: identity
            .mint_binding(binding, &prepared.request)?
            .to_vec()
            .into(),
        nonce: prepared.request.nonce.to_be_bytes::<32>().to_vec().into(),
        publicKey: decode::<64>(&public.public_key)?.to_vec().into(),
        pcrs: [0x11u8, 0x22, 0x33]
            .into_iter()
            .enumerate()
            .map(|(i, b)| TestPcr {
                index: i as u64,
                value: TestBytes48 {
                    first: [b; 32].into(),
                    second: [b; 16].into(),
                },
            })
            .collect(),
        moduleId: "UNSAFE_TEST_NO_NITRO".into(),
    }
    .abi_encode();
    let a = &prepared.request;
    Ok(Bridge::confidentialMintCall {
        a: (
            a.vaultId,
            a.depositId,
            a.recipient,
            a.amountHandle,
            a.inputProofHash,
            a.nonce,
            a.deadline,
        )
            .into(),
        inputProof: prepared.input_proof.clone(),
        signature: prepared.signature.clone(),
        evidence: (
            (
                Address::from(decode::<20>(&public.decrypt_key)?),
                B256::from(decode::<32>(&public.tls_key_hash)?),
                B256::from(decode::<32>(&public.auth_key_hash)?),
            )
                .into(),
            1u64,
            Bytes::from(output),
            Bytes::from_static(&[0x54, 0x53, 0x54, 0x31]),
        )
            .into(),
    }
    .abi_encode()
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;
    #[test]
    fn forged_journal_is_exactly_bound_and_normal_nsm_still_fails() {
        let identity = Identity::generate().unwrap();
        let public = identity.public().unwrap();
        let binding = BindingDomain {
            chain_id: 11155111,
            registry: format!("0x{}", "22".repeat(20)),
            bridge: format!("0x{}", "33".repeat(20)),
            policy_version: 1,
        };
        let domain = zz_core::Domain {
            chain_id: 11155111,
            bridge: decode(&binding.bridge).unwrap(),
            vault: zz_core::Id(decode(&public.vault_id).unwrap()),
        };
        let request = zz_zama::mint::Mint {
            vaultId: domain.vault.0.into(),
            depositId: [4; 32].into(),
            recipient: [5; 20].into(),
            amountHandle: [6; 32].into(),
            inputProofHash: keccak256([7]),
            nonce: U256::from(8),
            deadline: 1700000600,
        };
        let signature = zz_zama::mint::sign_mint(
            &identity.mint_signer().unwrap(),
            &domain,
            zz_core::Id([4; 32]),
            [5; 20],
            [6; 32],
            &[7],
            8,
            1700000600,
        )
        .unwrap();
        assert!(
            identity
                .attest_mint(&binding, &request, &signature)
                .is_err(),
            "unsafe-test must never make normal NSM succeed"
        );
        let prepared = PreparedMint {
            request,
            input_proof: vec![7].into(),
            signature: signature.into(),
            proof_request: serde_json::Value::Null,
        };
        let bytes = calldata(&identity, &binding, &prepared, 1700000000).unwrap();
        let call = Bridge::confidentialMintCall::abi_decode_validate(&bytes).unwrap();
        let journal = TestJournal::abi_decode_validate(&call.evidence.output).unwrap();
        assert_eq!(journal.timestamp, 1700000000000);
        assert_eq!(journal.result, 0);
        assert_eq!(journal.trustedCertsPrefixLen, 1);
        assert_eq!(
            journal.userData.as_ref(),
            identity.mint_binding(&binding, &prepared.request).unwrap()
        );
        assert_eq!(journal.nonce.as_ref(), U256::from(8).to_be_bytes::<32>());
        assert_eq!(journal.publicKey.len(), 64);
        assert_eq!(journal.moduleId, "UNSAFE_TEST_NO_NITRO");
        assert_eq!(call.evidence.proof.as_ref(), [0x54, 0x53, 0x54, 0x31]);
        assert_eq!(
            pcr_tuple().to_string(),
            "0x8763f7b4ff8be9260da66b94bf5e8fab677768a66074d4f2bf62e85ba173cef4"
        );
        let mut wrong = binding.clone();
        wrong.chain_id = 1;
        assert!(calldata(&identity, &wrong, &prepared, 1700000000).is_err());
        assert!(calldata(&identity, &binding, &prepared, 0).is_err());
        if let Ok(path) = std::env::var("CWXMR_UNSAFE_TEST_VECTOR") {
            std::fs::write(path,serde_json::to_vec(&serde_json::json!({"calldata":bytes,"expected":{"userData":journal.userData,"nonce":journal.nonce,"publicKey":journal.publicKey,"rootCert":root(),"timestamp":"1700000000000"}})).unwrap()).unwrap();
        }
    }
}
