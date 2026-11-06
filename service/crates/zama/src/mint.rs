use alloy::{
    primitives::{keccak256, Address, B256, U256},
    signers::{local::PrivateKeySigner, SignerSync},
    sol,
    sol_types::{Eip712Domain, SolStruct},
};
use zz_core::{Domain, Id};
sol! {
    struct Claim { uint256 requestId; bytes32 vaultId; uint64 deadline; }
    struct Settle { uint256 requestId; bytes32 vaultId; bytes32 paymentCommitment; uint64 deadline; }
    struct Mint {
        bytes32 vaultId;
        bytes32 depositId;
        address recipient;
        bytes32 amountHandle;
        bytes32 inputProofHash;
        uint256 nonce;
        uint64 deadline;
    }
}
pub fn sign_mint(
    signer: &PrivateKeySigner,
    domain: &Domain,
    deposit: Id,
    recipient: [u8; 20],
    handle: [u8; 32],
    proof: &[u8],
    nonce: u64,
    deadline: u64,
) -> Result<Vec<u8>, &'static str> {
    if recipient == [0; 20] || handle == [0; 32] || proof.is_empty() || deadline == 0 {
        return Err("invalid mint");
    }
    let data = Mint {
        vaultId: B256::from(domain.vault.0),
        depositId: B256::from(deposit.0),
        recipient: Address::from(recipient),
        amountHandle: B256::from(handle),
        inputProofHash: keccak256(proof),
        nonce: U256::from(nonce),
        deadline,
    };
    let eip_domain = signing_domain(domain);
    signer
        .sign_hash_sync(&data.eip712_signing_hash(&eip_domain))
        .map(|s| s.as_bytes().to_vec())
        .map_err(|_| "signing failed")
}

fn signing_domain(domain: &Domain) -> Eip712Domain {
    Eip712Domain {
        name: Some("CWXMRBridge".into()),
        version: Some("1".into()),
        chain_id: Some(U256::from(domain.chain_id)),
        verifying_contract: Some(Address::from(domain.bridge)),
        salt: None,
    }
}
pub fn sign_claim(
    signer: &PrivateKeySigner,
    domain: &Domain,
    request: U256,
    deadline: u64,
) -> Result<Vec<u8>, &'static str> {
    if deadline == 0 {
        return Err("invalid deadline");
    }
    let claim = Claim {
        requestId: request,
        vaultId: B256::from(domain.vault.0),
        deadline,
    };
    signer
        .sign_hash_sync(&claim.eip712_signing_hash(&signing_domain(domain)))
        .map(|s| s.as_bytes().to_vec())
        .map_err(|_| "signing failed")
}
pub fn sign_settle(
    signer: &PrivateKeySigner,
    domain: &Domain,
    request: U256,
    commitment: Id,
    deadline: u64,
) -> Result<Vec<u8>, &'static str> {
    if deadline == 0 || commitment.0 == [0; 32] {
        return Err("invalid settlement");
    }
    let settle = Settle {
        requestId: request,
        vaultId: B256::from(domain.vault.0),
        paymentCommitment: B256::from(commitment.0),
        deadline,
    };
    signer
        .sign_hash_sync(&settle.eip712_signing_hash(&signing_domain(domain)))
        .map(|s| s.as_bytes().to_vec())
        .map_err(|_| "signing failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn claim_and_settle_match_ethers_typed_data_vectors() {
        let domain = Domain {
            chain_id: 11155111,
            bridge: [0x22; 20],
            vault: Id([0x33; 32]),
        };
        let signer = PrivateKeySigner::random();
        let claim: B256 = "0x2f45a5099b9eb7149ec77dcbb96d9729bd2c4e0c2022212b009d45f08982631a"
            .parse()
            .unwrap();
        let settle: B256 = "0xf3d5e54ffa8c0d46c54384dbede3af09a21c8be7c1bb58f67cf010cc7e4c71e5"
            .parse()
            .unwrap();
        for (sig, digest) in [
            (
                sign_claim(&signer, &domain, U256::from(7), 123).unwrap(),
                claim,
            ),
            (
                sign_settle(&signer, &domain, U256::from(7), Id([0x44; 32]), 123).unwrap(),
                settle,
            ),
        ] {
            let signature = alloy::primitives::Signature::try_from(sig.as_slice()).unwrap();
            assert_eq!(
                signature.recover_address_from_prehash(&digest).unwrap(),
                signer.address()
            );
        }
    }
}
