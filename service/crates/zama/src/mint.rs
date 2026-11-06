use alloy::{
    primitives::{keccak256, Address, B256, U256},
    signers::{local::PrivateKeySigner, SignerSync},
    sol,
    sol_types::{Eip712Domain, SolStruct},
};
use zz_core::{Domain, Id};
sol! {
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
    let eip_domain = Eip712Domain {
        name: Some("CWXMRBridge".into()),
        version: Some("1".into()),
        chain_id: Some(U256::from(domain.chain_id)),
        verifying_contract: Some(Address::from(domain.bridge)),
        salt: None,
    };
    signer
        .sign_hash_sync(&data.eip712_signing_hash(&eip_domain))
        .map(|s| s.as_bytes().to_vec())
        .map_err(|_| "signing failed")
}
