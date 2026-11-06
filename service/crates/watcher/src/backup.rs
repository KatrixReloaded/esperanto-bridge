//! Host-visible envelopes contain only authenticated ciphertext and a KMS-wrapped data key.
//! This does not provide rollback protection or exclusive recovery.
use crate::attestation::Identity;
use anyhow::{ensure, Result};
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher as Aes};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: u8,
    pub wrapped_key: String,
    nonce: String,
    tag: String,
    ciphertext: String,
}
/// The key never leaves the enclave in plaintext; API errors deliberately exclude key bytes.
pub struct DataKey(pub Zeroizing<[u8; 32]>);
impl zz_core::storage::DataKeySource for DataKey {
    fn data_key(&self) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        Ok(*self.0)
    }
}
impl Envelope {
    pub fn seal(
        identity: &Identity,
        key: &DataKey,
        wrapped_key: String,
        domain: &[u8],
    ) -> Result<Self> {
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut tag = [0u8; 16];
        let plain = Zeroizing::new(serde_json::to_vec(identity)?);
        let ciphertext = encrypt_aead(
            Aes::aes_256_gcm(),
            &key.0[..],
            Some(&nonce),
            domain,
            &plain,
            &mut tag,
        )?;
        Ok(Self {
            version: 1,
            wrapped_key,
            nonce: hex::encode(nonce),
            tag: hex::encode(tag),
            ciphertext: hex::encode(ciphertext),
        })
    }
    pub fn open(&self, key: &DataKey, domain: &[u8]) -> Result<Identity> {
        ensure!(
            self.version == 1 && self.ciphertext.len() < 128 * 1024,
            "invalid backup envelope"
        );
        let nonce = hex::decode(&self.nonce)?;
        let tag = hex::decode(&self.tag)?;
        ensure!(
            nonce.len() == 12 && tag.len() == 16,
            "invalid backup nonce/tag"
        );
        let plain = Zeroizing::new(decrypt_aead(
            Aes::aes_256_gcm(),
            &key.0[..],
            Some(&nonce),
            domain,
            &hex::decode(&self.ciphertext)?,
            &tag,
        )?);
        Ok(serde_json::from_slice(&plain)?)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backup_authentication_and_core_integration() {
        let id = Identity::generate().unwrap();
        let key = DataKey(Zeroizing::new([7; 32]));
        let mut blob = Envelope::seal(&id, &key, "wrapped".into(), b"deployment A").unwrap();
        assert_eq!(
            id.public().unwrap().vault_id,
            blob.open(&key, b"deployment A")
                .unwrap()
                .public()
                .unwrap()
                .vault_id
        );
        assert!(blob.open(&key, b"deployment B").is_err());
        assert!(blob
            .open(&DataKey(Zeroizing::new([8; 32])), b"deployment A")
            .is_err());
        blob.ciphertext.replace_range(..2, "00");
        assert!(blob.open(&key, b"deployment A").is_err());
        let core = zz_core::storage::Cipher::new(&key).unwrap();
        let state = zz_core::VaultState::default();
        let vault = zz_core::Id([1; 32]);
        assert!(core.open(vault, &core.seal(vault, &state).unwrap()).is_ok());
    }
}
