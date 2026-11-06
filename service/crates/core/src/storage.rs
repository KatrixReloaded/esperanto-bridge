use crate::{Id, VaultState};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use postgres::Client;
use rand::{rngs::OsRng, RngCore};
use std::error::Error;
use zeroize::Zeroizing;

const AAD: &[u8] = b"cwxmr/vault-state/v1";

/// Key recovery must happen inside the enclave through an attested KMS recipient.
pub trait DataKeySource {
    fn data_key(&self) -> Result<[u8; 32], Box<dyn Error + Send + Sync>>;
}

pub struct Cipher {
    cipher: XChaCha20Poly1305,
}
impl Cipher {
    pub fn new(source: &impl DataKeySource) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let key = Zeroizing::new(source.data_key()?);
        let cipher = XChaCha20Poly1305::new((&*key).into());
        Ok(Self { cipher })
    }
    fn aad(vault: Id) -> Vec<u8> {
        [AAD, vault.0.as_slice()].concat()
    }
    pub fn seal(
        &self,
        vault: Id,
        state: &VaultState,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let plaintext = Zeroizing::new(serde_json::to_vec(state)?);
        let encrypted = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &Self::aad(vault),
                },
            )
            .map_err(|_| "encryption failed")?;
        Ok([nonce.as_slice(), encrypted.as_slice()].concat())
    }
    pub fn open(&self, vault: Id, blob: &[u8]) -> Result<VaultState, Box<dyn Error + Send + Sync>> {
        if blob.len() < 24 || blob.len() > 16 * 1024 * 1024 {
            return Err("invalid ciphertext".into());
        }
        let plain = Zeroizing::new(
            self.cipher
                .decrypt(
                    XNonce::from_slice(&blob[..24]),
                    Payload {
                        msg: &blob[24..],
                        aad: &Self::aad(vault),
                    },
                )
                .map_err(|_| "authentication failed")?,
        );
        Ok(serde_json::from_slice(&plain)?)
    }
}

/// PostgreSQL coordinates cooperative writers only; it does not establish freshness.
pub struct PostgresStore {
    client: Client,
    cipher: Cipher,
}
impl PostgresStore {
    /// TLS must terminate inside the enclave; this constructor only accepts an already configured client.
    pub fn new(client: Client, cipher: Cipher) -> Self {
        Self { client, cipher }
    }
    pub fn migrate(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.client
            .batch_execute(include_str!("../../../migrations/001_encrypted_vault.sql"))?;
        Ok(())
    }
    pub fn load(&mut self, vault: Id) -> Result<VaultState, Box<dyn Error + Send + Sync>> {
        let row = self
            .client
            .query_opt(
                "SELECT ciphertext FROM encrypted_vault_state WHERE vault_id=$1",
                &[&&vault.0[..]],
            )?
            .ok_or("vault state missing; explicit recovery required")?;
        let state = self.cipher.open(vault, &row.get::<_, Vec<u8>>(0))?;
        validate_domain(vault, &state)?;
        Ok(state)
    }
    pub fn initialize(&mut self, vault: Id) -> Result<(), Box<dyn Error + Send + Sync>> {
        let blob = self.cipher.seal(vault, &VaultState::default())?;
        let count = self.client.execute("INSERT INTO encrypted_vault_state(vault_id,ciphertext) VALUES($1,$2) ON CONFLICT DO NOTHING", &[&&vault.0[..], &blob])?;
        if count != 1 {
            return Err("vault already initialized".into());
        }
        Ok(())
    }
    pub fn update<T>(
        &mut self,
        vault: Id,
        f: impl FnOnce(&mut VaultState) -> Result<T, Box<dyn Error + Send + Sync>>,
    ) -> Result<T, Box<dyn Error + Send + Sync>> {
        let mut tx = self.client.transaction()?;
        // Serialize first creation too; row locks alone cannot lock a missing row.
        let lock = i64::from_be_bytes(vault.0[..8].try_into()?);
        tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&lock])?;
        let row = tx.query_opt(
            "SELECT ciphertext FROM encrypted_vault_state WHERE vault_id=$1 FOR UPDATE",
            &[&&vault.0[..]],
        )?;
        let mut state = match row {
            Some(row) => self.cipher.open(vault, &row.get::<_, Vec<u8>>(0))?,
            None => return Err("vault state missing; explicit recovery required".into()),
        };
        validate_domain(vault, &state)?;
        let result = f(&mut state)?;
        validate_domain(vault, &state)?;
        let blob = self.cipher.seal(vault, &state)?;
        tx.execute("INSERT INTO encrypted_vault_state(vault_id,ciphertext) VALUES($1,$2) ON CONFLICT(vault_id) DO UPDATE SET ciphertext=EXCLUDED.ciphertext", &[&&vault.0[..], &blob])?;
        tx.commit()?;
        Ok(result)
    }
}

fn validate_domain(vault: Id, state: &VaultState) -> Result<(), Box<dyn Error + Send + Sync>> {
    if state.intents.iter().any(|i| i.domain.vault != vault)
        || state
            .payouts
            .iter()
            .any(|p| p.reservation().domain.vault != vault)
        || state
            .evm_operations
            .iter()
            .any(|op| op.domain.vault != vault)
        || state
            .deposits
            .iter()
            .any(|d| !state.intents.iter().any(|i| i.id == d.intent_id))
    {
        return Err("vault domain mismatch".into());
    }
    Ok(())
}
