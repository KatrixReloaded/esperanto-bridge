use crate::{Id, VaultState};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use postgres::Client;
use rand::{rngs::OsRng, RngCore};
use std::{
    error::Error,
    sync::{Arc, Mutex},
};
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
///
/// The synchronous postgres client drives its own Tokio runtime. Every complete operation
/// runs outside the caller's runtime, including current-thread runtimes. The caller remains
/// blocked; clones share a mutex and the same client, so complete operations cannot overlap.
/// Mint and payout controllers therefore retain one session lease and encrypted state.
#[derive(Clone)]
pub struct PostgresStore {
    session: Arc<SharedSession>,
}
struct SharedSession(Mutex<Option<Session>>);
impl PostgresStore {
    /// Connect before entering async execution. TLS must terminate inside the enclave.
    pub fn new(client: Client, cipher: Cipher) -> Self {
        Self {
            session: Arc::new(SharedSession(Mutex::new(Some(Session::new(
                client, cipher,
            ))))),
        }
    }
    fn run<T: Send>(
        &mut self,
        f: impl FnOnce(&mut Session) -> Result<T, Box<dyn Error + Send + Sync>> + Send,
    ) -> Result<T, Box<dyn Error + Send + Sync>> {
        let mut shared = self
            .session
            .0
            .lock()
            .map_err(|_| "storage session poisoned")?;
        let session = shared.as_mut().expect("storage session present until drop");
        std::thread::scope(|scope| match scope.spawn(move || f(session)).join() {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        })
    }
    pub fn acquire_stagenet_poc_lease(
        &mut self,
        vault: Id,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.run(move |s| s.acquire_stagenet_poc_lease(vault))
    }
    pub fn check_stagenet_poc_lease(
        &mut self,
        vault: Id,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.run(move |s| s.check_stagenet_poc_lease(vault))
    }
    pub fn migrate(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.run(Session::migrate)
    }
    pub fn load(&mut self, vault: Id) -> Result<VaultState, Box<dyn Error + Send + Sync>> {
        self.run(move |s| s.load(vault))
    }
    pub fn initialize(&mut self, vault: Id) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.run(move |s| s.initialize(vault))
    }
    pub fn update<T: Send>(
        &mut self,
        vault: Id,
        f: impl FnOnce(&mut VaultState) -> Result<T, Box<dyn Error + Send + Sync>> + Send,
    ) -> Result<T, Box<dyn Error + Send + Sync>> {
        // The entire transaction and closure stay on one thread; no lock is released between
        // decrypting, applying the transition, encrypting and committing the state.
        self.run(move |s| s.update(vault, f))
    }
}
impl Drop for SharedSession {
    fn drop(&mut self) {
        if let Some(session) = self
            .0
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            // Client::drop also drives its runtime. Join before returning so session locks
            // are released before another cooperative process attempts to acquire them.
            let _ = std::thread::spawn(move || drop(session)).join();
        }
    }
}

/// PostgreSQL coordinates cooperative writers only; it does not establish freshness.
struct Session {
    client: Client,
    cipher: Cipher,
    poc_lease: Option<Id>,
}
impl Session {
    /// TLS must terminate inside the enclave; this constructor only accepts an already configured client.
    pub fn new(client: Client, cipher: Cipher) -> Self {
        Self {
            client,
            cipher,
            poc_lease: None,
        }
    }
    /// Cooperative session lock only, explicitly NOT malicious-clone fencing. A distinct
    /// two-int key space avoids colliding with ordinary one-int transaction locks.
    pub fn acquire_stagenet_poc_lease(
        &mut self,
        vault: Id,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if self.poc_lease.is_some() {
            return Err("PoC lease already configured".into());
        }
        let namespace = 0x4357584di32;
        let key = i32::from_be_bytes(vault.0[..4].try_into()?);
        let locked: bool = self
            .client
            .query_one("SELECT pg_try_advisory_lock($1,$2)", &[&namespace, &key])?
            .get(0);
        if !locked {
            return Err("another cooperative payout process holds the lease".into());
        }
        self.poc_lease = Some(vault);
        Ok(())
    }
    pub fn check_stagenet_poc_lease(
        &mut self,
        vault: Id,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if self.poc_lease != Some(vault) {
            return Err("PoC lease missing".into());
        }
        let namespace = 0x4357584di64;
        let key = u32::from_be_bytes(vault.0[..4].try_into()?) as i64;
        let held: bool = self.client.query_one("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND classid::bigint=$1 AND objid::bigint=$2 AND objsubid=2 AND granted)", &[&namespace, &key])?.get(0);
        if !held {
            self.poc_lease = None;
            return Err("PoC lease lost".into());
        }
        Ok(())
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
    if state
        .poc_attempts
        .iter()
        .any(|a| a.payout.reservation.domain.vault != vault)
        || state.intents.iter().any(|i| i.domain.vault != vault)
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
