//! Enclave-local deposit issuance and scan persistence. No RPC observation directly signs a mint.
use crate::attestation::{decode, BindingDomain, Identity};
use anyhow::{ensure, Result};
use monero_wallet::{address::Network, Scanner, ViewPair};
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;
use zz_core::{
    deposits::{Deposit, MintState},
    storage::PostgresStore,
    ChainEvidence, DepositIntent, Domain, Id,
};
use zz_monero::chain::ObservedOutput;

pub struct Deposits {
    store: PostgresStore,
    domain: Domain,
    pair: ViewPair,
    id_key: Zeroizing<[u8; 32]>,
}

impl Deposits {
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
        store
            .load(domain.vault)
            .map_err(|_| anyhow::anyhow!("encrypted vault state unavailable"))?;
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
            .map(|i| i.subaddress_index)
            .collect::<Vec<_>>();
        zz_monero::scanner(self.pair.clone(), &indices).map_err(anyhow::Error::msg)
    }

    /// One database transaction for the complete scanned block. Primary-address/change and
    /// coinbase outputs cannot create deposit records; duplicate output keys reject the batch.
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

#[cfg(test)]
mod tests {
    use super::*;
    use zz_core::storage::{Cipher, DataKeySource};
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
    }
}
