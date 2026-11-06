use std::error::Error;
use zz_core::{
    storage::{Cipher, DataKeySource, PostgresStore},
    *,
};
struct Key;
impl DataKeySource for Key {
    fn data_key(&self) -> Result<[u8; 32], Box<dyn Error + Send + Sync>> {
        Ok([7; 32])
    }
}
fn domain() -> Domain {
    Domain {
        chain_id: 11155111,
        bridge: [2; 20],
        vault: Id([3; 32]),
    }
}
fn payout(id: u8) -> ReservedPayout {
    ReservedPayout {
        request_id: Id([id; 32]),
        domain: domain(),
        amount: AtomicAmount(6),
        fee_headroom: AtomicAmount(1),
        input_ids: vec![Id([id; 32])],
        destination: "secret address".into(),
    }
}
#[test]
fn reservations_and_restart_do_not_create_second_transaction() {
    let cipher = Cipher::new(&Key).unwrap();
    let mut state = VaultState::default();
    state.reserve(payout(1), AtomicAmount(10)).unwrap();
    state.reserve(payout(1), AtomicAmount(10)).unwrap();
    let mut overlap = payout(2);
    overlap.input_ids = payout(1).input_ids;
    assert_eq!(
        state.reserve(overlap, AtomicAmount(100)),
        Err(StateError::Conflict)
    );
    assert_eq!(
        state.reserve(payout(2), AtomicAmount(10)),
        Err(StateError::InsufficientFunds)
    );
    let signed = PreparedPayout {
        reservation: payout(1),
        signed_transaction: vec![1, 2, 3],
        transaction_id: Id([9; 32]),
    };
    state.prepare(signed.clone()).unwrap();
    let blob = cipher.seal(domain().vault, &state).unwrap();
    assert!(!blob.windows(14).any(|w| w == b"secret address"));
    let mut restored = cipher.open(domain().vault, &blob).unwrap();
    restored.prepare(signed.clone()).unwrap();
    let mut other = signed;
    other.signed_transaction.push(4);
    assert_eq!(restored.prepare(other), Err(StateError::Conflict));
    assert_eq!(
        restored.authorize_broadcast(Id([1; 32])),
        Err(StateError::FencingUnavailable)
    );
    let mut tampered = blob.clone();
    tampered[25] ^= 1;
    assert!(cipher.open(domain().vault, &tampered).is_err());
    assert!(cipher.open(Id([4; 32]), &blob).is_err());
}
#[test]
fn actual_results_are_idempotent_and_nonzero() {
    let mut state = VaultState::default();
    assert_eq!(
        state.record_mint_result(Id([1; 32]), AtomicAmount(0)),
        Err(StateError::ZeroResult)
    );
    state
        .record_mint_result(Id([1; 32]), AtomicAmount(8))
        .unwrap();
    state
        .record_mint_result(Id([1; 32]), AtomicAmount(8))
        .unwrap();
    assert_eq!(
        state.record_mint_result(Id([1; 32]), AtomicAmount(9)),
        Err(StateError::Conflict)
    );
}
#[test]
fn postgres_persistence_and_racing_reservations() {
    let Ok(url) = std::env::var("CWXMR_TEST_DATABASE_URL") else {
        return;
    };
    let mut client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    client
        .batch_execute(include_str!("../../../migrations/001_encrypted_vault.sql"))
        .unwrap();
    let vault = domain().vault;
    client
        .execute(
            "DELETE FROM encrypted_vault_state WHERE vault_id=$1",
            &[&&vault.0[..]],
        )
        .unwrap();
    let mut store = PostgresStore::new(
        postgres::Client::connect(&url, postgres::NoTls).unwrap(),
        Cipher::new(&Key).unwrap(),
    );
    store.initialize(vault).unwrap();
    let threads: Vec<_> = (1..=2)
        .map(|id| {
            let url = url.clone();
            std::thread::spawn(move || {
                let mut s = PostgresStore::new(
                    postgres::Client::connect(&url, postgres::NoTls).unwrap(),
                    Cipher::new(&Key).unwrap(),
                );
                s.update(vault, |state| {
                    state.reserve(payout(id), AtomicAmount(10))?;
                    Ok(())
                })
                .is_ok()
            })
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .filter(|ok| *ok)
            .count(),
        1
    );
    drop(store);
    let mut restarted = PostgresStore::new(
        postgres::Client::connect(&url, postgres::NoTls).unwrap(),
        Cipher::new(&Key).unwrap(),
    );
    assert_eq!(
        restarted
            .update(vault, |state| Ok(state.payouts.len()))
            .unwrap(),
        1
    );
    let row = client
        .query_one(
            "SELECT ciphertext FROM encrypted_vault_state WHERE vault_id=$1",
            &[&&vault.0[..]],
        )
        .unwrap();
    let blob: Vec<u8> = row.get(0);
    assert!(!blob.windows(14).any(|w| w == b"secret address"));
    client
        .execute(
            "DELETE FROM encrypted_vault_state WHERE vault_id=$1",
            &[&&vault.0[..]],
        )
        .unwrap();
    assert!(restarted.update(vault, |_| Ok(())).is_err());
}
