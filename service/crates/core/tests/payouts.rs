use zz_core::{payouts::*, *};
fn domain() -> Domain {
    Domain {
        chain_id: 11155111,
        bridge: [2; 20],
        vault: Id([3; 32]),
    }
}
fn policy() -> StagenetPocPolicy {
    StagenetPocPolicy::accept_single_operator_single_process_no_rollback(domain()).unwrap()
}
fn evidence() -> ChainEvidence {
    ChainEvidence {
        block_hash: Id([7; 32]),
        height: 10,
    }
}
fn attempt() -> PocAttempt {
    PocAttempt {
        payout: PreparedPayout {
            reservation: ReservedPayout {
                request_id: Id([1; 32]),
                domain: domain(),
                amount: AtomicAmount(90),
                fee_headroom: AtomicAmount(10),
                input_ids: vec![Id([4; 32])],
                destination: "stagenet fixture".into(),
            },
            signed_transaction: vec![1, 2, 3],
            transaction_id: Id([5; 32]),
        },
        outgoing_key: [6; 32],
        actual_burn: AtomicAmount(100),
        fee_terms_hash: Id([8; 32]),
        nonzero_handle: Id([9; 32]),
        request_observed: evidence(),
        claim: None,
        claim_attempted: false,
        assignment: None,
        broadcast_attempted: false,
        broadcast_from: None,
        inclusion: None,
        settlement: None,
        settlement_attempted: false,
        settled: None,
    }
}
fn op(n: u64) -> EvmOperation {
    EvmOperation {
        domain: domain(),
        operation_id: Id([n as u8; 32]),
        signer: [4; 20],
        nonce: n,
        signed_bytes: vec![1, 2, 3],
        tx_hash: Id([n as u8; 32]),
    }
}
#[test]
fn production_closed_and_policy_refuses_mainnet() {
    assert_eq!(
        VaultState::default().authorize_broadcast(Id([1; 32])),
        Err(StateError::FencingUnavailable)
    );
    let mut d = domain();
    d.chain_id = 1;
    assert!(StagenetPocPolicy::accept_single_operator_single_process_no_rollback(d).is_err());
}
#[test]
fn immutable_attempt_assignment_races_and_ambiguous_sends() {
    let mut s = VaultState::default();
    let p = policy();
    let id = Id([1; 32]);
    s.prepare_poc(&p, attempt(), AtomicAmount(100)).unwrap();
    let mut changed = attempt();
    changed.payout.signed_transaction.push(4);
    assert!(s.prepare_poc(&p, changed, AtomicAmount(100)).is_err());
    assert!(s.attempt_poc_broadcast(&p, id, evidence()).is_err());
    s.journal_poc_claim(&p, id, op(1)).unwrap();
    s.attempt_poc_claim(&p, id).unwrap();
    assert!(s.attempt_poc_claim(&p, id).is_err());
    assert!(s
        .observe_poc_assignment(&p, id, Id([44; 32]), evidence())
        .is_err());
    s.observe_poc_assignment(&p, id, p.domain().vault, evidence())
        .unwrap();
    let bytes = s
        .attempt_poc_broadcast(&p, id, evidence())
        .unwrap()
        .signed_transaction;
    assert_eq!(bytes, vec![1, 2, 3]);
    let serialized = serde_json::to_vec(&s).unwrap();
    let mut restored: VaultState = serde_json::from_slice(&serialized).unwrap();
    assert!(restored.attempt_poc_broadcast(&p, id, evidence()).is_err());
    assert!(restored.journal_poc_settlement(&p, id, op(2)).is_err());
    restored.confirm_poc_payment(&p, id, evidence()).unwrap();
    restored.journal_poc_settlement(&p, id, op(2)).unwrap();
    restored.attempt_poc_settlement(&p, id).unwrap();
    assert!(restored.attempt_poc_settlement(&p, id).is_err());
    restored.confirm_poc_settlement(&p, id, evidence()).unwrap();
    let mut next = attempt();
    next.payout.reservation.request_id = Id([99; 32]);
    assert!(
        restored.prepare_poc(&p, next, AtomicAmount(100)).is_err(),
        "confirmed spent inputs cannot be reused"
    );
}
#[test]
fn zero_overflow_and_key_replacement_rejected() {
    let p = policy();
    let mut s = VaultState::default();
    let mut a = attempt();
    a.actual_burn = AtomicAmount(0);
    assert!(s.prepare_poc(&p, a, AtomicAmount(100)).is_err());
    let mut a = attempt();
    a.payout.reservation.amount = AtomicAmount(u64::MAX);
    assert!(s.prepare_poc(&p, a, AtomicAmount(u64::MAX)).is_err());
    let mut a = attempt();
    a.outgoing_key = [0; 32];
    assert!(s.prepare_poc(&p, a, AtomicAmount(100)).is_err());
    s.prepare_poc(&p, attempt(), AtomicAmount(100)).unwrap();
    let mut a = attempt();
    a.outgoing_key = [55; 32];
    assert!(s.prepare_poc(&p, a, AtomicAmount(100)).is_err());
    let mut a = attempt();
    a.payout.reservation.request_id = Id([55; 32]);
    a.payout.reservation.input_ids = vec![Id([56; 32])];
    a.payout.transaction_id = Id([57; 32]);
    assert!(
        s.prepare_poc(&p, a, AtomicAmount(200)).is_err(),
        "outgoing key cannot be reused for a different transaction"
    );
}

#[test]
fn cooperative_session_lease_loss_and_encrypted_restart() {
    use zz_core::storage::{Cipher, DataKeySource, PostgresStore};
    struct Key;
    impl DataKeySource for Key {
        fn data_key(&self) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
            Ok([77; 32])
        }
    }
    let Ok(url) = std::env::var("CWXMR_TEST_DATABASE_URL") else {
        return;
    };
    let mut first_client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let pid: i32 = first_client
        .query_one("SELECT pg_backend_pid()", &[])
        .unwrap()
        .get(0);
    let mut first = PostgresStore::new(first_client, Cipher::new(&Key).unwrap());
    first.migrate().unwrap();
    let mut random = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut random);
    let vault = Id(random);
    let mut d = domain();
    d.vault = vault;
    let p =
        StagenetPocPolicy::accept_single_operator_single_process_no_rollback(d.clone()).unwrap();
    first.initialize(vault).unwrap();
    first.acquire_stagenet_poc_lease(vault).unwrap();
    first.check_stagenet_poc_lease(vault).unwrap();
    let mut second = PostgresStore::new(
        postgres::Client::connect(&url, postgres::NoTls).unwrap(),
        Cipher::new(&Key).unwrap(),
    );
    assert!(second.acquire_stagenet_poc_lease(vault).is_err());
    let mut a = attempt();
    a.payout.reservation.domain = d;
    first
        .update(vault, |s| {
            s.prepare_poc(&p, a, AtomicAmount(100))?;
            Ok(())
        })
        .unwrap();
    let mut admin = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let blob: Vec<u8> = admin
        .query_one(
            "SELECT ciphertext FROM encrypted_vault_state WHERE vault_id=$1",
            &[&&vault.0[..]],
        )
        .unwrap()
        .get(0);
    let encoded_key = serde_json::to_vec(&[6u8; 32]).unwrap();
    assert!(!blob.windows(encoded_key.len()).any(|v| v == encoded_key));
    admin
        .query_one("SELECT pg_terminate_backend($1)", &[&pid])
        .unwrap();
    assert!(first.check_stagenet_poc_lease(vault).is_err());
    assert!(first.check_stagenet_poc_lease(vault).is_err());
    second.acquire_stagenet_poc_lease(vault).unwrap();
    second.check_stagenet_poc_lease(vault).unwrap();
    let restored = second.load(vault).unwrap();
    assert_eq!(
        restored.poc_attempt(&p, Id([1; 32])).unwrap().outgoing_key,
        [6; 32]
    );
    assert_eq!(
        restored
            .poc_attempt(&p, Id([1; 32]))
            .unwrap()
            .payout
            .signed_transaction,
        vec![1, 2, 3]
    );
}
