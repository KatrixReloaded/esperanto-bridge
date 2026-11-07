use zz_core::{deposits::*, *};

fn id(n: u8) -> Id {
    Id([n; 32])
}
fn inclusion(n: u8) -> ChainEvidence {
    ChainEvidence {
        block_hash: id(n),
        height: n.into(),
    }
}
fn setup() -> (VaultState, Deposit) {
    let mut state = VaultState::default();
    state
        .insert_intent(DepositIntent {
            id: id(1),
            domain: Domain {
                chain_id: 11155111,
                bridge: [2; 20],
                vault: id(3),
            },
            recipient: [4; 20],
            nonce: id(5),
            subaddress_index: 1,
            subaddress: "fixture".into(),
        })
        .unwrap();
    let deposit = Deposit {
        id: id(6),
        intent_id: id(1),
        output_key: id(7),
        transaction: id(8),
        output_index: 0,
        amount: AtomicAmount(100),
        wallet_output: vec![1],
        inclusion: inclusion(9),
        state: MintState::Observed,
        quarantined: false,
    };
    state.observe_deposit(deposit.clone()).unwrap();
    (state, deposit)
}
fn authorization() -> MintAuthorization {
    MintAuthorization {
        amount_handle: id(10),
        input_proof: vec![11],
        nonce: 0,
        deadline: 500,
        signature: vec![12; 65],
    }
}
fn operation(state: &VaultState, deposit: Id) -> EvmOperation {
    EvmOperation {
        domain: state.intents[0].domain.clone(),
        operation_id: deposit,
        signer: [13; 20],
        nonce: 5,
        signed_bytes: vec![14],
        tx_hash: id(15),
    }
}

#[test]
fn restart_after_journaling_resumes_same_bytes_and_rejects_replacement() {
    let (mut state, deposit) = setup();
    state.authorize_mint(deposit.id, authorization()).unwrap();
    let original = operation(&state, deposit.id);
    state.journal_mint(deposit.id, original.clone()).unwrap();
    let bytes = serde_json::to_vec(&state).unwrap();
    let mut restored: VaultState = serde_json::from_slice(&bytes).unwrap();
    restored.observe_deposit(deposit.clone()).unwrap();
    restored.journal_mint(deposit.id, original.clone()).unwrap();
    assert_eq!(restored.evm_operations.len(), 1);
    assert!(restored.evm_operations[0] == original);
    let mut replacement = original;
    replacement.signed_bytes.push(16);
    assert!(restored.journal_mint(deposit.id, replacement).is_err());
    assert!(restored
        .confirm_mint(deposit.id, id(16), AtomicAmount(100), inclusion(20))
        .is_err());
    assert!(restored
        .confirm_mint(deposit.id, id(15), AtomicAmount(101), inclusion(20))
        .is_err());
    restored
        .confirm_mint(deposit.id, id(15), AtomicAmount(100), inclusion(20))
        .unwrap();
    restored
        .confirm_mint(deposit.id, id(15), AtomicAmount(100), inclusion(20))
        .unwrap();
    assert!(restored
        .authorize_mint(deposit.id, authorization())
        .is_err());
}

#[test]
fn duplicate_output_key_cannot_be_minted_through_another_intent_or_transaction() {
    let (mut state, mut deposit) = setup();
    let mut other = state.intents[0].clone();
    other.id = id(21);
    other.nonce = id(22);
    other.subaddress_index = 2;
    state.insert_intent(other).unwrap();
    deposit.id = id(23);
    deposit.intent_id = id(21);
    deposit.transaction = id(24);
    assert_eq!(
        state.observe_deposit(deposit.clone()),
        Err(StateError::Conflict)
    );
    deposit.output_key = id(25);
    state.observe_deposit(deposit.clone()).unwrap();
    state.authorize_mint(id(6), authorization()).unwrap();
    assert_eq!(
        state.authorize_mint(deposit.id, authorization()),
        Err(StateError::Conflict)
    );
}

#[test]
fn reorg_preserves_journal_and_blocks_actions_even_after_restart() {
    let (mut state, deposit) = setup();
    state.authorize_mint(deposit.id, authorization()).unwrap();
    let op = operation(&state, deposit.id);
    state.journal_mint(deposit.id, op.clone()).unwrap();
    state.quarantine_deposit(deposit.id).unwrap();
    let mut state: VaultState =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(state.journal_mint(deposit.id, op).is_err());
    assert!(state
        .confirm_mint(deposit.id, id(15), AtomicAmount(100), inclusion(20))
        .is_err());
    assert!(state.deposits[0].quarantined);
    assert_eq!(state.evm_operations.len(), 1);
}

#[test]
fn zero_actual_result_is_terminal_and_nonce_stays_reserved() {
    let (mut state, mut deposit) = setup();
    state.authorize_mint(deposit.id, authorization()).unwrap();
    state
        .journal_mint(deposit.id, operation(&state, deposit.id))
        .unwrap();
    state
        .confirm_mint(deposit.id, id(15), AtomicAmount(0), inclusion(20))
        .unwrap();
    assert!(state.authorize_mint(deposit.id, authorization()).is_err());
    deposit.id = id(21);
    deposit.output_key = id(22);
    deposit.transaction = id(23);
    state.observe_deposit(deposit.clone()).unwrap();
    assert_eq!(
        state.authorize_mint(deposit.id, authorization()),
        Err(StateError::Conflict)
    );
}

#[test]
fn expired_mint_recovery_preserves_terms_and_cannot_repeat_or_replace_a_transaction() {
    let (mut state, deposit) = setup();
    let original = authorization();
    state.authorize_mint(deposit.id, original.clone()).unwrap();
    for (expected, now, deadline, signature) in [
        (500, 500, 1100, vec![16; 65]),
        (499, 501, 1100, vec![16; 65]),
        (500, 501, 501, vec![16; 65]),
        (500, 501, 1100, vec![16; 64]),
    ] {
        assert!(state
            .clone()
            .renew_expired_mint(deposit.id, expected, now, deadline, signature)
            .is_err());
    }
    let mut quarantined = state.clone();
    quarantined.quarantine_deposit(deposit.id).unwrap();
    assert!(quarantined
        .renew_expired_mint(deposit.id, 500, 501, 1100, vec![16; 65])
        .is_err());
    let mut submitted = state.clone();
    submitted
        .journal_mint(deposit.id, operation(&state, deposit.id))
        .unwrap();
    assert!(submitted
        .renew_expired_mint(deposit.id, 500, 501, 1100, vec![16; 65])
        .is_err());
    state
        .renew_expired_mint(deposit.id, 500, 501, 1100, vec![16; 65])
        .unwrap();
    let mut restored: VaultState =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    let MintState::Authorized(renewed) = &restored.deposits[0].state else {
        panic!("missing authorization");
    };
    assert!(renewed.amount_handle == original.amount_handle);
    assert_eq!(renewed.input_proof, original.input_proof);
    assert_eq!(renewed.nonce, original.nonce);
    assert_eq!(renewed.deadline, 1100);
    assert_eq!(renewed.signature, vec![16; 65]);
    assert!(restored
        .renew_expired_mint(deposit.id, 500, 1101, 1701, vec![17; 65])
        .is_err());
}

#[test]
fn old_backups_load_without_deposit_records() {
    let state: VaultState = serde_json::from_str(
        r#"{"intents":[],"payouts":[],"mint_results":[],"evm_operations":[]}"#,
    )
    .unwrap();
    assert!(state.deposits.is_empty());
}

#[test]
fn finalized_revert_recovery_preserves_history_terms_and_consumed_gas_nonce() {
    let (mut state, deposit) = setup();
    let auth = authorization();
    state.authorize_mint(deposit.id, auth.clone()).unwrap();
    let failed = operation(&state, deposit.id);
    state.journal_mint(deposit.id, failed.clone()).unwrap();
    for (transaction, evidence, now, deadline, signature) in [
        (id(16), inclusion(20), 501, 1100, vec![17; 65]),
        (failed.tx_hash, inclusion(0), 501, 1100, vec![17; 65]),
        (failed.tx_hash, inclusion(20), 500, 1100, vec![17; 65]),
        (failed.tx_hash, inclusion(20), 501, 501, vec![17; 65]),
        (failed.tx_hash, inclusion(20), 501, 1100, vec![17; 64]),
    ] {
        assert!(state
            .clone()
            .recover_reverted_mint(deposit.id, transaction, evidence, now, deadline, signature)
            .is_err());
    }
    let mut quarantined = state.clone();
    quarantined.quarantine_deposit(deposit.id).unwrap();
    assert!(quarantined
        .recover_reverted_mint(
            deposit.id,
            failed.tx_hash,
            inclusion(20),
            501,
            1100,
            vec![17; 65]
        )
        .is_err());
    let mut missing = state.clone();
    missing.evm_operations.clear();
    assert!(missing
        .recover_reverted_mint(
            deposit.id,
            failed.tx_hash,
            inclusion(20),
            501,
            1100,
            vec![17; 65]
        )
        .is_err());
    state
        .recover_reverted_mint(
            deposit.id,
            failed.tx_hash,
            inclusion(20),
            501,
            1100,
            vec![17; 65],
        )
        .unwrap();
    let mut state: VaultState =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(state.evm_operations.is_empty());
    assert_eq!(state.reverted_mints.len(), 1);
    assert!(state.reverted_mints[0].operation == failed);
    assert!(state.reverted_mints[0].authorization == auth);
    assert_eq!(state.reverted_mints[0].inclusion, inclusion(20));
    let MintState::Authorized(renewed) = &state.deposits[0].state else {
        panic!("not recovered");
    };
    let mut expected = auth;
    expected.deadline = 1100;
    expected.signature = vec![17; 65];
    assert!(*renewed == expected);
    assert!(state
        .recover_reverted_mint(
            deposit.id,
            failed.tx_hash,
            inclusion(20),
            1101,
            1700,
            vec![18; 65]
        )
        .is_err());
    let mut retry = failed.clone();
    retry.tx_hash = id(18);
    retry.signed_bytes = vec![19];
    assert_eq!(
        state.journal_mint(deposit.id, retry.clone()),
        Err(StateError::Conflict)
    );
    retry.nonce += 1;
    state.journal_mint(deposit.id, retry.clone()).unwrap();
    assert!(state.evm_operations[0] == retry);
    assert!(state.reverted_mints[0].operation == failed);
    // The bridge authorization nonce also remains assigned to this deposit.
    let mut other = deposit;
    other.id = id(21);
    other.output_key = id(22);
    other.transaction = id(23);
    state.observe_deposit(other.clone()).unwrap();
    assert_eq!(
        state.authorize_mint(other.id, authorization()),
        Err(StateError::Conflict)
    );
}
