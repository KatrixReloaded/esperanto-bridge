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
fn old_backups_load_without_deposit_records() {
    let state: VaultState = serde_json::from_str(
        r#"{"intents":[],"payouts":[],"mint_results":[],"evm_operations":[]}"#,
    )
    .unwrap();
    assert!(state.deposits.is_empty());
}
