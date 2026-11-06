//! Local Monero wallet primitives. These APIs do not validate consensus or authorize bridge actions.
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use hmac::{Hmac, Mac};
use monero_wallet::{
    address::{AddressType, MoneroAddress, Network, SubaddressIndex},
    ed25519::{Point, Scalar},
    Scanner, ViewPair, WalletOutput,
};
use sha2::Sha256;
use zeroize::Zeroizing;
use zz_core::{AtomicAmount, Domain, Id};

/// Construct a standard deterministic Monero view pair from a canonical private spend scalar.
/// The caller must generate/store the spend key inside the enclave and preserve it securely.
pub fn view_pair(spend: &Zeroizing<Scalar>) -> Result<ViewPair, &'static str> {
    if **spend == Scalar::ZERO {
        return Err("zero spend key");
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(32));
    spend
        .write(&mut *bytes)
        .map_err(|_| "spend key encoding failed")?;
    let view = Zeroizing::new(Scalar::hash(&*bytes));
    let public = Point::from(ED25519_BASEPOINT_POINT * (**spend).into());
    ViewPair::new(public, view).map_err(|_| "invalid view pair")
}

/// Account zero is reserved for bridge deposit intents; zero is the primary address.
pub fn subaddress(pair: &ViewPair, network: Network, index: u32) -> Result<String, &'static str> {
    let index =
        SubaddressIndex::new(0, index).ok_or("primary address is not a deposit subaddress")?;
    Ok(pair.subaddress(network, index).to_string())
}

/// Only standard and subaddresses on the configured network are accepted.
pub fn validate_destination(network: Network, text: &str) -> Result<MoneroAddress, &'static str> {
    let address =
        MoneroAddress::from_str(network, text).map_err(|_| "invalid address or network")?;
    if !matches!(
        address.kind(),
        AddressType::Legacy | AddressType::Subaddress
    ) {
        return Err("unsupported address type");
    }
    Ok(address)
}

/// Build a scanner over exactly the issued indices. Scanning results are observations, not proof
/// that the supplied block belongs to the canonical chain or that an output is spendable.
pub fn scanner(pair: ViewPair, indices: &[u32]) -> Result<Scanner, &'static str> {
    let mut scanner = Scanner::new(pair);
    for &index in indices {
        scanner
            .register_subaddress(SubaddressIndex::new(0, index).ok_or("invalid subaddress index")?);
    }
    Ok(scanner)
}

/// Derive a private, domain-separated identifier for one transaction output. The key must be
/// random, persistent, secret, and backed up alongside the wallet and intent mappings.
pub fn deposit_id(key: &[u8; 32], domain: &Domain, tx: [u8; 32], index: u64) -> Id {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(b"cwXMR/monero/output/v1\0");
    mac.update(&domain.chain_id.to_be_bytes());
    mac.update(&domain.bridge);
    mac.update(&domain.vault.0);
    mac.update(&tx);
    mac.update(&index.to_be_bytes());
    Id(mac.finalize().into_bytes().into())
}

/// Extract the decrypted amount locally; callers must durably detect duplicate output keys
/// (including the Monero burning bug), check change classification, and verify chain inclusion.
pub fn observed_amount(output: &WalletOutput) -> AtomicAmount {
    AtomicAmount(output.commitment().amount)
}

/// Identifier to reserve for a locally scanned output. Keep it within the enclave.
pub fn input_id(output: &WalletOutput) -> Id {
    Id(output.key().compress().to_bytes())
}

/// Check that the transaction uses exactly the uniquely reserved output keys.
pub fn verify_reserved_inputs(reserved: &[Id], selected: &[Id]) -> Result<(), String> {
    let reserved_set: std::collections::HashSet<_> = reserved.iter().copied().collect();
    let selected_set: std::collections::HashSet<_> = selected.iter().copied().collect();
    if reserved.is_empty()
        || reserved_set.len() != reserved.len()
        || selected_set.len() != selected.len()
        || reserved_set != selected_set
    {
        return Err("selected inputs do not match unique reservation".into());
    }
    Ok(())
}

/// Allocate inside `PostgresStore::update`, so the returned mapping is committed before use.
/// This does not protect against storage rollback or cloned enclaves.
pub fn allocate_intent(
    state: &mut zz_core::VaultState,
    pair: &ViewPair,
    network: Network,
    domain: Domain,
    id: Id,
    recipient: [u8; 20],
    nonce: Id,
) -> Result<zz_core::DepositIntent, String> {
    if let Some(existing) = state
        .intents
        .iter()
        .find(|i| i.id == id || (i.domain == domain && i.nonce == nonce))
    {
        if existing.id != id
            || existing.domain != domain
            || existing.recipient != recipient
            || existing.nonce != nonce
            || subaddress(pair, network, existing.subaddress_index)? != existing.subaddress
        {
            return Err("conflicting deposit intent".into());
        }
        return Ok(existing.clone());
    }
    let index = state
        .intents
        .iter()
        .map(|i| i.subaddress_index)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or("subaddress space exhausted")?;
    let intent = zz_core::DepositIntent {
        id,
        domain,
        recipient,
        nonce,
        subaddress_index: index,
        subaddress: subaddress(pair, network, index)?,
    };
    state
        .insert_intent(intent.clone())
        .map_err(|e| e.to_string())?;
    Ok(intent)
}

pub mod chain;
pub mod destination;

/// Construct and sign offline from already selected and durably reserved outputs and verified
/// decoys. This function does not establish that these prerequisites hold. The caller must also
/// verify assignment and payout fencing before releasing bytes for broadcast. Each incompatible
/// transaction must use a fresh, secret outgoing key, persisted with the pending attempt.
pub fn prepare_payout(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    spend: &Zeroizing<Scalar>,
    outgoing_key: Zeroizing<[u8; 32]>,
    network: Network,
    reservation: &zz_core::ReservedPayout,
    inputs: Vec<monero_wallet::OutputWithDecoys>,
    fee_rate: monero_wallet::interface::FeeRate,
) -> Result<zz_core::PreparedPayout, String> {
    use monero_wallet::{
        ringct::RctType,
        send::{Change, SignableTransaction},
    };
    let pair = view_pair(spend).map_err(str::to_owned)?;
    let destination =
        validate_destination(network, &reservation.destination).map_err(str::to_owned)?;
    if reservation.amount.0 == 0 {
        return Err("zero payout".into());
    }
    let selected: Vec<Id> = inputs
        .iter()
        .map(|o| Id(o.key().compress().to_bytes()))
        .collect();
    verify_reserved_inputs(&reservation.input_ids, &selected)?;
    let tx = SignableTransaction::new(
        RctType::ClsagBulletproofPlus,
        outgoing_key,
        inputs,
        vec![(destination, reservation.amount.0)],
        Change::new(pair, None),
        vec![],
        fee_rate,
    )
    .map_err(|e| format!("cannot construct transaction: {e:?}"))?;
    if tx.necessary_fee() > reservation.fee_headroom.0 {
        return Err("fee exceeds reservation".into());
    }
    let signed = tx
        .sign(rng, spend)
        .map_err(|e| format!("cannot sign transaction: {e:?}"))?;
    Ok(zz_core::PreparedPayout {
        reservation: reservation.clone(),
        transaction_id: Id(signed.hash()),
        signed_transaction: signed.serialize(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use monero_wallet::interface::FeeRate;

    fn pair() -> ViewPair {
        view_pair(&Zeroizing::new(Scalar::ONE)).unwrap()
    }
    fn domain() -> Domain {
        Domain {
            chain_id: 1,
            bridge: [2; 20],
            vault: Id([3; 32]),
        }
    }

    #[test]
    fn subaddresses_are_deterministic_and_network_checked() {
        let p = pair();
        let a = subaddress(&p, Network::Stagenet, 1).unwrap();
        assert_eq!(a, subaddress(&pair(), Network::Stagenet, 1).unwrap());
        assert_ne!(a, subaddress(&p, Network::Stagenet, 2).unwrap());
        assert!(validate_destination(Network::Stagenet, &a)
            .unwrap()
            .is_subaddress());
        assert!(validate_destination(Network::Mainnet, &a).is_err());
        assert!(subaddress(&p, Network::Stagenet, 0).is_err());
        assert!(view_pair(&Zeroizing::new(Scalar::ZERO)).is_err());
    }

    #[test]
    fn rejects_integrated_and_invalid_addresses() {
        let p = pair();
        assert!(validate_destination(
            Network::Mainnet,
            &p.legacy_address(Network::Mainnet).to_string()
        )
        .is_ok());
        assert!(validate_destination(
            Network::Mainnet,
            &p.legacy_integrated_address(Network::Mainnet, [0; 8])
                .to_string()
        )
        .is_err());
        assert!(validate_destination(Network::Mainnet, "not an address").is_err());
    }

    #[test]
    fn output_ids_are_stable_distinct_and_domain_bound() {
        let key = [9; 32];
        let d = domain();
        let id = deposit_id(&key, &d, [4; 32], 0);
        assert_eq!(id, deposit_id(&key, &d, [4; 32], 0));
        assert_ne!(id, deposit_id(&key, &d, [4; 32], 1));
        assert_ne!(id, deposit_id(&key, &d, [5; 32], 0));
        assert_ne!(id, deposit_id(&[8; 32], &d, [4; 32], 0));
        let mut other = d.clone();
        other.vault = Id([6; 32]);
        assert_ne!(id, deposit_id(&key, &other, [4; 32], 0));
    }

    #[test]
    fn intent_allocation_is_idempotent_and_rejects_conflicts() {
        let mut state = zz_core::VaultState::default();
        let first = allocate_intent(
            &mut state,
            &pair(),
            Network::Stagenet,
            domain(),
            Id([1; 32]),
            [4; 20],
            Id([5; 32]),
        )
        .unwrap();
        let retry = allocate_intent(
            &mut state,
            &pair(),
            Network::Stagenet,
            domain(),
            Id([1; 32]),
            [4; 20],
            Id([5; 32]),
        )
        .unwrap();
        assert!(first == retry);
        assert_eq!(first.subaddress_index, 1);
        assert!(allocate_intent(
            &mut state,
            &pair(),
            Network::Stagenet,
            domain(),
            Id([1; 32]),
            [7; 20],
            Id([5; 32])
        )
        .is_err());
        assert!(allocate_intent(
            &mut state,
            &pair(),
            Network::Mainnet,
            domain(),
            Id([1; 32]),
            [4; 20],
            Id([5; 32])
        )
        .is_err());
        let second = allocate_intent(
            &mut state,
            &pair(),
            Network::Stagenet,
            domain(),
            Id([2; 32]),
            [4; 20],
            Id([6; 32]),
        )
        .unwrap();
        assert_eq!(second.subaddress_index, 2);
    }

    #[test]
    fn rejects_corrupt_journal_bytes() {
        let r = zz_core::ReservedPayout {
            request_id: Id([1; 32]),
            domain: domain(),
            amount: AtomicAmount(1),
            fee_headroom: AtomicAmount(1),
            input_ids: vec![],
            destination: String::new(),
        };
        let p = zz_core::PreparedPayout {
            reservation: r,
            signed_transaction: vec![1, 2, 3],
            transaction_id: Id([0; 32]),
        };
        assert!(journaled_bytes(&p).is_err());
    }

    #[test]
    fn refuses_to_construct_without_inputs() {
        let r = zz_core::ReservedPayout {
            request_id: Id([1; 32]),
            domain: domain(),
            amount: AtomicAmount(1),
            fee_headroom: AtomicAmount(u64::MAX),
            input_ids: vec![],
            destination: pair().legacy_address(Network::Stagenet).to_string(),
        };
        let result = prepare_payout(
            &mut rand_core::OsRng,
            &Zeroizing::new(Scalar::ONE),
            Zeroizing::new([1; 32]),
            Network::Stagenet,
            &r,
            vec![],
            FeeRate::new(1, 1).unwrap(),
        );
        assert!(result.is_err());
    }
}

/// Recover the exact previously journaled bytes after validating their encoding and transaction ID.
/// This does not grant permission to broadcast: finalized assignment and rollback-resistant fencing
/// must be checked independently on every attempt.
pub fn journaled_bytes(prepared: &zz_core::PreparedPayout) -> Result<&[u8], &'static str> {
    use monero_wallet::transaction::Transaction;
    let mut cursor = std::io::Cursor::new(&prepared.signed_transaction);
    let tx = Transaction::read(&mut cursor).map_err(|_| "invalid transaction encoding")?;
    if cursor.position() != prepared.signed_transaction.len() as u64
        || tx.serialize() != prepared.signed_transaction
    {
        return Err("noncanonical transaction encoding");
    }
    if !matches!(
        &tx,
        Transaction::V2 {
            proofs: Some(_),
            ..
        }
    ) {
        return Err("unsupported transaction");
    }
    if Id(tx.hash()) != prepared.transaction_id {
        return Err("transaction id mismatch");
    }
    Ok(&prepared.signed_transaction)
}
