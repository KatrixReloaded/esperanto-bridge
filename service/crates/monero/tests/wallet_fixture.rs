// Test data from monero-wallet 0.2.0 src/tests/scan.rs, MIT licensed.
// Synthetic decoys below are deliberately invalid for network broadcast.
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use monero_wallet::{
    address::Network,
    block::Block,
    ed25519::{Point, Scalar},
    interface::{FeeRate, ScannableBlock},
    ringct::clsag::Decoys,
    transaction::{Pruned, Timelock, Transaction},
    OutputWithDecoys, Scanner, ViewPair,
};
use zeroize::Zeroizing;
use zz_core::{AtomicAmount, ChainEvidence, Domain, Id, ReservedPayout};
use zz_monero::{
    chain::{self, AuthenticatedChain, ChainStatus},
    journaled_bytes, prepare_payout, verify_reserved_inputs,
};

fn scalar(s: &str) -> Scalar {
    Scalar::read(&mut hex::decode(s).unwrap().as_slice()).unwrap()
}
fn spend() -> Zeroizing<Scalar> {
    Zeroizing::new(scalar(
        "ccf0ea10e1ea64354f42fa710c2b318e581969cf49046d809d1f0aadb3fc7a02",
    ))
}
fn fixture() -> (ScannableBlock, Scanner) {
    let block = Block::read(
        &mut hex::decode(include_str!("fixtures/block.hex").trim())
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let tx = Transaction::<Pruned>::read(
        &mut hex::decode(include_str!("fixtures/tx.hex").trim())
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let public = Point::from(ED25519_BASEPOINT_POINT * (*spend()).into());
    let view = Zeroizing::new(scalar(
        "a28b4b2085592881df94ee95da332c16b5bb773eb8bb74730208cbb236c73806",
    ));
    (
        ScannableBlock {
            block,
            transactions: vec![tx],
            output_index_for_first_ringct_output: Some(0),
        },
        Scanner::new(ViewPair::new(public, view).unwrap()),
    )
}
struct FixtureChain {
    block: ScannableBlock,
    tip: u64,
    canonical: bool,
}
impl AuthenticatedChain for FixtureChain {
    type Error = ();
    fn tip(&self) -> Result<ChainEvidence, ()> {
        Ok(ChainEvidence {
            height: self.tip,
            block_hash: Id([8; 32]),
        })
    }
    fn canonical_hash(&self, height: u64) -> Result<Option<Id>, ()> {
        if height == self.tip {
            return Ok(Some(Id([8; 32])));
        }
        if height == self.block.block.number() as u64 && self.canonical {
            return Ok(Some(Id(self.block.block.hash())));
        }
        if height == self.block.block.number() as u64 {
            return Ok(Some(Id([9; 32])));
        }
        Ok(None)
    }
    fn consensus_time(&self) -> Result<u64, ()> {
        Ok(2_000_000_000)
    }
    fn scannable_block(&self, _: u64) -> Result<ScannableBlock, ()> {
        Ok(self.block.clone())
    }
}

#[test]
fn scans_fixture_and_reassesses_confirmations_and_reorg() {
    let (block, mut scanner) = fixture();
    let height = block.block.number() as u64;
    let mut chain = FixtureChain {
        block,
        tip: height + 9,
        canonical: true,
    };
    let outputs = chain::scan_block(&chain, &mut scanner, height).unwrap();
    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[0].output.commitment().amount, 10_000);
    assert_ne!(outputs[0].output.key(), outputs[1].output.key());
    assert_eq!(
        chain::status(&chain, &outputs[0], 2).unwrap(),
        ChainStatus::Pending
    );
    chain.tip += 1;
    assert_eq!(
        chain::status(&chain, &outputs[0], 2).unwrap(),
        ChainStatus::Mature
    );
    assert_eq!(
        chain::status(&chain, &outputs[0], 12).unwrap(),
        ChainStatus::Pending
    );
    // Replace only the upstream wallet fixture's serialized additional timelock field.
    let mut bytes = outputs[0].output.serialize();
    assert_eq!(bytes[152], 0);
    bytes.splice(152..153, Timelock::Block(50).serialize());
    let locked = chain::ObservedOutput {
        output: monero_wallet::WalletOutput::read(&mut bytes.as_slice()).unwrap(),
        block: outputs[0].block.clone(),
        coinbase: false,
    };
    assert_eq!(
        chain::status(&chain, &locked, 2).unwrap(),
        ChainStatus::Pending
    );
    chain.tip = 50;
    assert_eq!(
        chain::status(&chain, &locked, 2).unwrap(),
        ChainStatus::Mature
    );
    let mut bytes = outputs[0].output.serialize();
    bytes.splice(152..153, Timelock::Time(2_000_000_001).serialize());
    let locked = chain::ObservedOutput {
        output: monero_wallet::WalletOutput::read(&mut bytes.as_slice()).unwrap(),
        block: outputs[0].block.clone(),
        coinbase: false,
    };
    assert_eq!(
        chain::status(&chain, &locked, 2).unwrap(),
        ChainStatus::Pending
    );
    let coinbase = chain::ObservedOutput {
        output: outputs[0].output.clone(),
        block: outputs[0].block.clone(),
        coinbase: true,
    };
    assert_eq!(
        chain::status(&chain, &coinbase, 2).unwrap(),
        ChainStatus::Pending
    );
    chain.tip = height + 60;
    assert_eq!(
        chain::status(&chain, &coinbase, 2).unwrap(),
        ChainStatus::Mature
    );
    chain.canonical = false;
    assert_eq!(
        chain::status(&chain, &outputs[0], 2).unwrap(),
        ChainStatus::Reorganized
    );
}

#[test]
fn signs_fixture_with_synthetic_decoys_and_recovers_exact_bytes() {
    let (block, mut scanner) = fixture();
    let outputs = scanner.scan(block).unwrap().ignore_additional_timelock();
    let output = &outputs[0];
    let mut ring = vec![[output.key(), output.commitment().commit()]];
    for i in 1u64..16 {
        let scalar = curve25519_dalek::Scalar::from(i);
        let point = Point::from(ED25519_BASEPOINT_POINT * scalar);
        ring.push([point, point]);
    }
    let decoys = Decoys::new(vec![1; 16], 0, ring).unwrap();
    let mut data = output.key().compress().to_bytes().to_vec();
    output.key_offset().write(&mut data).unwrap();
    output.commitment().write(&mut data).unwrap();
    decoys.write(&mut data).unwrap();
    let input = OutputWithDecoys::read(&mut data.as_slice()).unwrap();
    let id = Id(input.key().compress().to_bytes());
    assert!(verify_reserved_inputs(&[id, id], &[id, id]).is_err());
    assert!(verify_reserved_inputs(&[id], &[Id([1; 32])]).is_err());
    let reservation = ReservedPayout {
        request_id: Id([1; 32]),
        domain: Domain {
            chain_id: 1,
            bridge: [2; 20],
            vault: Id([3; 32]),
        },
        amount: AtomicAmount(100),
        fee_headroom: AtomicAmount(9_000),
        input_ids: vec![id],
        destination: zz_monero::view_pair(&spend())
            .unwrap()
            .legacy_address(Network::Stagenet)
            .to_string(),
    };
    let prepared = prepare_payout(
        &mut rand_core::OsRng,
        &spend(),
        Zeroizing::new([1; 32]),
        Network::Stagenet,
        &reservation,
        vec![input],
        FeeRate::new(1, 1).unwrap(),
    )
    .unwrap();
    assert_eq!(
        journaled_bytes(&prepared).unwrap(),
        prepared.signed_transaction
    );
    let mut modified = prepared.clone();
    modified.transaction_id = Id([0; 32]);
    assert!(journaled_bytes(&modified).is_err());
}
