//! Opt-in live test; uses public fixture keys, no wallet funds or signing.
use monero_wallet::ed25519::Scalar;
use zeroize::Zeroizing;
use zz_monero::{scanner, stagenet::TrustedStagenet, view_pair};

#[tokio::test]
#[ignore = "requires a running Nym SOCKS listener and explicit trusted stagenet daemon"]
async fn trusted_stagenet_tip_and_scan_round_trip() {
    let node = std::env::var("CWXMR_STAGENET_RPC").expect("set CWXMR_STAGENET_RPC");
    let daemon = TrustedStagenet::connect(&node)
        .await
        .expect("stagenet genesis");
    let tip = daemon.tip().await.expect("tip");
    let bytes =
        hex::decode("ccf0ea10e1ea64354f42fa710c2b318e581969cf49046d809d1f0aadb3fc7a02").unwrap();
    let spend = Zeroizing::new(Scalar::read(&mut bytes.as_slice()).unwrap());
    let mut scanner = scanner(view_pair(&spend).unwrap(), &[1]).unwrap();
    let block = daemon
        .scan_height(&mut scanner, tip.height)
        .await
        .expect("scan block");
    assert_eq!(block.block.height, tip.height);
    assert_eq!(block.block.block_hash, tip.block_hash);
}
