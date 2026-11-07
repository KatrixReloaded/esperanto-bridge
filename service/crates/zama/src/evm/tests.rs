use super::*;
use alloy::{
    consensus::{SignableTransaction, TxEip1559},
    eips::eip2718::Encodable2718,
    primitives::TxKind,
    signers::{local::PrivateKeySigner, SignerSync},
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

fn signed(chain_id: u64) -> Bytes {
    let signer: PrivateKeySigner =
        "1111111111111111111111111111111111111111111111111111111111111111"
            .parse()
            .unwrap();
    let tx = TxEip1559 {
        chain_id,
        nonce: 7,
        gas_limit: 21000,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        to: TxKind::Call(Address::repeat_byte(0x22)),
        ..Default::default()
    };
    let sig = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
    let envelope: TxEnvelope = tx.into_signed(sig).into();
    envelope.encoded_2718().into()
}
fn server(response: Option<Value>) -> (Client, thread::JoinHandle<(String, Value)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = Client::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0; 2048];
        let split = loop {
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&chunk[..n]);
            if let Some(i) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let header = String::from_utf8(bytes[..split].to_vec()).unwrap();
        let length: usize = header
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(|s| s.trim().parse().unwrap())
            })
            .unwrap();
        while bytes.len() - split < length {
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&chunk[..n]);
        }
        let body = serde_json::from_slice(&bytes[split..split + length]).unwrap();
        if let Some(response) = response {
            let encoded = serde_json::to_vec(&response).unwrap();
            let h=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",encoded.len());
            let _ = stream.write_all(h.as_bytes());
            let _ = stream.write_all(&encoded);
        }
        (header.lines().next().unwrap().to_owned(), body)
    });
    (client, worker)
}
fn receipt_value(hash: B256) -> Value {
    json!({"chainId":"11155111","trust":"explicitly_trusted_rpc","finality":"finalized",
        "finalizedHead":{"hash":B256::repeat_byte(1),"number":"0xa","parentHash":B256::repeat_byte(2),"timestamp":"0x65555555"},
        "receipt":{"transactionHash":hash,"blockHash":B256::repeat_byte(1),"blockNumber":"0xa","transactionIndex":"0x0","status":"0x1","gasUsed":"0x5208","logs":[{
            "address":Address::repeat_byte(0x22),"topics":[B256::repeat_byte(5)],"data":"0x1234","blockHash":B256::repeat_byte(1),"blockNumber":"0xa","transactionHash":hash,"transactionIndex":"0x0","logIndex":"0x0","removed":false}]}})
}
#[test]
fn journal_restore_is_exact_chain_bound_and_signature_checked() {
    let tx = SignedTransaction::from_signed_bytes(signed(CHAIN_ID)).unwrap();
    assert_eq!(tx.hash(), keccak256(tx.raw()));
    assert_eq!(
        SignedTransaction::restore(tx.raw().clone(), tx.hash())
            .unwrap()
            .raw(),
        tx.raw()
    );
    assert!(SignedTransaction::restore(tx.raw().clone(), B256::ZERO).is_err());
    assert!(SignedTransaction::from_signed_bytes(signed(1)).is_err());
    assert!(SignedTransaction::from_signed_bytes(Bytes::from_static(&[1, 2, 3])).is_err());
    let mut extra = tx.raw().to_vec();
    extra.push(0);
    assert!(SignedTransaction::from_signed_bytes(extra.into()).is_err());
}
#[test]
fn endpoints_are_enclave_local_only() {
    assert!(Client::new("http://127.0.0.1:8788/").is_ok());
    for url in [
        "https://127.0.0.1:8788",
        "http://localhost:8788",
        "http://127.1:8788",
        "http://127.0.0.1:0",
        "http://127.0.0.1:8788/path",
        "http://127.0.0.1:8788?x=1",
    ] {
        assert!(Client::new(url).is_err());
    }
}
#[tokio::test]
async fn submission_sends_persisted_bytes_once_and_ack_is_not_finality() {
    let tx = SignedTransaction::from_signed_bytes(signed(CHAIN_ID)).unwrap();
    let (client, worker) = server(Some(
        json!({"chainId":"11155111","hash":tx.hash(),"outcome":"accepted"}),
    ));
    assert_eq!(
        client.submit_journaled(&tx).await,
        SubmissionOutcome::Accepted { hash: tx.hash() }
    );
    let (path, body) = worker.join().unwrap();
    assert_eq!(path, "POST /evm/send HTTP/1.1");
    assert_eq!(body["rawTransaction"], json!(tx.raw()));
    assert_eq!(body["expectedHash"], json!(tx.hash()));
}
#[tokio::test]
async fn lost_ack_wrong_hash_wrong_chain_and_malformed_ack_are_ambiguous() {
    let tx = SignedTransaction::from_signed_bytes(signed(CHAIN_ID)).unwrap();
    for response in [
        None,
        Some(
            json!({"chainId":"11155111","hash":tx.hash(),"outcome":"ambiguous","reason":"submission_unknown"}),
        ),
        Some(json!({"chainId":"1","hash":tx.hash(),"outcome":"accepted"})),
        Some(json!({"chainId":"11155111","hash":B256::ZERO,"outcome":"accepted"})),
        Some(json!({"secret":"do not expose"})),
    ] {
        let (client, worker) = server(response);
        assert_eq!(
            client.submit_journaled(&tx).await,
            SubmissionOutcome::Ambiguous { hash: tx.hash() }
        );
        assert_eq!(worker.join().unwrap().1["rawTransaction"], json!(tx.raw()));
    }
}
#[tokio::test]
async fn read_observation_rejects_chain_and_trust_substitution() {
    for (chain, trust, valid) in [
        ("11155111", "explicitly_trusted_rpc", true),
        ("1", "explicitly_trusted_rpc", false),
        ("11155111", "authenticated_consensus", false),
    ] {
        let (client, worker) = server(Some(
            json!({"chainId":chain,"trust":trust,"result":"0x1234"}),
        ));
        let result = client
            .call(
                Address::repeat_byte(0x22),
                Bytes::new(),
                B256::repeat_byte(1),
            )
            .await;
        assert_eq!(result.is_ok(), valid);
        let (_, body) = worker.join().unwrap();
        assert_eq!(body["params"][1]["requireCanonical"], true);
        assert_eq!(body["method"], "eth_call");
    }
}
#[tokio::test]
async fn receipt_requires_consistent_hash_logs_finality_and_status() {
    let hash = B256::repeat_byte(8);
    let good = receipt_value(hash);
    let mut cases = vec![(good.clone(), true)];
    for (field, value) in [
        ("transactionHash", json!(B256::ZERO)),
        ("status", json!("0x2")),
        ("blockNumber", json!("0x0a")),
    ] {
        let mut bad = good.clone();
        bad["receipt"][field] = value;
        cases.push((bad, false));
    }
    let mut bad = good.clone();
    bad["receipt"]["logs"][0]["removed"] = json!(true);
    cases.push((bad, false));
    let mut bad = good.clone();
    bad["finality"] = json!("included");
    cases.push((bad, false));
    let mut bad = good.clone();
    bad["finalizedHead"]["hash"] = json!(B256::repeat_byte(9));
    cases.push((bad, false));
    cases.push((json!({"chainId":"11155111","trust":"explicitly_trusted_rpc","receipt":null,"finality":"not_found","finalizedHead":null}),true));
    for (value, valid) in cases {
        let (client, worker) = server(Some(value));
        assert_eq!(client.receipt(hash).await.is_ok(), valid);
        worker.join().unwrap();
    }
}

#[test]
fn only_matching_finalized_status_zero_receipt_permits_recovery() {
    let hash = B256::repeat_byte(8);
    let mut value = receipt_value(hash);
    let success: ReceiptObservation = serde_json::from_value(value.clone()).unwrap();
    assert!(success.finalized_revert(hash).unwrap().is_none());
    value["receipt"]["status"] = json!("0x0");
    let logs_on_revert: ReceiptObservation = serde_json::from_value(value.clone()).unwrap();
    assert!(logs_on_revert.finalized_revert(hash).is_err());
    value["receipt"]["logs"] = json!([]);
    let failed: ReceiptObservation = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        failed.finalized_revert(hash).unwrap(),
        Some(zz_core::ChainEvidence {
            block_hash: zz_core::Id(B256::repeat_byte(1).0),
            height: 10,
        })
    );
    assert!(failed.finalized_revert(B256::repeat_byte(9)).is_err());
    value["finality"] = json!("included");
    value["finalizedHead"]["number"] = json!("0x9");
    let included: ReceiptObservation = serde_json::from_value(value).unwrap();
    assert!(included.finalized_revert(hash).unwrap().is_none());
    let missing: ReceiptObservation = serde_json::from_value(json!({"chainId":"11155111",
        "trust":"explicitly_trusted_rpc","receipt":null,"finality":"not_found","finalizedHead":null})).unwrap();
    assert!(missing.finalized_revert(hash).unwrap().is_none());
}
