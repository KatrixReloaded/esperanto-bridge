use super::{evidence, Config};
use alloy::{
    primitives::{keccak256, Address, B256},
    sol_types::SolCall,
};
use anyhow::{ensure, Result};
use serde::Deserialize;
use serde_json::json;
use zz_zama::evm::{BlockObservation, Client, ReadMethod};
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pins {
    pub bridge: Address,
    pub bridge_code_hash: B256,
    pub registry: Address,
    pub registry_code_hash: B256,
    pub adapter: Address,
    pub adapter_code_hash: B256,
    pub verifier: Address,
    pub verifier_code_hash: B256,
}
alloy::sol! { interface PinReads {
    function registry() view returns(address); function bridge() view returns(address);
    function adapter() view returns(address); function verifier() view returns(address);
    function zkVerifier() view returns(address); function token() view returns(address);
    function decimals() view returns(uint8); function unsafeTestOnly() view returns(bool);
    function rootCert() view returns(bytes32); function programId() view returns(bytes32);
    function proofSelector() view returns(bytes4); function coprocessor() view returns(uint8);
    function configurationValid() view returns(bool);
    function approvedPcrTuples(uint64 version,bytes32 tuple) view returns(bool);
} }
async fn read<C: SolCall>(evm: &Client, to: Address, hash: B256, call: C) -> Result<C::Return> {
    Ok(C::abi_decode_returns_validate(
        &evm.call(to, call.abi_encode().into(), hash).await?.result,
    )?)
}
pub async fn verify(evm: &Client, config: &Config) -> Result<BlockObservation> {
    config.validate()?;
    let p = &config.pins;
    let head: BlockObservation = evm
        .read(ReadMethod::BlockByNumber, json!(["latest", false]))
        .await?
        .result;
    for (address, expected) in [
        (p.bridge, p.bridge_code_hash),
        (p.registry, p.registry_code_hash),
        (p.adapter, p.adapter_code_hash),
        (p.verifier, p.verifier_code_hash),
    ] {
        ensure!(
            !address.is_zero() && !expected.is_zero(),
            "development deployment pins missing"
        );
        let code: alloy::primitives::Bytes = evm
            .read(
                ReadMethod::Code,
                json!([address,{"blockHash":head.hash,"requireCanonical":true}]),
            )
            .await?
            .result;
        ensure!(
            !code.is_empty() && keccak256(&code) == expected,
            "development runtime hash mismatch"
        );
    }
    ensure!(
        read(evm, p.bridge, head.hash, PinReads::registryCall {}).await? == p.registry
            && read(evm, p.registry, head.hash, PinReads::bridgeCall {}).await? == p.bridge
            && read(evm, p.registry, head.hash, PinReads::adapterCall {}).await? == p.adapter,
        "development deployment link mismatch"
    );
    ensure!(
        read(evm, p.adapter, head.hash, PinReads::verifierCall {}).await? == p.verifier
            && read(evm, p.adapter, head.hash, PinReads::zkVerifierCall {}).await? == p.verifier,
        "unsafe verifier route mismatch"
    );
    ensure!(
        read(evm, p.verifier, head.hash, PinReads::unsafeTestOnlyCall {}).await?
            && read(
                evm,
                p.adapter,
                head.hash,
                PinReads::configurationValidCall {}
            )
            .await?,
        "explicit unsafe verifier marker required"
    );
    ensure!(
        read(evm, p.adapter, head.hash, PinReads::rootCertCall {}).await? == evidence::root()
            && read(evm, p.adapter, head.hash, PinReads::programIdCall {}).await?
                == evidence::program()
            && read(evm, p.adapter, head.hash, PinReads::proofSelectorCall {})
                .await?
                .as_slice()
                == [0x54, 0x53, 0x54, 0x31]
            && read(evm, p.adapter, head.hash, PinReads::coprocessorCall {}).await? == 2,
        "unsafe verifier constants mismatch"
    );
    ensure!(
        read(
            evm,
            p.registry,
            head.hash,
            PinReads::approvedPcrTuplesCall {
                version: 1,
                tuple: evidence::pcr_tuple()
            }
        )
        .await?,
        "test PCR policy not approved"
    );
    let token = read(evm, p.bridge, head.hash, PinReads::tokenCall {}).await?;
    ensure!(
        read(evm, token, head.hash, PinReads::decimalsCall {}).await? == 12,
        "unexpected token precision"
    );
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        primitives::{Bytes, FixedBytes},
        sol_types::SolValue,
    };
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
        time::Duration,
    };
    #[test]
    fn real_loopback_pin_protocol_rejects_wrong_hash_marker_and_route() {
        for failure in ["none", "hash", "marker", "route"] {
            let mut config = super::super::tests::config();
            let code = Bytes::from_static(&[0x60, 0x00]);
            let hash = keccak256(&code);
            config.pins.bridge_code_hash = hash;
            config.pins.registry_code_hash = hash;
            config.pins.adapter_code_hash = hash;
            config.pins.verifier_code_hash = hash;
            let pins = config.pins.clone();
            if failure == "hash" {
                config.pins.bridge_code_hash = B256::repeat_byte(5);
            }
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            listener.set_nonblocking(true).unwrap();
            let done = Arc::new(AtomicBool::new(false));
            let stop = done.clone();
            let server = thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let (mut socket, _) = match listener.accept() {
                        Ok(s) => s,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                            continue;
                        }
                        Err(e) => panic!("{e}"),
                    };
                    socket
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut header = Vec::new();
                    let mut byte = [0u8; 1];
                    while !header.ends_with(b"\r\n\r\n") {
                        socket.read_exact(&mut byte).unwrap();
                        header.push(byte[0]);
                    }
                    let text = String::from_utf8(header).unwrap();
                    assert!(text.starts_with("POST /evm/read "));
                    let len: usize = text
                        .lines()
                        .find_map(|l| {
                            l.to_lowercase()
                                .strip_prefix("content-length:")
                                .map(|n| n.trim().parse().unwrap())
                        })
                        .unwrap();
                    let mut body = vec![0; len];
                    socket.read_exact(&mut body).unwrap();
                    let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    let method = request["method"].as_str().unwrap();
                    let result = if method == "eth_getBlockByNumber" {
                        json!({"hash":format!("0x{}","ab".repeat(32)),"number":"0x10","parentHash":format!("0x{}","cd".repeat(32)),"timestamp":"0x65"})
                    } else if method == "eth_getCode" {
                        assert_eq!(request["params"][1]["requireCanonical"], true);
                        json!(code)
                    } else {
                        assert_eq!(method, "eth_call");
                        assert_eq!(request["params"][1]["requireCanonical"], true);
                        let raw = hex::decode(
                            request["params"][0]["data"]
                                .as_str()
                                .unwrap()
                                .trim_start_matches("0x"),
                        )
                        .unwrap();
                        let selector = &raw[..4];
                        let encoded = if selector == PinReads::registryCall::SELECTOR {
                            pins.registry.abi_encode()
                        } else if selector == PinReads::bridgeCall::SELECTOR {
                            pins.bridge.abi_encode()
                        } else if selector == PinReads::adapterCall::SELECTOR {
                            pins.adapter.abi_encode()
                        } else if selector == PinReads::verifierCall::SELECTOR
                            || selector == PinReads::zkVerifierCall::SELECTOR
                        {
                            if failure == "route" {
                                Address::ZERO.abi_encode()
                            } else {
                                pins.verifier.abi_encode()
                            }
                        } else if selector == PinReads::unsafeTestOnlyCall::SELECTOR {
                            (failure != "marker").abi_encode()
                        } else if selector == PinReads::configurationValidCall::SELECTOR
                            || selector == PinReads::approvedPcrTuplesCall::SELECTOR
                        {
                            true.abi_encode()
                        } else if selector == PinReads::rootCertCall::SELECTOR {
                            evidence::root().abi_encode()
                        } else if selector == PinReads::programIdCall::SELECTOR {
                            evidence::program().abi_encode()
                        } else if selector == PinReads::proofSelectorCall::SELECTOR {
                            FixedBytes::<4>::from([0x54, 0x53, 0x54, 0x31]).abi_encode()
                        } else if selector == PinReads::coprocessorCall::SELECTOR {
                            alloy::primitives::U256::from(2).abi_encode()
                        } else if selector == PinReads::tokenCall::SELECTOR {
                            Address::repeat_byte(5).abi_encode()
                        } else if selector == PinReads::decimalsCall::SELECTOR {
                            alloy::primitives::U256::from(12).abi_encode()
                        } else {
                            panic!("unexpected selector")
                        };
                        json!(Bytes::from(encoded))
                    };
                    let body=json!({"chainId":"11155111","trust":"explicitly_trusted_rpc","result":result}).to_string();
                    write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
                }
            });
            let rt = tokio::runtime::Runtime::new().unwrap();
            let result = rt.block_on(verify(&Client::new(&url).unwrap(), &config));
            done.store(true, Ordering::Relaxed);
            server.join().unwrap();
            assert_eq!(
                result.is_ok(),
                failure == "none",
                "case {failure}: {:?}",
                result.err()
            );
        }
    }
}
