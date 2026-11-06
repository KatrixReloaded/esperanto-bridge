use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use openssl::ssl::{SslAcceptor, SslMethod, SslVersion};
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::json;
use std::{
    io::{Read, Write},
    net::TcpListener,
    time::Duration,
};
use zz_watcher::{
    attestation::{self, BindingDomain, Identity},
    backup::Envelope,
    kms::{self, Kms},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    domain: BindingDomain,
    kms: kms::Config,
    initialize: bool,
}
fn bounded(response: reqwest::blocking::Response) -> Result<Vec<u8>> {
    ensure!(
        response.status().is_success(),
        "host transport rejected request"
    );
    let mut bytes = Vec::new();
    response.take(256 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 256 * 1024, "host response bound exceeded");
    Ok(bytes)
}
fn recover(config: &Config) -> Result<Identity> {
    // Production cannot proceed without the real NSM, including during a first initialization.
    attestation::attest(b"cwxmr-startup-preflight", b"v1", b"")?;
    let host = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(20))
        .build()?;
    let credentials: kms::Credentials = serde_json::from_slice(&bounded(
        host.get("http://127.0.0.1:8444/credentials").send()?,
    )?)?;
    let kms = Kms::new(config.kms.clone())?;
    let domain = config.domain.recovery_domain()?;
    let context = hex::encode(openssl::sha::sha256(&domain));
    let response = host.get("http://127.0.0.1:8444/backup").send()?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        ensure!(
            config.initialize,
            "backup missing; explicit initialization is required"
        );
        let identity = Identity::generate()?;
        let (key, wrapped) = kms.recover(None, &context, &credentials)?;
        let envelope = Envelope::seal(&identity, &key, wrapped, &domain)?;
        bounded(
            host.put("http://127.0.0.1:8444/backup")
                .json(&envelope)
                .send()?,
        )?;
        // Read back authenticated ciphertext before publishing this identity.
        let stored: Envelope =
            serde_json::from_slice(&bounded(host.get("http://127.0.0.1:8444/backup").send()?)?)?;
        let restored = stored.open(&key, &domain)?;
        ensure!(
            restored.public()?.vault_id == identity.public()?.vault_id,
            "backup readback mismatch"
        );
        let _core_cipher = zz_core::storage::Cipher::new(&key)
            .map_err(|_| anyhow::anyhow!("core cipher initialization failed"))?;
        Ok(identity)
    } else {
        let envelope: Envelope = serde_json::from_slice(&bounded(response)?)?;
        let (key, _) = kms.recover(Some(&envelope.wrapped_key), &context, &credentials)?;
        let identity = envelope.open(&key, &domain)?;
        let _core_cipher = zz_core::storage::Cipher::new(&key)
            .map_err(|_| anyhow::anyhow!("core cipher initialization failed"))?;
        Ok(identity)
    }
}
fn serve(identity: Identity, domain: BindingDomain, port: u16, native: bool) -> Result<()> {
    identity.validate_wallet()?;
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    acceptor.set_certificate(identity.certificate()?.as_ref())?;
    acceptor.set_private_key(identity.tls_key()?.as_ref())?;
    acceptor.check_private_key()?;
    let acceptor = acceptor.build();
    // Only the public TLS endpoint is forwarded. Secret SDK HTTP remains enclave-local.
    let _fhe = zz_zama::fhe::Client::new("http://127.0.0.1:8788")?;
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!(
        "{}",
        json!({"event":"runtime-ready","native_development":native,"identity":identity.public()?,"bridge_actions_enabled":false})
    );
    for socket in listener.incoming() {
        let socket = socket?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut stream = match acceptor.accept(socket) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut bytes = Vec::new();
        let mut scratch = [0u8; 1024];
        while bytes.len() < 8192 && !bytes.windows(4).any(|x| x == b"\r\n\r\n") {
            match stream.read(&mut scratch) {
                Ok(0) | Err(_) => break,
                Ok(n) => bytes.extend_from_slice(&scratch[..n]),
            };
        }
        let request = std::str::from_utf8(&bytes).unwrap_or("");
        let path = request.lines().next().unwrap_or("");
        let (status, body) = if path == "GET /health HTTP/1.1" {
            (
                "200 OK",
                json!({"runtime":"ready","native_development":native,"bridge_actions_enabled":false,"required_gates":["authenticated-chain-verification","payout-fencing","deployed-proof-and-FHE-roundtrip"]}),
            )
        } else if path == "GET /identity HTTP/1.1" {
            ("200 OK", serde_json::to_value(identity.public()?)?)
        } else if let Some(nonce) = path
            .strip_prefix("GET /attestation?nonce=")
            .and_then(|p| p.strip_suffix(" HTTP/1.1"))
        {
            let result = attestation::decode::<32>(nonce)
                .and_then(|nonce| Ok((nonce, identity.attest_identity(&domain, nonce)?)));
            match result {
                Ok((nonce, document)) => (
                    "200 OK",
                    json!({"purpose":"identity-discovery-only","document":STANDARD.encode(document),"identity":identity.public()?,"nonce":hex::encode(nonce),"user_data":hex::encode(identity.identity_binding(&domain,nonce)?)}),
                ),
                Err(_) => (
                    "503 Service Unavailable",
                    json!({"error":"real_nsm_attestation_required"}),
                ),
            }
        } else {
            ("404 Not Found", json!({"error":"route_not_available"}))
        };
        let body = serde_json::to_vec(&body)?;
        let header=format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",body.len());
        let _ = stream
            .write_all(header.as_bytes())
            .and_then(|_| stream.write_all(&body));
        let _ = stream.shutdown();
    }
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") => {
            let path = args.get(2).context("usage: zz-watcher serve CONFIG.json")?;
            let config: Config = serde_json::from_slice(&std::fs::read(path)?)?;
            let identity = recover(&config)?;
            serve(identity, config.domain, 8443, false)
        }
        Some("serve-dev") => {
            let port = args.get(2).map(|s| s.parse()).transpose()?.unwrap_or(8443);
            serve(
                Identity::generate()?,
                BindingDomain {
                    chain_id: 31337,
                    registry: "11".repeat(20),
                    bridge: "22".repeat(20),
                    policy_version: 1,
                },
                port,
                true,
            )
        }
        _ => bail!("usage: zz-watcher serve CONFIG.json | serve-dev [PORT]"),
    }
}
