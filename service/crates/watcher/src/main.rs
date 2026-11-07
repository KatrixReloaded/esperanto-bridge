mod database;
mod http;
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use openssl::ssl::{SslAcceptor, SslMethod, SslVersion};
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::json;
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use zz_watcher::{
    attestation::{self, BindingDomain, Identity},
    backup::Envelope,
    deposits::Deposits,
    kms::{self, Kms},
    mints::{self, Mints},
    withdrawals::{self, Withdrawals},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    domain: BindingDomain,
    kms: kms::Config,
    initialize: bool,
    database: database::Config,
    monero: MoneroConfig,
    #[serde(default)]
    minting: Option<mints::Config>,
    #[serde(default)]
    withdrawals: Option<withdrawals::Config>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MoneroConfig {
    rpc_url: String,
    birth_height: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentRequest {
    recipient: String,
    nonce: String,
}

impl Config {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.domain.chain_id == 11155111,
            "runtime requires Sepolia/stagenet"
        );
        if let Some(minting) = &self.minting {
            minting.validate()?;
            ensure!(
                !self.initialize,
                "minting requires an explicitly restored identity"
            );
        }
        if let Some(withdrawals) = &self.withdrawals {
            withdrawals.validate()?;
            ensure!(
                self.minting.is_some() && !self.initialize,
                "withdrawals require the restored mint identity and deployment policy"
            );
        }
        Ok(())
    }
}

fn retryable_sync(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<zz_watcher::deposits::ChainUnavailable>()
        .is_some()
}

/// The worker owns chain progress. A poisoned mutex, repeated failures or reconciliation error
/// permanently mark the scanner stopped until operator intervention/restart.
fn start_sync(
    deposits: Arc<Mutex<Deposits>>,
    config: MoneroConfig,
    health: Arc<AtomicU8>,
    identity: Arc<Identity>,
    binding: BindingDomain,
    minting: Option<mints::Config>,
    withdrawals: Option<withdrawals::Config>,
) {
    std::thread::spawn(move || {
        struct Stopped(Arc<AtomicU8>);
        impl Drop for Stopped {
            fn drop(&mut self) {
                self.0.store(3, Ordering::Relaxed);
            }
        }
        let _stopped = Stopped(health.clone());
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => return,
        };
        let mut failures = 0u8;
        let chain = loop {
            match runtime.block_on(zz_monero::stagenet::TrustedStagenet::connect(
                &config.rpc_url,
            )) {
                Ok(chain) => break chain,
                Err(_) => {
                    health.store(2, Ordering::Relaxed);
                    failures += 1;
                    if failures >= 5 {
                        return;
                    }
                    std::thread::sleep(Duration::from_secs(u64::from(failures) * 5));
                }
            }
        };
        let chain = match minting.as_ref().and_then(|m| m.demo_mint_confirmations) {
            Some(n) => match chain.with_demo_mint_confirmations(n) {
                Ok(chain) => chain,
                Err(_) => return,
            },
            None => chain,
        };
        let payout_fees = minting.as_ref().map(mints::Config::fees);
        let mints = match minting.map(Mints::new).transpose() {
            Ok(mints) => mints,
            Err(_) => return,
        };
        if let Some(mints) = &mints {
            if runtime.block_on(mints.verify(&identity, &binding)).is_err() {
                return;
            }
        }
        let mut withdrawals = match withdrawals {
            Some(config) => {
                let Some(fees) = payout_fees else {
                    return;
                };
                let Ok(mut deposits) = deposits.lock() else {
                    return;
                };
                match runtime.block_on(Withdrawals::new(
                    config,
                    fees,
                    &mut deposits,
                    &identity,
                    &binding,
                    &chain,
                )) {
                    Ok(controller) => Some(controller),
                    Err(_) => return,
                }
            }
            None => None,
        };
        failures = 0;
        loop {
            let result = match deposits.lock() {
                Ok(mut deposits) => {
                    runtime.block_on(deposits.sync_once(&chain, config.birth_height))
                }
                Err(_) => return,
            };
            match result {
                Ok(advanced) => {
                    failures = 0;
                    health.store(1, Ordering::Relaxed);
                    if !advanced {
                        if let Some(mints) = &mints {
                            // Serialize scan, proof and nonce allocation. A failed proof/mint stops
                            // the worker; restarting cannot implicitly resubmit a paid proof job.
                            let result = match deposits.lock() {
                                Ok(mut deposits) => runtime.block_on(async {
                                    let pending_mints = deposits.pending_mints()?;
                                    let pending_payout = match withdrawals.as_mut() {
                                        Some(payouts) => payouts.has_pending()?,
                                        None => false,
                                    };
                                    // A submitted mint is reconciled first. An existing payout
                                    // owns the signer until completion; only then can new mint
                                    // authorizations or another payout be scheduled.
                                    let submitted_mint =
                                        pending_mints.iter().any(|(_, submitted)| *submitted);
                                    if submitted_mint
                                        || (!pending_payout && !pending_mints.is_empty())
                                    {
                                        mints
                                            .step(&mut deposits, &identity, &binding, &chain)
                                            .await?;
                                    } else if let Some(payouts) = withdrawals.as_mut() {
                                        payouts.step(&identity, &binding, &chain, mints).await?;
                                    }
                                    Ok::<(), anyhow::Error>(())
                                }),
                                Err(_) => return,
                            };
                            if result.is_err() {
                                eprintln!("Mint runner stopped; reconcile the persistent proof and transaction journals");
                                return;
                            }
                        }
                        std::thread::sleep(Duration::from_secs(10));
                    }
                }
                Err(error) => {
                    health.store(2, Ordering::Relaxed);
                    if !retryable_sync(&error) {
                        return;
                    }
                    failures += 1;
                    if failures >= 5 {
                        return;
                    }
                    std::thread::sleep(Duration::from_secs(u64::from(failures) * 5));
                }
            }
        }
    });
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
fn recover(config: &Config) -> Result<(Identity, zz_core::storage::Cipher, bool)> {
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
        let core_cipher = zz_core::storage::Cipher::new(&key)
            .map_err(|_| anyhow::anyhow!("core cipher initialization failed"))?;
        Ok((identity, core_cipher, true))
    } else {
        let envelope: Envelope = serde_json::from_slice(&bounded(response)?)?;
        let (key, _) = kms.recover(Some(&envelope.wrapped_key), &context, &credentials)?;
        let identity = envelope.open(&key, &domain)?;
        let core_cipher = zz_core::storage::Cipher::new(&key)
            .map_err(|_| anyhow::anyhow!("core cipher initialization failed"))?;
        Ok((identity, core_cipher, false))
    }
}
fn serve(
    identity: Arc<Identity>,
    domain: BindingDomain,
    port: u16,
    native: bool,
    deposits: Option<Arc<Mutex<Deposits>>>,
    sync_health: Arc<AtomicU8>,
    minting_enabled: bool,
    withdrawals_enabled: bool,
) -> Result<()> {
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
        json!({"event":"runtime-ready","native_development":native,"identity":identity.public()?,"bridge_actions_enabled":minting_enabled,"withdrawals_enabled":withdrawals_enabled})
    );
    for socket in listener.incoming() {
        let socket = socket?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut stream = match acceptor.accept(socket) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let request = match http::read_request(&mut stream) {
            Ok(request) => request,
            Err(_) => {
                let _ = stream.write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                continue;
            }
        };
        let (status, body) = if request.method == "GET" && request.target == "/health" {
            let scan = match sync_health.load(Ordering::Relaxed) {
                0 => "starting",
                1 => "running",
                2 => "degraded",
                _ => "stopped",
            };
            let runtime = if !native && sync_health.load(Ordering::Relaxed) >= 2 {
                "degraded"
            } else {
                "ready"
            };
            (
                "200 OK",
                json!({"runtime":runtime,"native_development":native,"bridge_actions_enabled":minting_enabled && sync_health.load(Ordering::Relaxed)==1,"withdrawals_enabled":withdrawals_enabled && sync_health.load(Ordering::Relaxed)==1,"monero_sync":scan,"trust_model":"trusted-stagenet-single-operator-no-rollback"}),
            )
        } else if request.method == "GET" && request.target == "/identity" {
            ("200 OK", serde_json::to_value(identity.public()?)?)
        } else if request.method == "GET" && request.target.starts_with("/attestation?nonce=") {
            let nonce = &request.target["/attestation?nonce=".len()..];
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
        } else if (request.method == "POST" && request.target == "/v1/deposit-intents")
            || (request.method == "GET" && request.target.starts_with("/v1/deposit-intents/"))
        {
            if !minting_enabled || sync_health.load(Ordering::Relaxed) != 1 {
                (
                    "503 Service Unavailable",
                    json!({"error":"bridge_actions_disabled"}),
                )
            } else if let Some(ref shared) = deposits {
                match shared.try_lock() {
                    Ok(mut deposits) => {
                        let result = if request.method == "POST" {
                            serde_json::from_slice::<IntentRequest>(&request.body)
                                .map_err(anyhow::Error::from)
                                .and_then(|body| {
                                    ensure!(
                                        body.recipient.starts_with("0x")
                                            && body.nonce.starts_with("0x"),
                                        "canonical hex required"
                                    );
                                    let intent = deposits.issue(
                                        attestation::decode::<20>(&body.recipient)?,
                                        zz_core::Id(attestation::decode::<32>(&body.nonce)?),
                                    )?;
                                    deposits.get(intent.id)
                                })
                        } else {
                            let id = request
                                .target
                                .strip_prefix("/v1/deposit-intents/")
                                .unwrap_or("");
                            (|| {
                                ensure!(id.starts_with("0x"), "canonical hex required");
                                deposits.get(zz_core::Id(attestation::decode::<32>(id)?))
                            })()
                        };
                        match result {
                            Ok(value) => ("200 OK", value),
                            Err(_) => (
                                "400 Bad Request",
                                json!({"error":"invalid_or_unavailable_intent"}),
                            ),
                        }
                    }
                    Err(_) => ("503 Service Unavailable", json!({"error":"bridge_busy"})),
                }
            } else {
                (
                    "503 Service Unavailable",
                    json!({"error":"bridge_unavailable"}),
                )
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
            config.validate()?;
            let database = database::connect_client(&config.database)?;
            let (identity, cipher, initialized_now) = recover(&config)?;
            let vault = zz_core::Id(attestation::decode::<32>(&identity.public()?.vault_id)?);
            let store = database::open(database, cipher, vault, initialized_now)?;
            let mut deposits = Deposits::open(store, &identity, &config.domain)?;
            let minting_enabled = config.minting.is_some();
            let withdrawals_enabled = config.withdrawals.is_some();
            if let Some(minting) = &config.minting {
                ensure!(
                    !initialized_now
                        && attestation::decode::<32>(&identity.public()?.vault_id)?
                            == minting.expected_vault_id.0,
                    "minting requires the expected recovered vault"
                );
                deposits.acquire_mint_lease()?;
            }
            let identity = Arc::new(identity);
            let deposits = Arc::new(Mutex::new(deposits));
            let health = Arc::new(AtomicU8::new(0));
            start_sync(
                deposits.clone(),
                config.monero,
                health.clone(),
                identity.clone(),
                config.domain.clone(),
                config.minting,
                config.withdrawals,
            );
            serve(
                identity,
                config.domain,
                8443,
                false,
                Some(deposits),
                health,
                minting_enabled,
                withdrawals_enabled,
            )
        }
        Some("serve-dev") => {
            let port = args.get(2).map(|s| s.parse()).transpose()?.unwrap_or(8443);
            serve(
                Arc::new(Identity::generate()?),
                BindingDomain {
                    chain_id: 31337,
                    registry: "11".repeat(20),
                    bridge: "22".repeat(20),
                    policy_version: 1,
                },
                port,
                true,
                None,
                Arc::new(AtomicU8::new(3)),
                false,
                false,
            )
        }
        _ => bail!("usage: zz-watcher serve CONFIG.json | serve-dev [PORT]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minting_requires_explicit_policy_restored_identity_and_deployment_pins() {
        let mut value: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../enclave/config/runtime.example.json"
        ))
        .unwrap();
        assert!(serde_json::from_value::<Config>(value.clone())
            .unwrap()
            .validate()
            .is_ok());
        value["minting"] = json!({
            "assumption":"trusted-stagenet-single-operator-no-rollback",
            "expected_vault_id":format!("0x{}", "01".repeat(32)),
            "bridge_code_hash":format!("0x{}", "02".repeat(32)),
            "registry_code_hash":format!("0x{}", "03".repeat(32)),
            "adapter":format!("0x{}", "04".repeat(20)),
            "adapter_code_hash":format!("0x{}", "05".repeat(32)),
            "confirmations":10,"demo_mint_confirmations":3,"demo_evm_mint_confirmations":2,
            "gas_limit":3_000_000,"max_fee_per_gas":5_000_000_000u64,
            "max_priority_fee_per_gas":1_000_000_000u64
        });
        assert!(serde_json::from_value::<Config>(value.clone())
            .unwrap()
            .validate()
            .is_ok());
        let mut invalid_retry = value.clone();
        invalid_retry["minting"]["retry_expired_mint"] = json!({
            "deposit_id":format!("0x{}", "00".repeat(32)),"expired_deadline":1
        });
        assert!(serde_json::from_value::<Config>(invalid_retry)
            .unwrap()
            .validate()
            .is_err());
        for (path, replacement) in [
            ("/initialize", json!(true)),
            ("/domain/chain_id", json!(1)),
            ("/minting/assumption", json!("")),
            (
                "/minting/expected_vault_id",
                json!(format!("0x{}", "00".repeat(32))),
            ),
            (
                "/minting/adapter_code_hash",
                json!(format!("0x{}", "00".repeat(32))),
            ),
            ("/minting/demo_mint_confirmations", json!(2)),
            ("/minting/demo_evm_mint_confirmations", json!(1)),
        ] {
            let mut invalid = value.clone();
            *invalid.pointer_mut(path).unwrap() = replacement;
            assert!(
                serde_json::from_value::<Config>(invalid)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{path}"
            );
        }
        value["withdrawals"] = json!({
            "assumption":"trusted-stagenet-single-operator-no-rollback",
            "fee_terms_hash":format!("0x{}", "06".repeat(32)),
            "fixed_fee_atomic":100,"network_fee_cap_atomic":90,
            "max_fee_per_weight":1000,"confirmations":10,"evm_deployment_block":1
        });
        assert!(serde_json::from_value::<Config>(value.clone())
            .unwrap()
            .validate()
            .is_ok());
        for (path, replacement) in [
            ("/withdrawals/assumption", json!("")),
            ("/withdrawals/fixed_fee_atomic", json!(0)),
            ("/withdrawals/network_fee_cap_atomic", json!(101)),
            ("/withdrawals/confirmations", json!(3)),
            ("/withdrawals/evm_deployment_block", json!(0)),
            ("/minting", serde_json::Value::Null),
            ("/initialize", json!(true)),
        ] {
            let mut invalid = value.clone();
            *invalid.pointer_mut(path).unwrap() = replacement;
            assert!(
                serde_json::from_value::<Config>(invalid)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{path}"
            );
        }
    }

    #[test]
    fn only_typed_chain_errors_are_retried() {
        assert!(retryable_sync(&anyhow::Error::new(
            zz_watcher::deposits::ChainUnavailable
        )));
        assert!(!retryable_sync(&anyhow::anyhow!("chain unavailable")));
        assert!(!retryable_sync(&anyhow::anyhow!("scan anchor reorganized")));
        assert!(!retryable_sync(&anyhow::anyhow!(
            "quarantine persistence failed"
        )));
    }
}
