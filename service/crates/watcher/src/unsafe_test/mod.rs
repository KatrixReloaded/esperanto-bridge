//! Explicit host-trusted development mode. This module is absent without `unsafe-test`.
//! It does not emulate NSM: verifier journals are deliberately forged and labelled as such.
mod evidence;
#[path = "../http.rs"]
mod http;
mod pins;
use crate::{
    attestation::{BindingDomain, Identity},
    deposits::Deposits,
    redemptions::{NextAction, PayoutConfig, Redemptions},
};
use alloy::sol_types::SolCall;
use anyhow::{ensure, Context, Result};
pub use pins::Pins;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};
use zz_core::{
    payouts::StagenetPocPolicy,
    storage::{Cipher, DataKeySource, PostgresStore},
    AtomicAmount, Domain, Id,
};
use zz_monero::stagenet::TrustedStagenet;
use zz_zama::{
    evm::{self, Finality},
    fhe,
    transaction::Fees,
};
const MODE: &str = "UNSAFE_TEST_NO_NITRO";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub mode: String,
    pub chain_id: u64,
    pub pins: Pins,
    pub bundle: String,
    pub database_url: String,
    pub monero_rpc_url: String,
    pub monero_birth_height: u64,
    pub evm_deployment_block: u64,
    pub api_port: u16,
    pub confirmations: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
    pub fee_terms_hash: alloy::primitives::B256,
    pub fixed_fee_atomic: u64,
    pub network_fee_cap_atomic: u64,
    pub max_fee_per_weight: u64,
}
impl Config {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.mode == MODE
                && self.chain_id == 11155111
                && self.api_port > 0
                && self.confirmations >= 10
                && self.gas_limit > 0
                && self.gas_limit <= 10_000_000
                && self.max_fee_per_gas > 0
                && self.max_priority_fee_per_gas <= self.max_fee_per_gas
                && self.fixed_fee_atomic > 0
                && self.network_fee_cap_atomic > 0
                && self.network_fee_cap_atomic <= self.fixed_fee_atomic
                && self.max_fee_per_weight > 0
                && !self.fee_terms_hash.is_zero(),
            "invalid unsafe stagenet configuration"
        );
        let db: postgres::Config = self.database_url.parse()?;
        ensure!(
            db.get_hosts().len() == 1
                && matches!(&db.get_hosts()[0],postgres::config::Host::Tcp(host) if host=="127.0.0.1"),
            "development database must be loopback"
        );
        ensure!(
            db.get_hostaddrs().is_empty() || db.get_hostaddrs().iter().all(|a| a.is_loopback()),
            "database host override forbidden"
        );
        Ok(())
    }
    fn binding(&self) -> BindingDomain {
        BindingDomain {
            chain_id: 11155111,
            registry: format!("{}", self.pins.registry),
            bridge: format!("{}", self.pins.bridge),
            policy_version: 1,
        }
    }
    fn fees(&self) -> Fees {
        Fees {
            gas_limit: self.gas_limit,
            max_fee_per_gas: self.max_fee_per_gas.into(),
            max_priority_fee_per_gas: self.max_priority_fee_per_gas.into(),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    mode: String,
    identity: Identity,
    data_key: [u8; 32],
}
impl Drop for Bundle {
    fn drop(&mut self) {
        self.data_key.zeroize();
    }
}
impl DataKeySource for Bundle {
    fn data_key(&self) -> std::result::Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.data_key)
    }
}
fn load_bundle(path: &Path) -> Result<Bundle> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && meta.permissions().mode() & 0o077 == 0 && meta.len() <= 65536,
        "private development bundle required"
    );
    let bytes = Zeroizing::new(std::fs::read(path)?);
    let bundle: Bundle = serde_json::from_slice(&bytes)?;
    ensure!(
        bundle.mode == MODE && bundle.data_key != [0; 32],
        "development bundle marker missing"
    );
    bundle.identity.validate_wallet()?;
    Ok(bundle)
}
fn initialize(path: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut key = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut *key);
    let bundle = Bundle {
        mode: MODE.into(),
        identity: Identity::generate()?,
        data_key: *key,
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&Zeroizing::new(serde_json::to_vec(&bundle)?))?;
    file.sync_all()?;
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    println!(
        "{}",
        json!({"mode":MODE,"identity":bundle.identity.public()?})
    );
    Ok(())
}
fn domain(config: &Config, bundle: &Bundle) -> Result<Domain> {
    Ok(Domain {
        chain_id: 11155111,
        bridge: config.pins.bridge.into_array(),
        vault: Id(crate::attestation::decode(
            &bundle.identity.public()?.vault_id,
        )?),
    })
}
fn store(config: &Config, bundle: &Bundle) -> Result<PostgresStore> {
    config.validate()?;
    let mut pg: postgres::Config = config.database_url.parse()?;
    pg.connect_timeout(Duration::from_secs(10));
    Ok(PostgresStore::new(
        pg.connect(postgres::NoTls)?,
        Cipher::new(bundle).map_err(|_| anyhow::anyhow!("development cipher unavailable"))?,
    ))
}
fn read_config(path: &Path) -> Result<Config> {
    ensure!(
        std::fs::metadata(path)?.len() <= 32768,
        "configuration too large"
    );
    let config: Config = serde_json::from_slice(&std::fs::read(path)?)?;
    config.validate()?;
    Ok(config)
}
pub fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() >= 3,
        "usage: zz-dev init BUNDLE | init-db CONFIG | check CONFIG | run CONFIG --send-stagenet"
    );
    if args[1] == "init" {
        ensure!(args.len() == 3, "unexpected arguments");
        return initialize(Path::new(&args[2]));
    }
    eprintln!("UNSAFE TEST startup: configuration");
    let config = read_config(Path::new(&args[2]))?;
    eprintln!("UNSAFE TEST startup: local_identity_bundle");
    let bundle = load_bundle(Path::new(&config.bundle))?;
    match args[1].as_str() {
        "init-db" => {
            ensure!(args.len() == 3, "unexpected arguments");
            let mut s = store(&config, &bundle)?;
            s.migrate()
                .map_err(|_| anyhow::anyhow!("migration failed"))?;
            s.initialize(domain(&config, &bundle)?.vault).map_err(|_| {
                anyhow::anyhow!("initialization failed; existing state never overwritten")
            })?;
            Ok(())
        }
        "check" => {
            ensure!(args.len() == 3, "unexpected arguments");
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(pins::verify(
                &evm::Client::new("http://127.0.0.1:8788")?,
                &config,
            ))?;
            println!("UNSAFE TEST pins verified; no transaction submitted");
            Ok(())
        }
        "run" => {
            ensure!(
                args.len() == 4 && args[3] == "--send-stagenet",
                "run requires explicit --send-stagenet; this can spend testnet funds"
            );
            run(config, bundle)
        }
        _ => anyhow::bail!("unknown development command"),
    }
}
fn run(config: Config, bundle: Bundle) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let evm = evm::Client::new("http://127.0.0.1:8788")?;
    eprintln!("UNSAFE TEST startup: trusted_stagenet_connection");
    let chain = rt
        .block_on(TrustedStagenet::connect(&config.monero_rpc_url))
        .map_err(|_| anyhow::anyhow!("verified stagenet unavailable"))?;
    let binding = config.binding();
    let d = domain(&config, &bundle)?;
    eprintln!("UNSAFE TEST startup: encrypted_deposit_store");
    let deposits = Arc::new(Mutex::new(Deposits::open(
        store(&config, &bundle)?,
        &bundle.identity,
        &binding,
    )?));
    alloy::sol! {function getCurrentKmsContextId() view returns(uint256);}
    eprintln!("UNSAFE TEST startup: deployment_pin_verification");
    let head = rt.block_on(pins::verify(&evm, &config))?;
    eprintln!("UNSAFE TEST startup: host_kms_context");
    let context = rt
        .block_on(evm.call(
            zz_zama::SEPOLIA_KMS_VERIFIER,
            getCurrentKmsContextIdCall {}.abi_encode().into(),
            head.hash,
        ))?
        .result;
    let context = getCurrentKmsContextIdCall::abi_decode_returns_validate(&context)?;
    eprintln!("UNSAFE TEST startup: cooperative_payout_lease");
    let mut redemptions = Redemptions::open(
        store(&config, &bundle)?,
        StagenetPocPolicy::accept_single_operator_single_process_no_rollback(d)?,
        PayoutConfig {
            fee_terms_hash: Id(config.fee_terms_hash.0),
            fixed_fee: AtomicAmount(config.fixed_fee_atomic),
            network_fee_cap: AtomicAmount(config.network_fee_cap_atomic),
            max_fee_per_weight: config.max_fee_per_weight,
            monero_confirmations: config.confirmations,
            kms_context: context,
        },
        &bundle.identity,
        &chain,
    )?;
    let port = config.api_port;
    let health = Arc::new(AtomicU8::new(0));
    let worker_health = health.clone();
    let worker_deposits = deposits.clone();
    std::thread::spawn(move || {
        struct Stopped(Arc<AtomicU8>);
        impl Drop for Stopped {
            fn drop(&mut self) {
                self.0.store(3, Ordering::Relaxed);
            }
        }
        let _stopped = Stopped(worker_health.clone());
        let result = (|| -> Result<()> {
            let fhe = fhe::Client::new("http://127.0.0.1:8788")?;
            let mut cursor = config.evm_deployment_block;
            let mut payment_cursor = None;
            let mut scan_failures = 0u8;
            loop {
                redemptions.check_runner_lease()?;
                let mut deposits = worker_deposits
                    .lock()
                    .map_err(|_| anyhow::anyhow!("worker lock poisoned"))?;
                match rt.block_on(deposits.sync_once(&chain, config.monero_birth_height)) {
                    Ok(advanced) => {
                        scan_failures = 0;
                        if advanced {
                            drop(deposits);
                            continue;
                        }
                    }
                    Err(error) => {
                        worker_health.store(0, Ordering::Relaxed);
                        // Only this read-only scan is retryable. Release the API mutex during
                        // backoff, retain the same lease, then recheck it at the loop entrance.
                        drop(deposits);
                        if let Some(delay) = scan_retry_delay(&error, &mut scan_failures) {
                            eprintln!("UNSAFE TEST scan: read retry; issuance unavailable");
                            std::thread::sleep(delay);
                            continue;
                        }
                        eprintln!("UNSAFE TEST scan: failed; retries exhausted or disallowed");
                        return Err(error);
                    }
                }
                worker_health.store(1, Ordering::Relaxed);
                rt.block_on(step(
                    &config,
                    &bundle.identity,
                    &chain,
                    &evm,
                    &fhe,
                    &mut deposits,
                    &mut redemptions,
                    &mut cursor,
                    &mut payment_cursor,
                ))?;
                drop(deposits);
                std::thread::sleep(Duration::from_secs(5));
            }
        })();
        if result.is_err() {
            worker_health.store(3, Ordering::Relaxed);
            eprintln!("UNSAFE TEST worker stopped; reconcile existing journals before restarting");
        }
    });
    eprintln!("UNSAFE TEST startup: loopback_api_and_worker");
    serve(port, deposits, health)
}
/// At most three consecutive failed scan attempts. This must never wrap financial actions or reconciliation.
fn scan_retry_delay(error: &anyhow::Error, failures: &mut u8) -> Option<Duration> {
    error.downcast_ref::<crate::deposits::ChainUnavailable>()?;
    *failures = failures.saturating_add(1);
    if *failures >= 3 {
        None
    } else {
        Some(Duration::from_secs(u64::from(*failures) * 5))
    }
}

async fn finalized(evm: &evm::Client, hash: Id) -> Result<bool> {
    let receipt = evm.receipt(hash.0.into()).await?;
    if receipt.finality != Finality::Finalized {
        return Ok(false);
    }
    ensure!(
        receipt.receipt.as_ref().is_some_and(|r| r.status == 1),
        "journaled transaction reverted; manual reconciliation required"
    );
    Ok(true)
}
async fn step(
    config: &Config,
    identity: &Identity,
    chain: &TrustedStagenet,
    evm: &evm::Client,
    fhe: &fhe::Client,
    deposits: &mut Deposits,
    redemptions: &mut Redemptions,
    cursor: &mut u64,
    payment_cursor: &mut Option<u64>,
) -> Result<()> {
    let pending = deposits.pending_mints()?;
    let payout = redemptions.pending()?.first().copied();
    // Idle discovery needs no financial authority. Pending work, including reconciliation,
    // must still pass the complete pin check on this tick; never reuse a previous tick's check.
    let head = if pending.is_empty() && payout.is_none() {
        None
    } else {
        Some(pins::verify(evm, config).await?)
    };
    // Reconcile existing mint envelopes before allocating any new signer nonce.
    if let Some((id, _)) = pending.iter().find(|(_, submitted)| *submitted) {
        deposits.reconcile_mint(identity, evm, fhe, *id).await?;
        return Ok(());
    }
    if let Some((id, action)) = payout {
        let head = head.context("pending payout pin verification missing")?;
        match action {
            NextAction::JournalClaim => {
                redemptions
                    .journal_claim(
                        identity,
                        evm,
                        fhe,
                        id,
                        head.timestamp.checked_add(600).context("clock overflow")?,
                        config.fees(),
                    )
                    .await?;
            }
            NextAction::SubmitClaim => {
                let _ = redemptions.submit_claim(evm, id).await?;
            }
            NextAction::WaitForAssignmentThenBroadcast => {
                if finalized(
                    evm,
                    redemptions
                        .development_pending_hash(id)?
                        .context("claim hash missing")?,
                )
                .await?
                {
                    let _ = redemptions.broadcast(chain, evm, id).await?;
                }
            }
            NextAction::FindPayment => {
                let (found, next) = redemptions.find_payment(chain, id, *payment_cursor).await?;
                *payment_cursor = if found.is_some() { None } else { Some(next) };
            }
            NextAction::JournalSettlement => {
                redemptions
                    .journal_settlement(
                        identity,
                        chain,
                        evm,
                        id,
                        head.timestamp.checked_add(600).context("clock overflow")?,
                        config.fees(),
                    )
                    .await?;
            }
            NextAction::SubmitSettlement => {
                let _ = redemptions.submit_settlement(chain, evm, id).await?;
            }
            NextAction::ConfirmSettlement => {
                if finalized(
                    evm,
                    redemptions
                        .development_pending_hash(id)?
                        .context("settlement hash missing")?,
                )
                .await?
                {
                    redemptions.confirm_settlement(evm, id).await?;
                }
            }
            NextAction::Complete => {}
        }
        return Ok(());
    }
    for (id, _) in pending {
        let Some(prepared) = deposits
            .prepare_mint_authorization(
                identity,
                &config.binding(),
                chain,
                fhe,
                evm,
                id,
                config.confirmations,
                600,
            )
            .await?
        else {
            continue;
        };
        // Fresh trusted RPC time after expensive encryption. No NSM document is fabricated.
        let clock = pins::verify(evm, config).await?;
        let calldata = evidence::calldata(identity, &config.binding(), &prepared, clock.timestamp)?;
        redemptions.check_runner_lease()?;
        deposits
            .journal_mint_transaction(
                identity,
                chain,
                evm,
                id,
                config.confirmations,
                calldata.to_vec(),
                config.fees(),
            )
            .await?;
        redemptions.check_runner_lease()?;
        let _ = deposits
            .submit_mint(chain, evm, id, config.confirmations)
            .await?;
        return Ok(());
    }
    let head: evm::BlockObservation = evm
        .read(evm::ReadMethod::BlockByNumber, json!(["finalized", false]))
        .await?
        .result;
    if *cursor > head.number {
        return Ok(());
    }
    let to = head.number.min(cursor.saturating_add(255));
    for id in redemptions.discover(evm, *cursor, to).await? {
        // A discovered log is not authority to decrypt or reserve funds. Verify before prepare,
        // including when this tick skipped the pending-work check above.
        pins::verify(evm, config).await?;
        // prepare is idempotent for completed journal entries. Only an actual positive burn can
        // create an attempt; an unsupported/zero candidate stops for explicit reconciliation.
        redemptions.prepare(identity, chain, evm, fhe, id).await?;
        if !redemptions.pending()?.is_empty() {
            return Ok(());
        }
    }
    *cursor = to.checked_add(1).context("block cursor overflow")?;
    Ok(())
}
fn read_local_request(stream: &mut std::net::TcpStream, port: u16) -> Result<http::Request> {
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        ensure!(header.len() < 8192, "headers too large");
        stream.read_exact(&mut byte)?;
        header.push(byte[0]);
    }
    let text = std::str::from_utf8(&header)?;
    let mut host = None;
    for line in text.split("\r\n").skip(1).filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':').context("invalid header")?;
        ensure!(
            !name.eq_ignore_ascii_case("origin"),
            "browser origin forbidden"
        );
        if name.eq_ignore_ascii_case("host") {
            ensure!(host.replace(value.trim()).is_none(), "duplicate host");
        }
    }
    let expected = format!("127.0.0.1:{port}");
    ensure!(host == Some(expected.as_str()), "loopback Host required");
    Ok(http::read_request(
        &mut std::io::Cursor::new(header).chain(stream),
    )?)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentRequest {
    recipient: String,
    nonce: String,
}
fn serve(port: u16, deposits: Arc<Mutex<Deposits>>, health: Arc<AtomicU8>) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!(
        "UNSAFE TEST runner ready on loopback; attestation is forged, keys are host-controlled"
    );
    for socket in listener.incoming() {
        let mut stream = socket?;
        if !stream.peer_addr()?.ip().is_loopback() {
            continue;
        }
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let request = read_local_request(&mut stream, port);
        let (status, body) = match request {
            Err(_) => ("400 Bad Request", json!({"error":"invalid_local_request"})),
            Ok(r) if r.method == "GET" && r.target == "/health" => (
                "200 OK",
                json!({"runtime":if health.load(Ordering::Relaxed)==1{"ready"}else{"unavailable"},"native_development":true,"unsafe_test_only":true,"mock_attestation":true,"mode":MODE,"network":"stagenet","chain_id":11155111,"bridge_actions_enabled":health.load(Ordering::Relaxed)==1}),
            ),
            Ok(r)
                if (r.method == "POST" && r.target == "/v1/deposit-intents")
                    || (r.method == "GET" && r.target.starts_with("/v1/deposit-intents/")) =>
            {
                if r.method == "POST" && health.load(Ordering::Relaxed) != 1 {
                    (
                        "503 Service Unavailable",
                        json!({"error":"worker_unavailable"}),
                    )
                } else if let Ok(mut deposits) = deposits.try_lock() {
                    let result = (|| -> Result<serde_json::Value> {
                        if r.method == "POST" {
                            let input: IntentRequest = serde_json::from_slice(&r.body)?;
                            ensure!(
                                input.recipient.starts_with("0x") && input.nonce.starts_with("0x"),
                                "canonical hex required"
                            );
                            let intent = deposits.issue(
                                crate::attestation::decode(&input.recipient)?,
                                Id(crate::attestation::decode(&input.nonce)?),
                            )?;
                            deposits.get(intent.id)
                        } else {
                            let id = r
                                .target
                                .strip_prefix("/v1/deposit-intents/")
                                .context("invalid route")?;
                            ensure!(id.starts_with("0x"), "canonical hex required");
                            deposits.get(Id(crate::attestation::decode(id)?))
                        }
                    })();
                    match result {
                        Ok(value) => ("200 OK", value),
                        Err(_) => (
                            "400 Bad Request",
                            json!({"error":"invalid_or_unavailable_intent"}),
                        ),
                    }
                } else {
                    ("503 Service Unavailable", json!({"error":"worker_busy"}))
                }
            }
            _ => ("404 Not Found", json!({"error":"route_not_available"})),
        };
        let body = serde_json::to_vec(&body)?;
        let header=format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",body.len());
        let _ = stream
            .write_all(header.as_bytes())
            .and_then(|_| stream.write_all(&body));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_typed_scan_reads_retry_with_two_bounded_backoffs() {
        let unavailable = anyhow::Error::new(crate::deposits::ChainUnavailable);
        let mut failures = 0;
        assert_eq!(
            scan_retry_delay(&unavailable, &mut failures),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            scan_retry_delay(&unavailable, &mut failures),
            Some(Duration::from_secs(10))
        );
        assert_eq!(scan_retry_delay(&unavailable, &mut failures), None);
        assert_eq!(scan_retry_delay(&unavailable, &mut failures), None);
        for fatal in [
            "trusted chain unavailable",
            "scan anchor reorganized",
            "vault state unavailable",
            "ambiguous broadcast",
        ] {
            let mut failures = 0;
            assert_eq!(
                scan_retry_delay(&anyhow::anyhow!(fatal), &mut failures),
                None
            );
            assert_eq!(failures, 0);
        }
    }
    pub(super) fn config() -> Config {
        serde_json::from_value(json!({"mode":MODE,"chain_id":11155111,"pins":{"bridge":"0x1111111111111111111111111111111111111111","registry":"0x2222222222222222222222222222222222222222","adapter":"0x3333333333333333333333333333333333333333","verifier":"0x4444444444444444444444444444444444444444","bridge_code_hash":format!("0x{}","01".repeat(32)),"registry_code_hash":format!("0x{}","02".repeat(32)),"adapter_code_hash":format!("0x{}","03".repeat(32)),"verifier_code_hash":format!("0x{}","04".repeat(32))},"bundle":"unused","database_url":"postgresql://127.0.0.1:5432/postgres","monero_rpc_url":"https://stagenet.example","monero_birth_height":1,"evm_deployment_block":1,"api_port":8789,"confirmations":10,"gas_limit":1000000,"max_fee_per_gas":1000000000,"max_priority_fee_per_gas":1,"fee_terms_hash":format!("0x{}","05".repeat(32)),"fixed_fee_atomic":1000,"network_fee_cap_atomic":100,"max_fee_per_weight":100})).unwrap()
    }
    #[test]
    fn explicit_mode_mainnet_remote_database_and_fee_limits() {
        let mut c = config();
        assert!(c.validate().is_ok());
        c.mode = "production".into();
        assert!(c.validate().is_err());
        c.mode = MODE.into();
        c.chain_id = 1;
        assert!(c.validate().is_err());
        c.chain_id = 11155111;
        c.database_url = "postgresql://remote.example/postgres".into();
        assert!(c.validate().is_err());
        c.database_url = "host=127.0.0.1 hostaddr=1.2.3.4".into();
        assert!(c.validate().is_err());
    }
    #[test]
    fn host_bundle_is_private_persistent_and_never_overwritten() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "cwxmr-dev-bundle-{}-{}.json",
            std::process::id(),
            rand::random::<u64>()
        ));
        initialize(&path).unwrap();
        let first = load_bundle(&path).unwrap();
        let second = load_bundle(&path).unwrap();
        assert_eq!(
            first.identity.public().unwrap().vault_id,
            second.identity.public().unwrap().vault_id
        );
        assert_eq!(first.data_key, second.data_key);
        assert!(initialize(&path).is_err());
        let cipher = Cipher::new(&first).unwrap();
        let vault = Id([7; 32]);
        let blob = cipher.seal(vault, &zz_core::VaultState::default()).unwrap();
        assert!(Cipher::new(&second).unwrap().open(vault, &blob).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_bundle(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn local_http_rejects_browser_origins_and_rebinding_hosts() {
        for (headers, ok) in [
            ("Host: 127.0.0.1:8789", true),
            ("Host: attacker.example", false),
            (
                "Host: 127.0.0.1:8789\r\nOrigin: https://attacker.example",
                false,
            ),
            ("Host: 127.0.0.1:8789\r\nHost: 127.0.0.1:8789", false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let text = format!("GET /health HTTP/1.1\r\n{headers}\r\n\r\n");
            let t = std::thread::spawn(move || {
                let mut s = std::net::TcpStream::connect(address).unwrap();
                s.write_all(text.as_bytes()).unwrap();
            });
            let (mut s, _) = listener.accept().unwrap();
            assert_eq!(read_local_request(&mut s, 8789).is_ok(), ok);
            t.join().unwrap();
        }
    }
}
