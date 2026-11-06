// Host-only single-request network prover. Never signs an Ethereum transaction.
// Built against the pinned Automata guest and the accompanying capped SDK patch.
use alloy_sol_types::SolValue;
use anyhow::{ensure, Context, Result};
use aws_nitro_enclave_attestation_verifier::stub::{VerifierInput, VerifierJournal};
use serde_json::{json, Value};
use sp1_sdk::{
    network::NetworkMode, HashableKey, ProveRequest, Prover, ProvingKey, SP1ProofMode, SP1Stdin,
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const PROGRAM: &str = "0x00643c7149cf335e7ec9d3f3301e69658a7f0ef2bc7546509c257ed8809f28e1";
const GAS_LIMIT: u64 = 80_000_000;
const CYCLE_LIMIT: u64 = 100_000_000;
const PRICE_CAP: u64 = 2_400_000_000;

fn save_new(path: &Path, value: &Value) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(serde_json::to_string_pretty(value)?.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 5,
        "usage: cwxmr_network_proof inspect|prepare|submit|resume REPORT OUTPUT_DIR WALLET_JSON"
    );
    let mode = &args[1];
    ensure!(
        ["inspect", "prepare", "submit", "resume"].contains(&mode.as_str()),
        "invalid mode"
    );
    let out = Path::new(&args[3]);
    fs::create_dir_all(out)?;
    if mode == "submit" {
        ensure!(
            !out.join("started.json").exists(),
            "a submission was already attempted; reconcile or resume it"
        );
    }
    let report = fs::read(&args[2])?;
    let input = VerifierInput {
        trustedCertsPrefixLen: 1,
        attestationReport: report.clone().into(),
    };
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(input.abi_encode());
    let (expected_values, execution) = {
        use sp1_sdk::blocking::{LightProver, Prover};
        let local = LightProver::new();
        let pk = local.setup(sp1_methods::SP1_VERIFIER_ELF)?;
        ensure!(
            pk.verifying_key().bytes32() == PROGRAM,
            "unexpected local guest program"
        );
        local
            .execute(sp1_methods::SP1_VERIFIER_ELF, stdin.clone())
            .run()?
    };
    let journal = VerifierJournal::abi_decode(expected_values.as_slice())?;
    ensure!(
        format!("{:?}", journal.result) == "Success",
        "attestation verification failed"
    );
    ensure!(
        execution.gas().context("missing gas estimate")? <= GAS_LIMIT,
        "gas estimate exceeds cap"
    );
    ensure!(
        execution.total_instruction_count() <= CYCLE_LIMIT,
        "cycle estimate exceeds cap"
    );
    let report_hash = alloy_primitives::keccak256(&report).to_string();
    if mode == "inspect" {
        save_new(
            &out.join("execution.json"),
            &json!({
                "schema":"cwxmr-nsm-execution-v1", "program":PROGRAM, "report_hash":report_hash,
                "output":alloy_primitives::hex::encode_prefixed(expected_values.as_slice()),
                "proof_submitted":false
            }),
        )?;
        println!("Locally executed Nitro verifier; no proof requested");
        return Ok(());
    }
    tokio::runtime::Runtime::new()?.block_on(async {
        let mut requester = String::new();
        let key = if mode == "prepare" {
            "0000000000000000000000000000000000000000000000000000000000000001".to_owned()
        } else {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::symlink_metadata(&args[4])?;
            ensure!(meta.is_file() && meta.permissions().mode() & 0o077 == 0 && meta.len() <= 16384,
                "requester wallet must be a private regular file");
            let wallet: Value = serde_json::from_slice(&fs::read(&args[4])?)?;
            let mut wallet = wallet.get("data").unwrap_or(&wallet);
            wallet = wallet.get("wallets").unwrap_or(wallet);
            if wallet.is_array() { wallet = &wallet[0]; }
            let key = wallet["private_key"].as_str().context("missing requester key")?;
            let signer: alloy_signer_local::PrivateKeySigner = key.parse().context("invalid requester key")?;
            requester = signer.address().to_string();
            ensure!(wallet["address"].as_str().context("missing wallet address")?.eq_ignore_ascii_case(&requester),
                "wallet address mismatch");
            key.to_owned()
        };
        let client = sp1_sdk::ProverClient::builder().network_for(NetworkMode::Mainnet)
            .private_key(&key).build().await;
        let pk = client.setup(sp1_methods::SP1_VERIFIER_ELF).await?;
        ensure!(pk.verifying_key().bytes32() == PROGRAM, "program differs from deployed adapter");
        let params = client.get_proof_request_params(SP1ProofMode::Groth16).await?;
        let sp1_sdk::network::proto::GetProofRequestParamsResponse::Auction(params) = params
            else { anyhow::bail!("auction pricing unavailable") };
        let ceiling = params.base_fee.parse::<u128>()? + u128::from(GAS_LIMIT) * u128::from(PRICE_CAP);
        ensure!(ceiling <= 1_000_000_000_000_000_000, "quote exceeds 1 PROVE ceiling");
        println!("{}", json!({"mode":mode,"program":PROGRAM,"report_hash":report_hash,
            "cycles":execution.total_instruction_count(),"prover_gas":execution.gas(),
            "current_max_cost_atomic_prove":ceiling.to_string(),"hard_cap_prove":1}));
        if mode == "prepare" { return Ok(()); }
        let started = Instant::now();
        let request_id = if mode == "submit" {
            save_new(&out.join("started.json"), &json!({"requester":requester,"program":PROGRAM,
                "report_hash":report_hash,"unix_time":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                "gas_limit":GAS_LIMIT,"cycle_limit":CYCLE_LIMIT,"price_cap_atomic":PRICE_CAP,
                "hard_cap_atomic_prove":"1000000000000000000","automatic_paid_retries":false}))?;
            let id = client.prove(&pk, stdin).groth16().gas_limit(GAS_LIMIT).cycle_limit(CYCLE_LIMIT)
                .max_price_per_pgu(PRICE_CAP).timeout(Duration::from_secs(540)).request().await?;
            save_new(&out.join("request.json"), &json!({"request_id":id.to_string(),"report_hash":report_hash}))?;
            println!("{}", json!({"request_id":id.to_string(),"submitted":true}));
            id
        } else {
            let saved: Value = serde_json::from_slice(&fs::read(out.join("request.json"))?)?;
            ensure!(saved["report_hash"].as_str() == Some(report_hash.as_str()), "report differs from submitted input");
            saved["request_id"].as_str().context("missing request id")?.parse()?
        };
        // Poll the existing request only; never use the SDK's auto-resubmitting prove().await path.
        let proof = if out.join("proof.bin").exists() {
            sp1_sdk::SP1ProofWithPublicValues::load(out.join("proof.bin"))?
        } else {
            let proof = client.wait_proof(request_id, Some(Duration::from_secs(540)), Some(Duration::from_secs(540))).await?;
            proof.save(out.join("proof.bin"))?;
            proof
        };
        client.verify(&proof, pk.verifying_key(), None)?;
        ensure!(proof.public_values.as_slice() == expected_values.as_slice(), "public values differ from local execution");
        let proof_bytes = proof.bytes();
        ensure!(proof_bytes.starts_with(&[0x43,0x88,0xa2,0x1c]), "proof selector differs from deployed adapter");
        save_new(&out.join("verified-proof.json"), &json!({"request_id":request_id.to_string(),
            "schema":"cwxmr-network-proof-v1","program":PROGRAM,"report_hash":report_hash,"locally_verified":true,
            "seconds":started.elapsed().as_secs_f64(),
            "output":alloy_primitives::hex::encode_prefixed(proof.public_values.as_slice()),
            "proof":alloy_primitives::hex::encode_prefixed(proof_bytes)}))?;
        println!("{}", json!({"request_id":request_id.to_string(),"locally_verified":true,
            "seconds":started.elapsed().as_secs_f64()}));
        Ok::<_, anyhow::Error>(())
    })
}
