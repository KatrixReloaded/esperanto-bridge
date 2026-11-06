//! Public proof material crosses the parent boundary. Its response remains untrusted until
//! the mint journal validates the complete call against the authorization and on-chain verifier.
use alloy::primitives::Address;
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::time::Duration;

const MAX_BODY: usize = 512 * 1024;
const MAX_CALLDATA: usize = 128 * 1024;

pub struct Prover(reqwest::Client);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    schema: String,
    verification: String,
    transaction: Transaction,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Transaction {
    to: Address,
    data: String,
    value: String,
}

impl Prover {
    pub fn new() -> Result<Self> {
        Ok(Self(
            reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(560))
                .build()?,
        ))
    }

    pub async fn candidate(
        &self,
        bridge: Address,
        request: serde_json::Value,
        document: &[u8],
    ) -> Result<Vec<u8>> {
        ensure!(
            !document.is_empty() && document.len() <= 65536,
            "invalid NSM document size"
        );
        let body = serde_json::to_vec(&serde_json::json!({
            "request":request,"document":STANDARD.encode(document)
        }))?;
        ensure!(body.len() <= MAX_BODY, "proof request too large");
        // This fixed loopback port is the enclave-side vsock relay, not an arbitrary host URL.
        let mut response = self
            .0
            .post("http://127.0.0.1:8447/prove")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await?;
        ensure!(
            response.status() == reqwest::StatusCode::OK,
            "proof service unavailable"
        );
        ensure!(
            response
                .content_length()
                .is_none_or(|n| n <= MAX_BODY as u64),
            "proof response too large"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= MAX_BODY,
                "proof response too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        decode_candidate(&bytes, bridge)
    }
}

fn decode_candidate(bytes: &[u8], bridge: Address) -> Result<Vec<u8>> {
    ensure!(bytes.len() <= MAX_BODY, "proof response too large");
    let candidate: Candidate = serde_json::from_slice(bytes)?;
    ensure!(
        candidate.schema == "cwxmr-mint-proof-candidate-v1"
            && candidate.verification == "candidate_unverified"
            && candidate.transaction.to == bridge
            && candidate.transaction.value == "0",
        "invalid proof candidate envelope"
    );
    let data = candidate
        .transaction
        .data
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("invalid proof calldata encoding"))?;
    ensure!(
        data.len() >= 8 && data.len() <= MAX_CALLDATA * 2,
        "invalid proof calldata size"
    );
    Ok(hex::decode(data)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parent_cannot_change_destination_value_or_assert_verification() {
        let bridge = Address::from([1; 20]);
        let valid = serde_json::json!({"schema":"cwxmr-mint-proof-candidate-v1",
            "verification":"candidate_unverified","transaction":{"to":bridge,"data":"0x12345678","value":"0"}});
        let decode =
            |v: &serde_json::Value| decode_candidate(&serde_json::to_vec(v).unwrap(), bridge);
        assert_eq!(decode(&valid).unwrap(), [0x12, 0x34, 0x56, 0x78]);
        for (field, value) in [
            ("to", serde_json::json!(Address::from([2; 20]))),
            ("value", serde_json::json!("1")),
            ("data", serde_json::json!("0xzzzzzzzz")),
        ] {
            let mut changed = valid.clone();
            changed["transaction"][field] = value;
            assert!(decode(&changed).is_err());
        }
        let mut changed = valid.clone();
        changed["verification"] = serde_json::json!("verified");
        assert!(decode(&changed).is_err());
        changed = valid;
        changed["private_key"] = serde_json::json!("not accepted");
        assert!(decode(&changed).is_err());
    }
}
