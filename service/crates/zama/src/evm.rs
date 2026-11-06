//! Sepolia transport through enclave-local sidecar + mandatory Nym. These are explicitly
//! trusted RPC observations, not independent consensus proofs. Persist signed bytes/hash
//! before submit_journaled; never replace an ambiguously submitted transaction.
use alloy::{
    consensus::{transaction::SignerRecoverable, Transaction, TxEnvelope},
    eips::eip2718::Decodable2718,
    primitives::{keccak256, Address, Bytes, B256},
    transports::http::reqwest,
};
use anyhow::{anyhow, ensure, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
pub const CHAIN_ID: u64 = 11_155_111;
const MAX_RESPONSE: usize = 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(130);

/// Immutable signed envelope. Restore checks chain, signature, bytes and expected hash.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedTransaction {
    raw_transaction: Bytes,
    expected_hash: B256,
}
impl SignedTransaction {
    pub fn from_signed_bytes(raw: Bytes) -> Result<Self> {
        ensure!(
            !raw.is_empty() && raw.len() <= 128 * 1024,
            "invalid_signed_transaction"
        );
        let tx = TxEnvelope::decode_2718_exact(&raw)
            .map_err(|_| anyhow!("invalid_signed_transaction"))?;
        ensure!(
            matches!(
                tx,
                TxEnvelope::Legacy(_) | TxEnvelope::Eip2930(_) | TxEnvelope::Eip1559(_)
            ) && tx.chain_id() == Some(CHAIN_ID),
            "invalid_signed_transaction"
        );
        tx.recover_signer()
            .map_err(|_| anyhow!("invalid_signed_transaction"))?;
        let expected_hash = keccak256(&raw);
        ensure!(*tx.tx_hash() == expected_hash, "invalid_signed_transaction");
        Ok(Self {
            raw_transaction: raw,
            expected_hash,
        })
    }
    pub fn restore(raw: Bytes, expected_hash: B256) -> Result<Self> {
        let tx = Self::from_signed_bytes(raw)?;
        ensure!(tx.expected_hash == expected_hash, "journal_hash_mismatch");
        Ok(tx)
    }
    pub fn hash(&self) -> B256 {
        self.expected_hash
    }
    pub fn raw(&self) -> &Bytes {
        &self.raw_transaction
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmissionOutcome {
    /// Acknowledged hash only: not inclusion, success or finality.
    Accepted { hash: B256 },
    /// Reconcile this same hash; bytes may already be in the network. Never auto-resend.
    Ambiguous { hash: B256 },
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Trust {
    #[serde(rename = "explicitly_trusted_rpc")]
    ExplicitlyTrustedRpc,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation<T> {
    chain_id: String,
    pub trust: Trust,
    pub result: T,
}
#[derive(Debug, Clone, Copy, Serialize)]
pub enum ReadMethod {
    #[serde(rename = "eth_call")]
    Call,
    #[serde(rename = "eth_getCode")]
    Code,
    #[serde(rename = "eth_getLogs")]
    Logs,
    #[serde(rename = "eth_getBlockByHash")]
    BlockByHash,
    #[serde(rename = "eth_getBlockByNumber")]
    BlockByNumber,
    #[serde(rename = "eth_getTransactionCount")]
    TransactionCount,
    #[serde(rename = "eth_estimateGas")]
    EstimateGas,
    #[serde(rename = "eth_gasPrice")]
    GasPrice,
    #[serde(rename = "eth_maxPriorityFeePerGas")]
    MaxPriorityFeePerGas,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlockObservation {
    pub hash: B256,
    #[serde(with = "quantity")]
    pub number: u64,
    pub parent_hash: B256,
    #[serde(with = "quantity")]
    pub timestamp: u64,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogObservation {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
    pub block_hash: B256,
    #[serde(with = "quantity")]
    pub block_number: u64,
    pub transaction_hash: B256,
    #[serde(with = "quantity")]
    pub transaction_index: u64,
    #[serde(with = "quantity")]
    pub log_index: u64,
    pub removed: bool,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub transaction_hash: B256,
    pub block_hash: B256,
    #[serde(with = "quantity")]
    pub block_number: u64,
    #[serde(with = "quantity")]
    pub transaction_index: u64,
    #[serde(with = "quantity")]
    pub status: u64,
    #[serde(with = "quantity")]
    pub gas_used: u64,
    pub logs: Vec<LogObservation>,
}
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Finality {
    NotFound,
    Included,
    Finalized,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptObservation {
    chain_id: String,
    pub trust: Trust,
    pub receipt: Option<Receipt>,
    pub finality: Finality,
    pub finalized_head: Option<BlockObservation>,
}
impl ReceiptObservation {
    fn validate(&self, expected: B256) -> Result<()> {
        ensure!(self.chain_id == CHAIN_ID.to_string(), "chain_mismatch");
        match (&self.receipt, &self.finalized_head, self.finality) {
            (None, None, Finality::NotFound) => Ok(()),
            (Some(r), Some(head), Finality::Included | Finality::Finalized) => {
                ensure!(
                    r.transaction_hash == expected
                        && r.status <= 1
                        && r.logs.len() <= 1024
                        && !r.block_hash.is_zero()
                        && !head.hash.is_zero(),
                    "receipt_scope_mismatch"
                );
                ensure!(
                    (head.number >= r.block_number) == (self.finality == Finality::Finalized),
                    "inconsistent_finality"
                );
                ensure!(
                    head.number != r.block_number || head.hash == r.block_hash,
                    "inconsistent_finality"
                );
                let mut seen = std::collections::BTreeSet::new();
                for log in &r.logs {
                    ensure!(
                        !log.removed
                            && log.topics.len() <= 4
                            && log.data.len() <= 128 * 1024
                            && log.transaction_hash == expected
                            && log.block_hash == r.block_hash
                            && log.block_number == r.block_number
                            && log.transaction_index == r.transaction_index
                            && seen.insert(log.log_index),
                        "receipt_scope_mismatch"
                    );
                }
                Ok(())
            }
            _ => Err(anyhow!("inconsistent_finality")),
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SendResponse {
    chain_id: String,
    hash: B256,
    outcome: String,
    reason: Option<String>,
}

pub struct Client {
    http: reqwest::Client,
    base: reqwest::Url,
}
impl Client {
    pub fn new(base_url: &str) -> Result<Self> {
        let authority = base_url
            .strip_prefix("http://127.0.0.1:")
            .map(|s| s.strip_suffix('/').unwrap_or(s));
        ensure!(
            authority.is_some_and(|p| !p.is_empty()
                && p.bytes().all(|c| c.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|n| n != 0)),
            "invalid_sidecar_url"
        );
        let base = reqwest::Url::parse(base_url).map_err(|_| anyhow!("invalid_sidecar_url"))?;
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(5))
            .timeout(DEADLINE)
            .build()
            .map_err(|_| anyhow!("sidecar_client_failed"))?;
        Ok(Self { http, base })
    }
    /// Whitelisted reads only. call/code/estimate use EIP-1898 hash pins, log ranges <=256 blocks.
    /// Consumers must additionally check the expected contract ABI and business semantics.
    pub async fn read<T: DeserializeOwned>(
        &self,
        method: ReadMethod,
        params: Value,
    ) -> Result<Observation<T>> {
        ensure!(params.is_array(), "invalid_evm_request");
        let observed: Observation<T> = self
            .post(
                "evm/read",
                &json!({"chainId":CHAIN_ID.to_string(),"method":method,"params":params}),
            )
            .await?;
        ensure!(observed.chain_id == CHAIN_ID.to_string(), "chain_mismatch");
        Ok(observed)
    }
    pub async fn call(
        &self,
        contract: Address,
        data: Bytes,
        block_hash: B256,
    ) -> Result<Observation<Bytes>> {
        self.read(
            ReadMethod::Call,
            json!([{"to":contract,"data":data},{"blockHash":block_hash,"requireCanonical":true}]),
        )
        .await
    }
    /// Caller must durably journal this exact envelope first. No signing, nonce allocation,
    /// fee bumping, resending or transaction replacement happens in this client.
    pub async fn submit_journaled(&self, tx: &SignedTransaction) -> SubmissionOutcome {
        let outcome: Result<SendResponse> = self.post("evm/send", &json!({"chainId":CHAIN_ID.to_string(),"rawTransaction":tx.raw(),"expectedHash":tx.hash()})).await;
        match outcome {
            Ok(r)
                if r.chain_id == CHAIN_ID.to_string()
                    && r.hash == tx.hash()
                    && r.outcome == "accepted"
                    && r.reason.is_none() =>
            {
                SubmissionOutcome::Accepted { hash: tx.hash() }
            }
            _ => SubmissionOutcome::Ambiguous { hash: tx.hash() },
        }
    }
    /// Missing receipt does not prove rejection or authorize a replacement transaction.
    pub async fn receipt(&self, hash: B256) -> Result<ReceiptObservation> {
        let observed: ReceiptObservation = self
            .post(
                "evm/receipt",
                &json!({"chainId":CHAIN_ID.to_string(),"hash":hash}),
            )
            .await?;
        observed.validate(hash)?;
        Ok(observed)
    }
    async fn post<T: DeserializeOwned>(&self, endpoint: &str, request: &Value) -> Result<T> {
        let body = serde_json::to_vec(request).map_err(|_| anyhow!("invalid_evm_request"))?;
        ensure!(body.len() <= 512 * 1024, "invalid_evm_request");
        tokio::time::timeout(DEADLINE, async {
            let mut response = self
                .http
                .post(
                    self.base
                        .join(endpoint)
                        .map_err(|_| anyhow!("invalid_sidecar_url"))?,
                )
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body)
                .send()
                .await
                .map_err(|_| anyhow!("evm_sidecar_transport_failed"))?;
            ensure!(response.status().as_u16() == 200, "evm_sidecar_rejected");
            let mime = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .to_ascii_lowercase();
            ensure!(
                mime == "application/json" || mime == "application/json; charset=utf-8",
                "invalid_evm_response"
            );
            ensure!(
                response
                    .content_length()
                    .is_none_or(|n| n <= MAX_RESPONSE as u64),
                "invalid_evm_response"
            );
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| anyhow!("evm_sidecar_transport_failed"))?
            {
                ensure!(
                    chunk.len() <= MAX_RESPONSE.saturating_sub(bytes.len()),
                    "invalid_evm_response"
                );
                bytes.extend_from_slice(&chunk);
            }
            serde_json::from_slice(&bytes).map_err(|_| anyhow!("invalid_evm_response"))
        })
        .await
        .map_err(|_| anyhow!("evm_sidecar_timeout"))?
    }
}
mod quantity {
    use serde::{Deserialize, Deserializer};
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let s = String::deserialize(deserializer)?;
        let v = s
            .strip_prefix("0x")
            .filter(|v| {
                !v.is_empty()
                    && v.len() <= 16
                    && (v.len() == 1 || !v.starts_with('0'))
                    && v.bytes().all(|c| c.is_ascii_hexdigit())
            })
            .ok_or_else(|| serde::de::Error::custom("invalid_quantity"))?;
        u64::from_str_radix(v, 16).map_err(|_| serde::de::Error::custom("invalid_quantity"))
    }
}
#[cfg(test)]
mod tests;
