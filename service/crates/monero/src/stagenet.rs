//! Trusted-node stagenet PoC. This is not independent consensus authentication.
use crate::chain::{ChainStatus, ObservedOutput};
use futures_util::StreamExt;
use monero_daemon_rpc::{HttpTransport, MoneroDaemon};
use monero_wallet::{
    interface::{
        InterfaceError, ProvidesBlockchain, ProvidesBlockchainMeta, ProvidesScannableBlocks,
        PublishTransaction,
    },
    transaction::{Timelock, Transaction},
    Scanner,
};
use reqwest::{Client, Proxy, Url};
use std::{collections::HashSet, time::Duration};
use zz_core::{ChainEvidence, Id};

// https://github.com/monero-project/monero/blob/master/src/checkpoints/checkpoints.cpp
const STAGENET_GENESIS: [u8; 32] = [
    0x76, 0xee, 0x3c, 0xc9, 0x86, 0x46, 0x29, 0x22, 0x06, 0xcd, 0x3e, 0x86, 0xf7, 0x4d, 0x88, 0xb4,
    0xdc, 0xc1, 0xd9, 0x37, 0x08, 0x86, 0x45, 0xe9, 0xb0, 0xcb, 0xca, 0x84, 0xb7, 0xce, 0x74, 0xeb,
];
const MAX_RESPONSE: usize = 32 * 1024 * 1024;
const MAX_REQUEST: usize = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(120);

fn unavailable() -> InterfaceError {
    InterfaceError::InterfaceError("stagenet daemon unavailable or invalid".into())
}

fn maturity(
    depth: u64,
    coinbase: bool,
    confirmations: u64,
    tip_height: u64,
    lock: Timelock,
    median_time: Option<u64>,
) -> Result<ChainStatus, InterfaceError> {
    if confirmations == 0 {
        return Err(unavailable());
    }
    let enough = depth.checked_add(1).ok_or_else(unavailable)? >= confirmations
        && depth >= if coinbase { 60 } else { 10 };
    let unlocked = match lock {
        Timelock::None => true,
        Timelock::Block(h) => tip_height >= u64::try_from(h).map_err(|_| unavailable())?,
        Timelock::Time(t) => median_time.ok_or_else(unavailable)? >= t,
    };
    Ok(if enough && unlocked {
        ChainStatus::Mature
    } else {
        ChainStatus::Pending
    })
}

#[derive(Clone)]
struct NymTransport {
    client: Client,
    base: Url,
}
impl NymTransport {
    fn new(node: &str, proxy: &str) -> Result<Self, InterfaceError> {
        let base = Url::parse(node).map_err(|_| unavailable())?;
        if base.scheme() != "https"
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.path() != "/"
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(unavailable());
        }
        let client = Client::builder()
            .no_proxy()
            .proxy(Proxy::all(proxy).map_err(|_| unavailable())?)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(TIMEOUT)
            .timeout(TIMEOUT)
            .build()
            .map_err(|_| unavailable())?;
        Ok(Self { client, base })
    }
}
impl HttpTransport for NymTransport {
    async fn post(
        &self,
        route: &str,
        body: Vec<u8>,
        response_size_limit: Option<usize>,
    ) -> Result<Vec<u8>, InterfaceError> {
        if body.len() > MAX_REQUEST
            || route.is_empty()
            || !route
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
        {
            return Err(unavailable());
        }
        let url = self.base.join(route).map_err(|_| unavailable())?;
        let content_type = if route.ends_with(".bin") {
            "application/octet-stream"
        } else {
            "application/json"
        };
        let response = self
            .client
            .post(url)
            .header("content-type", content_type)
            .body(body)
            .send()
            .await
            .map_err(|_| unavailable())?;
        if !response.status().is_success() {
            return Err(unavailable());
        }
        let limit = response_size_limit
            .unwrap_or(MAX_RESPONSE)
            .min(MAX_RESPONSE);
        if response.content_length().is_some_and(|n| n > limit as u64) {
            return Err(unavailable());
        }
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| unavailable())?;
            if chunk.len() > limit.saturating_sub(bytes.len()) {
                return Err(unavailable());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

/// A single explicitly trusted stagenet daemon reached through the enclave's Nym client.
/// Its answers are not an independent consensus or inclusion proof.
pub struct TrustedStagenet {
    daemon: MoneroDaemon<NymTransport>,
}

pub struct ScannedBlock {
    pub block: ChainEvidence,
    pub parent: Id,
    pub outputs: Vec<ObservedOutput>,
}
async fn checked_daemon<T: HttpTransport>(transport: T) -> Result<MoneroDaemon<T>, InterfaceError> {
    let daemon = MoneroDaemon::new(transport).await?;
    if daemon.block_hash(0).await? != STAGENET_GENESIS {
        return Err(unavailable());
    }
    Ok(daemon)
}
impl TrustedStagenet {
    pub async fn connect(node: &str) -> Result<Self, InterfaceError> {
        let transport = NymTransport::new(node, "socks5h://127.0.0.1:1080")?;
        let daemon = checked_daemon(transport).await?;
        Ok(Self { daemon })
    }
    pub async fn tip(&self) -> Result<ChainEvidence, InterfaceError> {
        let height = self.daemon.latest_block_number().await?;
        let block_hash = Id(self.daemon.block_hash(height).await?);
        Ok(ChainEvidence {
            height: u64::try_from(height).map_err(|_| unavailable())?,
            block_hash,
        })
    }
    pub async fn block_hash(&self, height: u64) -> Result<Id, InterfaceError> {
        Ok(Id(self
            .daemon
            .block_hash(usize::try_from(height).map_err(|_| unavailable())?)
            .await?))
    }
    pub async fn scan_height(
        &self,
        scanner: &mut Scanner,
        height: u64,
    ) -> Result<ScannedBlock, InterfaceError> {
        let number = usize::try_from(height).map_err(|_| unavailable())?;
        let before = self.daemon.block_hash(number).await?;
        let block = self.daemon.scannable_block_by_number(number).await?;
        if block.block.number() != number || block.block.hash() != before {
            return Err(unavailable());
        }
        let parent = Id(block.block.header.previous);
        let miner = block.block.miner_transaction().hash();
        let found = scanner
            .scan(block)
            .map_err(|_| unavailable())?
            .ignore_additional_timelock();
        if self.daemon.block_hash(number).await? != before {
            return Err(unavailable());
        }
        let mut seen = HashSet::new();
        if found
            .iter()
            .any(|o| !seen.insert(o.key().compress().to_bytes()))
        {
            return Err(unavailable());
        }
        let evidence = ChainEvidence {
            height,
            block_hash: Id(before),
        };
        let outputs = found
            .into_iter()
            .map(|output| ObservedOutput {
                coinbase: output.transaction() == miner,
                output,
                block: evidence.clone(),
            })
            .collect();
        Ok(ScannedBlock {
            block: evidence,
            parent,
            outputs,
        })
    }

    /// Evaluate trusted-node canonicality, depth and timelock. This is not mint authorization.
    pub async fn status(
        &self,
        observed: &ObservedOutput,
        confirmations: u64,
    ) -> Result<ChainStatus, InterfaceError> {
        if confirmations == 0 {
            return Err(unavailable());
        }
        let tip = self.tip().await?;
        if self.block_hash(observed.block.height).await? != observed.block.block_hash {
            return Ok(ChainStatus::Reorganized);
        }
        let depth = tip
            .height
            .checked_sub(observed.block.height)
            .ok_or_else(unavailable)?;
        let lock = observed.output.additional_timelock();
        let median_time = match lock {
            Timelock::Time(_) => {
                let end = usize::try_from(tip.height).map_err(|_| unavailable())?;
                let mut times: Vec<_> = self
                    .daemon
                    .contiguous_blocks(end.saturating_sub(59)..=end)
                    .await?
                    .into_iter()
                    .map(|b| b.header.timestamp)
                    .collect();
                if times.is_empty() {
                    return Err(unavailable());
                }
                times.sort_unstable();
                Some(times[times.len() / 2])
            }
            _ => None,
        };
        if self.block_hash(observed.block.height).await? != observed.block.block_hash
            || self.block_hash(tip.height).await? != tip.block_hash
        {
            return Err(unavailable());
        }
        maturity(
            depth,
            observed.coinbase,
            confirmations,
            tip.height,
            lock,
            median_time,
        )
    }

    /// Check inclusion in a specified trusted-node canonical block, with a reorg consistency check.
    pub async fn includes_transaction(
        &self,
        height: u64,
        transaction_id: Id,
    ) -> Result<bool, InterfaceError> {
        let number = usize::try_from(height).map_err(|_| unavailable())?;
        let before = self.daemon.block_hash(number).await?;
        let block = self.daemon.block_by_number(number).await?;
        if block.hash() != before {
            return Err(unavailable());
        }
        let found = block.miner_transaction().hash() == transaction_id.0
            || block.transactions.contains(&transaction_id.0);
        if self.daemon.block_hash(number).await? != before {
            return Err(unavailable());
        }
        Ok(found)
    }

    /// Broadcast only previously journaled bytes. The caller must independently enforce the
    /// assignment and rollback-resistant payout fence on every attempt.
    pub async fn broadcast_journaled(
        &self,
        payout: &zz_core::PreparedPayout,
    ) -> Result<(), String> {
        let bytes = crate::journaled_bytes(payout).map_err(str::to_owned)?;
        let tx = Transaction::read(&mut std::io::Cursor::new(bytes))
            .map_err(|_| "invalid transaction".to_owned())?;
        self.daemon
            .publish_transaction(&tx)
            .await
            .map_err(|_| "broadcast failed or outcome unknown".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn trusted_maturity_enforces_depth_and_additional_locks() {
        assert_eq!(
            maturity(9, false, 1, 50, Timelock::None, None).unwrap(),
            ChainStatus::Pending
        );
        assert_eq!(
            maturity(10, false, 1, 50, Timelock::None, None).unwrap(),
            ChainStatus::Mature
        );
        assert_eq!(
            maturity(59, true, 1, 100, Timelock::None, None).unwrap(),
            ChainStatus::Pending
        );
        assert_eq!(
            maturity(60, true, 1, 100, Timelock::None, None).unwrap(),
            ChainStatus::Mature
        );
        assert_eq!(
            maturity(10, false, 12, 50, Timelock::None, None).unwrap(),
            ChainStatus::Pending
        );
        assert_eq!(
            maturity(10, false, 1, 50, Timelock::Block(51), None).unwrap(),
            ChainStatus::Pending
        );
        assert_eq!(
            maturity(
                10,
                false,
                1,
                50,
                Timelock::Time(2_000_000_000),
                Some(1_999_999_999)
            )
            .unwrap(),
            ChainStatus::Pending
        );
        assert_eq!(
            maturity(
                10,
                false,
                1,
                50,
                Timelock::Time(2_000_000_000),
                Some(2_000_000_000)
            )
            .unwrap(),
            ChainStatus::Mature
        );
        assert!(maturity(10, false, 0, 50, Timelock::None, None).is_err());
        assert!(maturity(10, false, 1, 50, Timelock::Time(2_000_000_000), None).is_err());
    }

    #[derive(Clone)]
    struct FakeDaemon {
        genesis: &'static str,
    }
    impl HttpTransport for FakeDaemon {
        async fn post(
            &self,
            route: &str,
            body: Vec<u8>,
            _: Option<usize>,
        ) -> Result<Vec<u8>, InterfaceError> {
            assert_eq!(route, "json_rpc");
            if body.first() == Some(&b'[') {
                return Ok(b"[]".to_vec());
            }
            assert!(String::from_utf8(body)
                .unwrap()
                .contains("on_get_block_hash"));
            Ok(format!(r#"{{"jsonrpc":"2.0","id":0,"result":"{}"}}"#, self.genesis).into_bytes())
        }
    }
    #[tokio::test]
    async fn requires_stagenet_genesis_using_upstream_rpc_decoder() {
        let good = FakeDaemon {
            genesis: "76ee3cc98646292206cd3e86f74d88b4dcc1d937088645e9b0cbca84b7ce74eb",
        };
        assert!(checked_daemon(good).await.is_ok());
        let bad = FakeDaemon {
            genesis: "418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3",
        };
        assert!(checked_daemon(bad).await.is_err());
    }
    #[test]
    fn rejects_unsafe_node_urls() {
        for node in [
            "http://daemon.example",
            "https://user:pass@daemon.example",
            "https://daemon.example/path",
            "https://daemon.example/?token=x",
        ] {
            assert!(NymTransport::new(node, "socks5h://127.0.0.1:1080").is_err());
        }
    }
    #[tokio::test]
    async fn socks_receives_hostname_and_failure_never_falls_back() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut hello = [0u8; 3];
            socket.read_exact(&mut hello).await.unwrap();
            assert_eq!(hello, [5, 1, 0]);
            socket.write_all(&[5, 0]).await.unwrap();
            let mut header = [0u8; 5];
            socket.read_exact(&mut header).await.unwrap();
            assert_eq!(header[3], 3);
            let mut host = vec![0; usize::from(header[4])];
            socket.read_exact(&mut host).await.unwrap();
            let mut port_bytes = [0u8; 2];
            socket.read_exact(&mut port_bytes).await.unwrap();
            assert_eq!(host, b"daemon.example.invalid");
            socket
                .write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let transport = NymTransport::new(
            "https://daemon.example.invalid",
            &format!("socks5h://127.0.0.1:{port}"),
        )
        .unwrap();
        assert!(transport
            .post("json_rpc", b"{}".to_vec(), Some(100))
            .await
            .is_err());
        server.await.unwrap();
    }
}
