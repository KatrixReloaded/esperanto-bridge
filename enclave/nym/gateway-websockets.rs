#[cfg(not(target_arch = "wasm32"))]
use crate::client::GatewayListeners;
use crate::error::GatewayClientError;
#[cfg(unix)]
use std::{
    os::fd::{AsRawFd, RawFd},
    sync::Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};
use tungstenite::handshake::client::Response;
use url::Url;

async fn connect(
    endpoint: &str,
    #[cfg(unix)] callback: Option<Arc<dyn Fn(RawFd) + Send + Sync>>,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), GatewayClientError> {
    let url =
        Url::parse(endpoint).map_err(|_| GatewayClientError::InvalidUrl(endpoint.to_owned()))?;
    if url.scheme() != "wss" || url.host_str().is_none() {
        return Err(GatewayClientError::InvalidUrl(endpoint.to_owned()));
    }
    let authority = format!(
        "{}:{}",
        url.host_str().unwrap(),
        url.port_or_known_default().unwrap_or(443)
    );
    let result = async {
        let mut stream = TcpStream::connect("127.0.0.1:8888").await?;
        #[cfg(unix)]
        if let Some(callback) = callback {
            callback(stream.as_raw_fd());
        }
        stream
            .write_all(
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
            )
            .await?;
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") && header.len() < 8192 {
            header.push(stream.read_u8().await?);
        }
        if !header.starts_with(b"HTTP/1.1 200 ") || !header.ends_with(b"\r\n\r\n") {
            return Err(std::io::Error::other("gateway CONNECT refused"));
        }
        Ok::<_, std::io::Error>(stream)
    }
    .await
    .map_err(|e| GatewayClientError::NetworkConnectionFailed {
        address: endpoint.to_owned(),
        source: Box::new(tungstenite::Error::from(e)),
    })?;
    let connector = Connector::Rustls(nym_http_api_client::tls::rustls_client_config());
    tokio_tungstenite::client_async_tls_with_config(endpoint, result, None, Some(connector))
        .await
        .map_err(|e| GatewayClientError::NetworkConnectionFailed {
            address: endpoint.to_owned(),
            source: Box::new(e),
        })
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn connect_async_with_fallback(
    endpoints: &GatewayListeners,
    _use_hickory_dns_resolver: bool,
    #[cfg(unix)] callback: Option<Arc<dyn Fn(RawFd) + Send + Sync>>,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), GatewayClientError> {
    match connect(
        endpoints.primary.as_ref(),
        #[cfg(unix)]
        callback.clone(),
    )
    .await
    {
        Ok(result) => Ok(result),
        Err(error) => match &endpoints.fallback {
            Some(fallback) => {
                connect(
                    fallback.as_ref(),
                    #[cfg(unix)]
                    callback,
                )
                .await
            }
            None => Err(error),
        },
    }
}
