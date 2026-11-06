use crate::error::ClientCoreError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};
use tungstenite::handshake::client::Response;
use url::Url;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn connect_async(
    endpoint: &str,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), ClientCoreError> {
    let url = Url::parse(endpoint).map_err(|_| ClientCoreError::InvalidUrl(endpoint.to_owned()))?;
    if url.scheme() != "wss" || url.host_str().is_none() {
        return Err(ClientCoreError::InvalidUrl(endpoint.to_owned()));
    }
    let authority = format!(
        "{}:{}",
        url.host_str().unwrap(),
        url.port_or_known_default().unwrap_or(443)
    );
    let mut stream = TcpStream::connect("127.0.0.1:8888").await?;
    stream
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await?;
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") && header.len() < 8192 {
        header.push(stream.read_u8().await?);
    }
    if !header.starts_with(b"HTTP/1.1 200 ") || !header.ends_with(b"\r\n\r\n") {
        return Err(std::io::Error::other("gateway CONNECT refused").into());
    }
    let connector = Connector::Rustls(nym_http_api_client::tls::rustls_client_config());
    tokio_tungstenite::client_async_tls_with_config(endpoint, stream, None, Some(connector))
        .await
        .map_err(Into::into)
}
