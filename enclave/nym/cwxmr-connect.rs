//! Gateway WSS over an enclave-local CONNECT proxy. No direct socket fallback.
use std::{future::Future, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};
use tungstenite::handshake::client::Response;
use url::Url;

pub(super) async fn connect<F>(
    endpoint: &str,
    proxy: &str,
    deadline: Duration,
    on_connect: F,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), tungstenite::Error>
where
    F: FnOnce(&TcpStream),
{
    let operation = async {
        let url = Url::parse(endpoint).map_err(|_| std::io::Error::other("invalid gateway URL"))?;
        if url.scheme() != "wss"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(std::io::Error::other("invalid gateway URL").into());
        }
        let authority = format!(
            "{}:{}",
            url.host_str().unwrap(),
            url.port_or_known_default().unwrap_or(443)
        );
        let mut stream = TcpStream::connect(proxy).await?;
        on_connect(&stream);
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
            return Err(std::io::Error::other("gateway CONNECT refused").into());
        }
        let connector = Connector::Rustls(nym_http_api_client::tls::rustls_client_config());
        tokio_tungstenite::client_async_tls_with_config(endpoint, stream, None, Some(connector))
            .await
            .map_err(Into::into)
    };
    bounded(operation, deadline).await
}

async fn bounded<T, F: Future<Output = Result<T, tungstenite::Error>>>(
    operation: F,
    deadline: Duration,
) -> Result<T, tungstenite::Error> {
    tokio::time::timeout(deadline, operation)
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "gateway connection timed out")
        })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    async fn denied(response: Option<&'static [u8]>, pause: Duration) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let n = socket.read(&mut request).await.unwrap();
            assert!(request[..n].starts_with(b"CONNECT gateway.invalid:443 HTTP/1.1\r\n"));
            if let Some(bytes) = response {
                socket.write_all(bytes).await.unwrap();
            }
            tokio::time::sleep(pause).await;
        });
        let result = connect(
            "wss://gateway.invalid/",
            &address.to_string(),
            Duration::from_millis(100),
            |_| {},
        )
        .await;
        assert!(result.is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn refusal_and_partial_header_fail() {
        denied(Some(b"HTTP/1.1 403 Forbidden\r\n\r\n"), Duration::ZERO).await;
        denied(
            Some(b"HTTP/1.1 200 Connection Established\r\n"),
            Duration::from_millis(200),
        )
        .await;
    }
    #[tokio::test]
    async fn timeout_and_invalid_tls_fail() {
        denied(None, Duration::from_millis(200)).await;
        denied(
            Some(b"HTTP/1.1 200 Connection Established\r\n\r\nnot TLS"),
            Duration::ZERO,
        )
        .await;
    }
    #[tokio::test]
    async fn refuses_plain_gateway_url() {
        assert!(connect(
            "ws://gateway.invalid/",
            "127.0.0.1:1",
            Duration::from_millis(100),
            |_| {}
        )
        .await
        .is_err());
    }
}
