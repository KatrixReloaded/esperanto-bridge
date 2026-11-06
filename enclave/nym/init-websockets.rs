use crate::error::ClientCoreError;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tungstenite::handshake::client::Response;

#[path = "cwxmr-connect.rs"]
mod cwxmr_connect;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn connect_async(
    endpoint: &str,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), ClientCoreError> {
    cwxmr_connect::connect(endpoint, "127.0.0.1:8888", Duration::from_secs(30), |_| {})
        .await
        .map_err(Into::into)
}
