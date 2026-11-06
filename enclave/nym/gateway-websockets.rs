#[cfg(not(target_arch = "wasm32"))]
use crate::client::GatewayListeners;
use crate::error::GatewayClientError;
use std::time::Duration;
#[cfg(unix)]
use std::{
    os::fd::{AsRawFd, RawFd},
    sync::Arc,
};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tungstenite::handshake::client::Response;

#[path = "cwxmr-connect.rs"]
mod cwxmr_connect;

async fn connect(
    endpoint: &str,
    #[cfg(unix)] callback: Option<Arc<dyn Fn(RawFd) + Send + Sync>>,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), GatewayClientError> {
    cwxmr_connect::connect(
        endpoint,
        "127.0.0.1:8888",
        Duration::from_secs(30),
        |stream| {
            #[cfg(unix)]
            if let Some(callback) = callback {
                callback(stream.as_raw_fd());
            }
        },
    )
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
