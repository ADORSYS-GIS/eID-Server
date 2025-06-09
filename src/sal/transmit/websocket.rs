use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use url::Url;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, warn};
use std::time::Duration;
use std::env;

// Default to localhost if AUSWEISAPP_HOST is not set
const DEFAULT_AUSWEISAPP_HOST: &str = "localhost";
const AUSWEISAPP_PORT: &str = "24727";
const AUSWEISAPP_PATH: &str = "eID-Kernel";
const MAX_RETRIES: u32 = 3;
const RETRY_DELAY_MS: u64 = 1000;

const AUSWEISAPP_WS_URL: &str = "ws://localhost:24727/eID-Kernel";

pub struct AusweisAppClient {
    ws_stream: Arc<Mutex<Option<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>>>,
}

impl AusweisAppClient {
    pub async fn new() -> Result<Self, String> {
        let mut retries = 0;
        let mut last_error = None;

        while retries < MAX_RETRIES {
            match Self::try_connect().await {
                Ok(ws_stream) => {
                    debug!("Successfully connected to AusweisApp2 WebSocket");
                    return Ok(Self {
                        ws_stream: Arc::new(Mutex::new(Some(ws_stream))),
                    });
                }
                Err(e) => {
                    last_error = Some(e);
                    retries += 1;
                    if retries < MAX_RETRIES {
                        warn!("Failed to connect to AusweisApp2 (attempt {}/{}), retrying in {}ms...", 
                            retries, MAX_RETRIES, RETRY_DELAY_MS);
                        tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                    }
                }
            }
        }

        Err(format!("Failed to connect to AusweisApp2 after {} attempts. Last error: {}", 
            MAX_RETRIES, 
            last_error.unwrap_or_else(|| "Unknown error".to_string())))
    }

    async fn try_connect() -> Result<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, String> {
        let url = Url::parse(AUSWEISAPP_WS_URL)
            .map_err(|e| format!("Failed to parse WebSocket URL: {}", e))?;

        debug!("Attempting to connect to AusweisApp2 at {}", AUSWEISAPP_WS_URL);

        let (ws_stream, _) = connect_async(url)
            .await
            .map_err(|e| format!("Failed to connect to AusweisApp2: {}", e))?;

        Ok(ws_stream)
    }

    pub async fn send_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>, String> {
        let mut ws_stream = self.ws_stream.lock().await;
        let ws = ws_stream.as_mut()
            .ok_or_else(|| "WebSocket connection not available".to_string())?;

        // Convert APDU to hex string
        let apdu_hex = hex::encode(apdu);
        debug!("Sending APDU to AusweisApp2: {}", apdu_hex);

        // Send APDU to AusweisApp2
        ws.send(Message::Text(apdu_hex))
            .await
            .map_err(|e| format!("Failed to send APDU: {}", e))?;

        // Receive response
        let response = ws.next()
            .await
            .ok_or_else(|| "No response received from AusweisApp2".to_string())?
            .map_err(|e| format!("Error receiving response: {}", e))?;

        match response {
            Message::Text(text) => { 
                debug!("Received response from AusweisApp2: {}", text);
                hex::decode(text)
                    .map_err(|e| format!("Failed to decode response: {}", e))
            }
            Message::Close(frame) => {
                let reason = frame.map(|f| f.reason.to_string()).unwrap_or_default();
                Err(format!("WebSocket closed: {}", reason))
            }
            _ => Err("Unexpected message type from AusweisApp2".to_string()),
        }
    }
}

impl Drop for AusweisAppClient {
    fn drop(&mut self) {
        debug!("Closing AusweisApp2 WebSocket connection");
    }
} 