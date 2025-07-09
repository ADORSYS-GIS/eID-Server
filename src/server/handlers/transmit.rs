use async_trait::async_trait;
use axum::{body::Bytes, extract::State, http::StatusCode, response::IntoResponse};
use tracing::{debug, error};

use crate::sal::transmit::channel::ApduTransport;

pub struct ServerApduTransport;

#[async_trait]
impl ApduTransport for ServerApduTransport {
    async fn transmit_apdu(&self, apdu: Vec<u8>, slot_handle: &str) -> Result<Vec<u8>, String> {
        debug!(
            "Transmitting APDU: {} for slot: {}",
            hex::encode(&apdu),
            slot_handle
        );
        let mut response = apdu;
        response.extend_from_slice(&[0x90, 0x00]);
        Ok(response)
    }
}

/// Handler for the /transmit endpoint
/// Processes APDU requests according to TR-03112 and ISO 24727-3
pub async fn transmit_handler<S>(
    State(state): State<crate::server::AppState<S>>,
    body: Bytes,
) -> impl IntoResponse
where
    S: crate::domain::eid::ports::EIDService + crate::domain::eid::ports::EidService,
{
    debug!("Received transmit request");
    match state.transmit_channel.handle_request(&body).await {
        Ok(response) => {
            debug!("Transmit request processed successfully");
            (StatusCode::OK, response)
        }
        Err(e) => {
            error!("Error handling transmit request: {e}");
            (StatusCode::BAD_REQUEST, format!("Error: {e}").into_bytes())
        }
    }
}
