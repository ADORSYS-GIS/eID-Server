use async_trait::async_trait;
use axum::{body::Bytes, extract::State, http::StatusCode, response::IntoResponse};
use tracing::{debug, error};

use crate::sal::transmit::channel::ApduTransport;

/// Mock APDU transport implementation for the server
/// This will be replaced with a real hardware implementation in production
pub struct ServerApduTransport;

#[async_trait]
impl ApduTransport for ServerApduTransport {
    async fn transmit_apdu(&self, apdu: Vec<u8>) -> Result<Vec<u8>, String> {
        // For now: echo back the APDU with status code 9000 (success)
        // This should be replaced with actual card communication
        debug!("Transmitting APDU: {}", hex::encode(&apdu));
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
            error!("Error handling transmit request: {}", e);
            (
                StatusCode::BAD_REQUEST,
                format!("Error: {}", e).into_bytes(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::eid::service::{EIDServiceConfig, UseidService};
    use crate::sal::transmit::{
        channel::TransmitChannel, config::TransmitConfig, protocol::ProtocolHandler,
        session::SessionManager,
    };
    use crate::server::AppState;
    use axum::http::StatusCode;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn test_transmit_handler_invalid_request() {
        // Setup
        let protocol_handler = ProtocolHandler::new();
        let session_manager = SessionManager::new(Duration::from_secs(60));
        let config = TransmitConfig::default();
        let transmit_channel = Arc::new(TransmitChannel::new(
            protocol_handler,
            session_manager,
            config,
        ));

        let eid_service = Arc::new(UseidService::new(EIDServiceConfig::default()));
        let state = AppState {
            use_id: eid_service.clone(),
            eid_service,
            transmit_channel,
        };

        // Test with invalid request
        let invalid_request = Bytes::from_static(b"invalid request");
        let response = transmit_handler(State(state), invalid_request)
            .await
            .into_response();

        // Verify - TransmitChannel converts errors to valid XML responses with error codes
        // so we expect a 200 OK status with an XML error response
        assert_eq!(response.status(), StatusCode::OK);
    }
}
