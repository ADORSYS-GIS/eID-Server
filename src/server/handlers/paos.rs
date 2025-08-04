use std::sync::Arc;

// handler/paos.rs
use axum::{extract::State, http::StatusCode, response::IntoResponse};
use tracing::{debug, error, warn};

use crate::{
    domain::eid::{
        models::{AuthenticationProtocolData, ConnectionHandle, DIDAuthenticateRequest},
        ports::{DIDAuthenticate, EIDService, EidService},
        service::{ConnectionHandle as ConnectionHandleService, SessionInfo},
    },
    eid::paos::parser::parse_start_paos,
    server::{AppState, handlers::did_auth::DIDAuthenticateHandler},
    session::SessionStore,
};

pub const EAC_REQUIRED_CHAT: &str = "7f4c12060904007f00070301020253053c0ff3ffff";

pub async fn paos_handler<S, STORE>(
    State(state): State<AppState<S, STORE>>,
    body: String,
) -> impl IntoResponse
where
    S: EIDService + EidService + DIDAuthenticate + Send + Sync + 'static,
    STORE: SessionStore + Clone,
{
    // Parse the SOAP request
    let paos_request = match parse_start_paos(&body) {
        Ok(request) => request,
        Err(err) => {
            error!("Failed to parse PAOS request: {}", err);
            return (
                StatusCode::BAD_REQUEST,
                "Failed to parse PAOS request".to_string(),
            )
                .into_response();
        }
    };

    // Verify session identifier exists
    if paos_request.session_identifier.is_empty() {
        error!("Session identifier is required");
        return (
            StatusCode::BAD_REQUEST,
            "Session identifier is required".to_string(),
        )
            .into_response();
    }
    let session_id = paos_request.session_identifier;

    // Verify session validity
    let session: Option<SessionInfo> = match state.session_manager.get(&session_id).await {
        Ok(session) => session,
        Err(err) => {
            error!("Session validation error: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            )
                .into_response();
        }
    };

    if session.is_none() {
        warn!("Invalid session identifier: {session_id}");
        return (
            StatusCode::UNAUTHORIZED,
            "Invalid session identifier".to_string(),
        )
            .into_response();
    }

    // Update session with connection handles
    let mut session = session.unwrap();
    session.connection_handles = vec![ConnectionHandleService {
        connection_handle: paos_request.connection_handle.card_application,
    }];
    if let Err(err) = state.session_manager.insert(&session_id, session).await {
        error!("Failed to update session connection handles: {err}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update session with connection handles".to_string(),
        )
            .into_response();
    }

    debug!("Successfully updated session: {}", session_id);

    // Create DIDAuthenticate request (EAC1)
    let did_authenticate_request = DIDAuthenticateRequest {
        connection_handle: ConnectionHandle {
            channel_handle: Some(session_id.clone()),
            ifd_name: Some("IFD".to_string()),
            slot_index: Some(0),
        },
        did_name: "EAC".to_string(),
        authentication_protocol_data: AuthenticationProtocolData {
            certificate_description: "".to_string(),
            required_chat: EAC_REQUIRED_CHAT.to_string(),
            optional_chat: None,
            transaction_info: None,
        },
    };

    // Call DIDAuthenticate handler
    let did_response = match state
        .service
        .handle_did_authenticate(did_authenticate_request)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            error!("DIDAuthenticate failed: {}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to process DIDAuthenticate".to_string(),
            )
                .into_response();
        }
    };

    // Convert to SOAP response
    let handler = DIDAuthenticateHandler::new(Arc::clone(&state.service));
    let soap_response = match handler.to_soap_response(did_response) {
        Ok(response) => response,
        Err(err) => {
            error!("Failed to serialize DIDAuthenticate response: {}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate response".to_string(),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        [("Content-Type", "application/xml")],
        soap_response,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Router,
        body::Body,
        http::{self, Request},
    };
    use tower::ServiceExt;

    use crate::{
        domain::eid::service::{EIDServiceConfig, SessionInfo, UseidService},
        session::{MemoryStore, SessionManager},
    };

    use super::*;

    async fn create_test_state(id: String) -> AppState<UseidService<MemoryStore>, MemoryStore> {
        let store = MemoryStore::new();
        let session_manager = SessionManager::new(store);

        // Use a valid 32-byte hex-encoded PSK (64 characters)
        let valid_psk =
            "6db33c51c46bad9b4db72f131fd33442f57ebe6fd9f62c1346b836b30bd37d3d".to_string();

        let session_info = SessionInfo {
            id: id.clone(),
            psk: valid_psk,
            operations: vec![],
            connection_handles: vec![],
        };

        // Store session asynchronously
        session_manager
            .insert(&session_info.id, &session_info)
            .await
            .expect("Failed to store session");

        let service = UseidService {
            config: EIDServiceConfig {
                ecard_server_address: Some("https://test.eid.example.com/ecard".to_string()),
            },
            session_manager: session_manager.clone(),
        };

        AppState {
            service: Arc::new(service.clone()),
            session_manager: Arc::new(session_manager),
        }
    }

    #[tokio::test]
    async fn test_paos_handler_endpoint_ok() {
        let state = create_test_state("faf7554cf8a24e51a4dbfa9881121905".to_string()).await;
        let app = Router::new()
            .route(
                "/eIDService/paos",
                axum::routing::post(paos_handler::<UseidService<MemoryStore>, MemoryStore>),
            )
            .with_state(state.clone());

        let soap_request = std::fs::read_to_string("test_data/startpaos.xml")
            .expect("Failed to read test SOAP request XML");

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/paos")
            .header("content-type", "application/soap+xml")
            .body(Body::from(soap_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_paos_handler_endpoint_invalid_session() {
        let state = create_test_state("invalidsession".to_string()).await;
        let app = Router::new()
            .route(
                "/eIDService/paos",
                axum::routing::post(paos_handler::<UseidService<MemoryStore>, MemoryStore>),
            )
            .with_state(state.clone());

        let soap_request = std::fs::read_to_string("test_data/startpaos.xml")
            .expect("Failed to read test SOAP request XML");

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/paos")
            .header("content-type", "application/soap+xml")
            .body(Body::from(soap_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
