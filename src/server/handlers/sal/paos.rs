use axum::{extract::State, http::StatusCode, response::IntoResponse};
use tracing::{debug, error, warn};

use crate::{
    domain::eid::ports::{EIDService, EidService},
    sal::paos::parser::parse_start_paos,
    server::AppState,
};

pub async fn paos_handler<S: EIDService + EidService>(
    State(state): State<AppState<S>>,
    body: String,
) -> impl IntoResponse {
    // Parse the SOAP request and handle potential error
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
    let is_valid = match state.use_id.is_session_valid(&session_id) {
        Ok(valid) => valid,
        Err(err) => {
            error!("Session validation error: {}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            )
                .into_response();
        }
    };

    if !is_valid {
        warn!("Invalid session identifier: {}", session_id);
        return (
            StatusCode::UNAUTHORIZED,
            "Invalid session identifier".to_string(),
        )
            .into_response();
    }

    // Update session with connection handles using the service interface
    if let Err(err) = state
        .use_id
        .update_session_connection_handles(&session_id, paos_request.connection_handles)
    {
        error!("Failed to update session connection handles: {}", err);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update session with connection handles".to_string(),
        )
            .into_response();
    }

    debug!("Successfully updated session: {}", session_id);
    StatusCode::OK.into_response()
}

// #[cfg(test)]
// mod tests {
//     use std::sync::{Arc, RwLock};

//     use axum::{
//         Router,
//         body::Body,
//         http::{self, Request},
//     };
//     use chrono::{Duration, Utc};
//     use tower::ServiceExt;

//     use crate::domain::eid::service::{
//         EIDServiceConfig, SessionInfo, SessionManager, UseidService,
//     };

//     use super::*;

//     fn create_test_state(id: String) -> AppState<UseidService> {
//         // Create in-memory session manager
//         let session_manager = InMemorySessionManager::new();

//         // Add test session
//         let session_info = SessionInfo {
//             id: id.clone(),
//             expiry: Utc::now() + Duration::minutes(5),
//             psk: "test_psk".to_string(),
//             operations: vec![],
//             request_counter: 0,
//             authentication_completed: false,
//             authentication_data: None,
//             connection_handles: vec![],
//         };

//         // Need to use runtime to handle async operations
//         let rt = tokio::runtime::Runtime::new().unwrap();
//         rt.block_on(async {
//             session_manager.store_session(session_info).await.unwrap();
//         });

//         let service = UseidService {
//             config: EIDServiceConfig {
//                 max_sessions: 10,
//                 session_timeout_minutes: 5,
//                 ecard_server_address: Some("https://test.eid.example.com/ecard".to_string()),
//                 redis_url: None,
//             },
//             session_manager: Arc::new(session_manager),
//         };

//         AppState {
//             use_id: Arc::new(service.clone()),
//             eid_service: Arc::new(service),
//         }
//     }

//     #[tokio::test]
//     async fn test_paos_handler_endpoint_ok() {
//         // Set up the router with the paos_handler
//         let state = create_test_state("unIdentifiantDeSessionExemple".to_string());
//         let app = Router::new()
//             .route(
//                 "/eIDService/paos",
//                 axum::routing::post(paos_handler::<UseidService>),
//             )
//             .with_state(state.clone());

//         // Prepare the SOAP request
//         let soap_request = std::fs::read_to_string("test_data/startpaos.xml").unwrap();

//         // Send the request
//         let request = Request::builder()
//             .method(http::Method::POST)
//             .uri("/eIDService/paos")
//             .header("content-type", "application/soap+xml")
//             .body(Body::from(soap_request))
//             .unwrap();

//         let response = app.oneshot(request).await.unwrap();

//         // Verify the response status
//         assert_eq!(response.status(), StatusCode::OK);
//     }

//     #[tokio::test]
//     async fn test_paos_handler_endpoint_invalid_session() {
//         let state = create_test_state("invalidsession".to_string());
//         let app = Router::new()
//             .route(
//                 "/eIDService/paos",
//                 axum::routing::post(paos_handler::<UseidService>),
//             )
//             .with_state(state.clone());

//         let soap_request = std::fs::read_to_string("test_data/startpaos.xml")
//             .expect("Failed to read test SOAP request XML");

//         let request = Request::builder()
//             .method(http::Method::POST)
//             .uri("/eIDService/paos")
//             .header("content-type", "application/soap+xml")
//             .body(Body::from(soap_request))
//             .unwrap();

//         let response = app.oneshot(request).await.unwrap();
//         assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
//     }
// }
