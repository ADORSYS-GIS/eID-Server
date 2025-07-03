use axum::{extract::State, http::StatusCode, response::IntoResponse};
use tracing::{debug, error, warn};

use crate::{
    domain::eid::{
        ports::{EIDService, EidService},
        service::ConnectionHandle,
    },
    sal::paos::parser::parse_start_paos,
    server::AppState,
};

pub async fn paos_handler<S: EIDService + EidService>(
    State(state): State<AppState<S>>,
    body: String,
) -> impl IntoResponse {
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
    let session_id = paos_request.session_identifier;
    if session_id.is_empty() {
        error!("Session identifier is required");
        return (
            StatusCode::BAD_REQUEST,
            "Session identifier is required".to_string(),
        )
            .into_response();
    }

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

    // Update session manager with connection handles
    let update_result = {
        let session_manager_arc = state.use_id.get_session_manager();
        let session_manager = match session_manager_arc.write() {
            Ok(mgr) => mgr,
            Err(err) => {
                error!("Session manager lock poisoned: {}", err);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
                    .into_response();
            }
        };

        // Acquire write lock on sessions
        let mut sessions = match session_manager.sessions.write() {
            Ok(sessions) => sessions,
            Err(err) => {
                error!("Sessions lock poisoned: {}", err);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
                    .into_response();
            }
        };

        // Find the session and update its connection handles
        if let Some(session) = sessions.iter_mut().find(|s| s.id == session_id) {
            for handle in paos_request.connection_handles {
                session.connection_handles.push(ConnectionHandle {
                    connection_handle: handle,
                });
            }
            debug!(
                "Updated session {} with {} connection handles",
                session_id,
                session.connection_handles.len()
            );
            Ok(())
        } else {
            error!("Session {} not found in session manager", session_id);
            Err(())
        }
    };

    if update_result.is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update session with connection handles".to_string(),
        )
            .into_response();
    }

    (StatusCode::OK).into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use axum::{
        Router,
        body::Body,
        http::{self, Request},
    };
    use chrono::{Duration, Utc};
    use tower::ServiceExt;

    use crate::domain::eid::service::{
        EIDServiceConfig, SessionInfo, SessionManager, UseidService,
    };
    use crate::server::AppState;
    use super::*;

    fn create_test_state(id: String) -> AppState<UseidService> {
        let service = UseidService {
            config: EIDServiceConfig {
                max_sessions: 10,
                session_timeout_minutes: 5,
                ecard_server_address: Some("https://test.eid.example.com/ecard".to_string()),
            },
            session_manager: Arc::new(RwLock::new(SessionManager {
                sessions: Arc::new(RwLock::new(vec![SessionInfo {
                    id,
                    expiry: Utc::now() + Duration::minutes(5),
                    psk: String::new(),
                    operations: vec![],
                    connection_handles: vec![],
                }])),
            })),
        };
        let service_arc = Arc::new(service);
        AppState {
            use_id: service_arc.clone(),
            eid_service: service_arc,
        }
    }

    #[tokio::test]
    async fn test_paos_handler_endpoint_ok() {
        // Set up the router with the paos_handler
        let state = create_test_state("unIdentifiantDeSessionExemple".to_string());
        let app = Router::new()
            .route(
                "/eIDService/paos",
                axum::routing::post(paos_handler::<UseidService>),
            )
            .with_state(state.clone());

        // Prepare the SOAP request
        let soap_request = std::fs::read_to_string("test_data/startpaos.xml").unwrap();

        // Send the request
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/paos")
            .header("content-type", "application/soap+xml")
            .body(Body::from(soap_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Verify the response status
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_paos_handler_endpoint_invalid_session() {
        let state = create_test_state("invalidsession".to_string());
        let app = Router::new()
            .route(
                "/eIDService/paos",
                axum::routing::post(paos_handler::<UseidService>),
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
