use axum::{extract::State, http::{StatusCode, HeaderMap, HeaderValue}, response::IntoResponse};
use tracing::{debug, error, warn};
use crate::sal::transmit::session::TransmitSessionStore;
use once_cell::sync::Lazy;

use crate::{
    domain::eid::{
        ports::{EIDService, EidService},
        service::ConnectionHandle,
    },
    sal::paos::parser::parse_start_paos,
    server::AppState,
};

const SOAP_RESPONSE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:paos="urn:liberty:paos:2006-08" xmlns:iso="urn:iso:std:iso-iec:24727:tech:schema">
  <soap:Header>
    <paos:PAOS soap:mustUnderstand="1" soap:actor="http://schemas.xmlsoap.org/soap/actor/next">
      <paos:Version>urn:liberty:paos:2006-08</paos:Version>
      <paos:EndpointReference>
        <paos:Address>http://www.projectliberty.org/2006/01/role/paos</paos:Address>
        <paos:MetaData>
          <paos:ServiceType>http://www.bsi.bund.de/ecard/api/1.1/PAOS/GetNextCommand</paos:ServiceType>
        </paos:MetaData>
      </paos:EndpointReference>
    </paos:PAOS>
  </soap:Header>
  <soap:Body>
    <iso:GetNextCommandResponse/>
  </soap:Body>
</soap:Envelope>"#;
 
static TRANSMIT_SESSION_STORE: Lazy<TransmitSessionStore> = Lazy::new(TransmitSessionStore::new);

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
        let mut session_manager = match session_manager_arc.write() {
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

        // Find the session and update its connection handles
        if let Some(session) = session_manager
            .sessions
            .iter_mut()
            .find(|s| s.id == session_id)
        {
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

    // After session_id is validated and before returning the response:
    TRANSMIT_SESSION_STORE.create_session(session_id.clone());

    // Return a minimal SOAP/PAOS-compliant response
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/soap+xml; charset=utf-8"),
    );
    (StatusCode::OK, headers, SOAP_RESPONSE).into_response()
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

    use super::*;

    fn create_test_state(id: String) -> AppState<UseidService> {
        let service = UseidService {
            config: EIDServiceConfig {
                max_sessions: 10,
                session_timeout_minutes: 5,
                ecard_server_address: Some("https://test.eid.example.com/ecard".to_string()),
            },
            session_manager: Arc::new(RwLock::new(SessionManager {
                sessions: vec![SessionInfo {
                    id,
                    expiry: Utc::now() + Duration::minutes(5),
                    psk: String::new(),
                    operations: vec![],
                    connection_handles: vec![],
                }],
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
