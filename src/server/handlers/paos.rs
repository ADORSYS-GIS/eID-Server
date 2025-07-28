use std::sync::Arc;
use axum::{extract::State, http::StatusCode, response::IntoResponse};
use base64::Engine;
use tracing::{debug, error, warn};
use std::string::String;
use crate::{
    domain::eid::{
        models::{AuthenticationProtocolData, ConnectionHandle, DIDAuthenticateRequest, EAC1InputType, EAC2InputType, EACPhase},
        ports::{DIDAuthenticate, EIDService, EidService},
        service::{DIDAuthenticateService},
        session_manager::SessionManager,
    },
    eid::paos::parser::parse_start_paos,
    server::{handlers::did_auth::DIDAuthenticateHandler, AppState},
};

pub const EAC_REQUIRED_CHAT: &str = "7f4c12060904007f00070301020253053c0ff3ffff";

pub async fn paos_handler<S>(State(state): State<AppState<S>>, body: String) -> impl IntoResponse
where
    S: EIDService + EidService + DIDAuthenticate + SessionManager + Send + Sync + 'static,
{
    // Parse the SOAP request
    let paos_request = match parse_start_paos(&body) {
        Ok(request) => request,
        Err(err) => {
            error!("Failed to parse PAOS request: {}", err);
            return (
                StatusCode::BAD_REQUEST,
                "Failed to parse PAOS request".to_string(),
            ).into_response();
        }
    };

    // Verify session identifier exists
    if paos_request.session_identifier.is_empty() {
        error!("Session identifier is required");
        return (
            StatusCode::BAD_REQUEST,
            "Session identifier is required".to_string(),
        ).into_response();
    }
    let session_id = paos_request.session_identifier;

    // Verify session validity
    let session_info = match state.use_id.get_session(&session_id).await {
        Ok(Some(info)) => info,
        Ok(None) => {
            warn!("Invalid session identifier: {}", session_id);
            return (
                StatusCode::UNAUTHORIZED,
                "Invalid session identifier".to_string(),
            ).into_response();
        }
        Err(err) => {
            error!("Session validation error: {}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ).into_response();
        }
    };

    // Update session with connection handles
    if let Err(err) = state
        .use_id
        .update_session_connection_handles(
            &session_id,
            vec![paos_request.connection_handle.card_application],
        )
        .await
    {
        error!("Failed to update session connection handles: {}", err);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update session with connection handles".to_string(),
        ).into_response();
    }

    debug!("Successfully updated session: {}", session_id);

    // Create DIDAuthenticate request based on session phase
    let did_authenticate_request = match session_info.eac_phase {
        EACPhase::EAC1 => {
            // Load certificate chain
            // Since we need certificate_store, we need a temporary DIDAuthenticateService
            let temp_service = DIDAuthenticateService::new_with_defaults(state.use_id.clone()).await;
            let certificate_der = match temp_service.certificate_store.load_cv_chain().await {
                Ok(der) => der,
                Err(err) => {
                    error!("Failed to load certificate chain: {}", err);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to load certificate chain".to_string(),
                    ).into_response();
                }
            };
            let certificate_b64 = base64::engine::general_purpose::STANDARD.encode(&certificate_der);

            DIDAuthenticateRequest {
                connection_handle: ConnectionHandle {
                    channel_handle: Some(session_id.clone()),
                    ifd_name: Some("IFD".to_string()),
                    slot_index: Some(0),
                },
                did_name: "EAC".to_string(),
                authentication_protocol_data: AuthenticationProtocolData {
                    phase: EACPhase::EAC1,
                    eac1_input: Some(EAC1InputType {
                        certificate: certificate_b64,
                        certificate_description: "".to_string(),
                        required_chat: EAC_REQUIRED_CHAT.to_string(),
                        optional_chat: None,
                        transaction_info: None,
                    }),
                    eac2_input: None,
                },
            }
        }
        EACPhase::EAC2 => {
            let challenge = match session_info.eac1_challenge {
                Some(ch) => ch,
                None => {
                    error!("No challenge stored for EAC2 phase");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "No challenge stored for EAC2 phase".to_string(),
                    ).into_response();
                }
            };

            // Generate ephemeral key pair and sign challenge
            // Use a temporary DIDAuthenticateService for crypto operations
            let temp_service = DIDAuthenticateService::new_with_defaults(state.use_id.clone()).await;
            let (_private_key, public_key) = match temp_service.crypto_provider.generate_keypair().await {
                Ok(kp) => kp,
                Err(err) => {
                    error!("Failed to generate keypair: {}", err);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to generate keypair".to_string(),
                    ).into_response();
                }
            };
            let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(&public_key);
            let signature = match temp_service.crypto_provider.hash_data(challenge.as_bytes(), "SHA256").await {
                Ok(sig) => sig,
                Err(err) => {
                    error!("Failed to sign challenge: {}", err);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to sign challenge".to_string(),
                    ).into_response();
                }
            };
            let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);

            DIDAuthenticateRequest {
                connection_handle: ConnectionHandle {
                    channel_handle: Some(session_id.clone()),
                    ifd_name: Some("IFD".to_string()),
                    slot_index: Some(0),
                },
                did_name: "EAC".to_string(),
                authentication_protocol_data: AuthenticationProtocolData {
                    phase: EACPhase::EAC2,
                    eac1_input: None,
                    eac2_input: Some(EAC2InputType {
                        ephemeral_public_key: public_key_b64,
                        signature: signature_b64,
                    }),
                },
            }
        }
    };

    // Call DIDAuthenticate handler
    let did_response = match state
        .eid_service
        .handle_did_authenticate(did_authenticate_request)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            error!("DIDAuthenticate failed: {}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to process DIDAuthenticate".to_string(),
            ).into_response();
        }
    };

    // Convert to SOAP response
    let handler = DIDAuthenticateHandler::new(Arc::clone(&state.eid_service));
    let soap_response = match handler.to_soap_response(did_response) {
        Ok(response) => response,
        Err(err) => {
            error!("Failed to serialize DIDAuthenticate response: {}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate response".to_string(),
            ).into_response();
        }
    };

    (
        StatusCode::OK,
        [("Content-Type", "application/xml")],
        soap_response,
    ).into_response()
}

// #[cfg(test)]
// mod tests {
//     use std::sync::Arc;

//     use axum::{
//         Router,
//         body::Body,
//         http::{self, Request},
//     };
//     use chrono::{Duration, Utc};
//     use tower::ServiceExt;

//     use crate::domain::eid::{
//         service::{EIDServiceConfig, SessionInfo, UseidService, DIDAuthenticateService},
//         session_manager::{InMemorySessionManager, SessionManager},
//     };

//     use super::*;

//     async fn create_test_state(id: String) -> AppState {
//         let session_manager = Arc::new(InMemorySessionManager::new()) as Arc<dyn SessionManager>;

//         // Use a valid 32-byte hex-encoded PSK (64 characters)
//         let valid_psk =
//             "6db33c51c46bad9b4db72f131fd33442f57ebe6fd9f62c1346b836b30bd37d3d".to_string();

//         let session_info = SessionInfo {
//             id: id.clone(),
//             expiry: Utc::now() + Duration::minutes(5),
//             psk: valid_psk,
//             operations: vec![],
//             connection_handles: vec![],
//             eac_phase: EACPhase::EAC1,
//             eac1_challenge: None,
//         };

//         // Store session asynchronously
//         session_manager
//             .store_session(session_info)
//             .await
//             .expect("Failed to store session");

//         let use_id_service = UseidService {
//             config: EIDServiceConfig {
//                 max_sessions: 10,
//                 session_timeout_minutes: 5,
//                 ecard_server_address: Some("https://test.eid.example.com/ecard".to_string()),
//                 redis_url: None,
//             },
//             session_manager: session_manager.clone(),
//         };

//         let eid_service = DIDAuthenticateService::new_with_defaults(session_manager).await;

//         AppState {
//             use_id: Arc::new(use_id_service),
//             eid_service: Arc::new(eid_service),
//         }
//     }

//     #[tokio::test]
//     async fn test_paos_handler_endpoint_ok() {
//         let state = create_test_state("faf7554cf8a24e51a4dbfa9881121905".to_string()).await;
//         let app = Router::new()
//             .route(
//                 "/eIDService/paos",
//                 axum::routing::post(paos_handler),
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
//         assert_eq!(response.status(), StatusCode::OK);
//     }

//     #[tokio::test]
//     async fn test_paos_handler_endpoint_invalid_session() {
//         let state = create_test_state("invalidsession".to_string()).await;
//         let app = Router::new()
//             .route(
//                 "/eIDService/paos",
//                 axum::routing::post(paos_handler),
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
