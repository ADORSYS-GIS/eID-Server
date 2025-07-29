use crate::{
    domain::eid::{
        ports::{DIDAuthenticate, EIDService, EidService},
        service::DIDAuthenticateService,
        session_manager::SessionManager,
    },
    eid::paos::parser::parse_start_paos,
    server::AppState,
};
use axum::{extract::State, http::StatusCode, response::IntoResponse};
use base64::Engine;
use tracing::{debug, error, warn};

pub const EAC_REQUIRED_CHAT: &str = "7f4c12060904007f00070301020253050000000004";
pub const EAC_OPTIONAL_CHAT: &str = "7f4c12060904007f0007030102025305000503ff00";

pub async fn paos_handler<S>(State(state): State<AppState<S>>, body: String) -> impl IntoResponse
where
    S: EIDService + EidService + DIDAuthenticate + SessionManager + Send + Sync + 'static,
{
    // Log the raw SOAP request for debugging
    debug!("Received StartPAOS request: {}", body);

    // Parse the SOAP request
    let paos_request = match parse_start_paos(&body) {
        Ok(request) => request,
        Err(err) => {
            error!(
                "Failed to parse PAOS request: {}. Raw request: {}",
                err, body
            );
            return (
                StatusCode::BAD_REQUEST,
                format!("Failed to parse PAOS request: {}", err),
            )
                .into_response();
        }
    };

    // Verify session identifier exists
    if paos_request.session_identifier.is_empty() {
        error!("Session identifier is empty in StartPAOS request");
        return (
            StatusCode::BAD_REQUEST,
            "Session identifier is required".to_string(),
        )
            .into_response();
    }
    let session_id = paos_request.session_identifier;

    // Verify message ID exists
    let message_id = match paos_request.message_id {
        Some(id) if !id.is_empty() => id,
        _ => {
            warn!(
                "Message ID missing or empty in StartPAOS request. Using fallback UUID. Raw request: {}",
                body
            );
            format!("urn:uuid:{}", uuid::Uuid::new_v4())
        }
    };
    debug!(
        "Parsed session_id: {}, message_id: {}",
        session_id, message_id
    );

    // Verify session validity
    let _session_info = match state.use_id.get_session(&session_id).await {
        Ok(Some(info)) => info,
        Ok(None) => {
            warn!("Invalid session identifier: {}", session_id);
            return (
                StatusCode::UNAUTHORIZED,
                "Invalid session identifier".to_string(),
            )
                .into_response();
        }
        Err(err) => {
            error!("Session validation error: {}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            )
                .into_response();
        }
    };

    // Clone card_application to avoid move
    let card_application = paos_request.connection_handle.card_application.clone();

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
        )
            .into_response();
    }

    debug!("Successfully updated session: {}", session_id);

    // Create temporary DIDAuthenticateService for certificate operations
    let temp_service = DIDAuthenticateService::new_with_defaults(state.use_id.clone()).await;

    // Load certificate chain
    let certificate_der = match temp_service.certificate_store.load_cv_chain().await {
        Ok(der) => {
            debug!(
                "Loaded certificate chain (raw DER, {} bytes): {:02x?}",
                der.len(),
                der
            );
            der
        }
        Err(err) => {
            error!("Failed to load certificate chain: {}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to load certificate chain".to_string(),
            )
                .into_response();
        }
    };

    // Split certificate chain into individual certificates
    let certs = match temp_service
        .certificate_store
        .split_concatenated_der(&certificate_der)
    {
        Ok(certs) => {
            debug!("Split certificate chain into {} certificates", certs.len());
            for (i, cert) in certs.iter().enumerate() {
                debug!(
                    "Certificate {} ({} bytes): {:02x?}",
                    i + 1,
                    cert.len(),
                    cert
                );
            }
            certs
        }
        Err(err) => {
            error!("Failed to split certificate chain: {}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to split certificate chain".to_string(),
            )
                .into_response();
        }
    };

    let certificates_b64: Vec<String> = certs
        .into_iter()
        .map(|cert| {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&cert);
            debug!("Base64-encoded certificate: {}", b64);
            b64
        })
        .collect();

    // Create certificate description (simplified, adjust as needed)
    let certificate_description = r#"308202e9060a04007f00070301030101a1160c14476f7665726e696b757320546573742044564341a21a1318687474703a2f2f7777772e676f7665726e696b75732e6465a31a0c18476f7665726e696b757320476d6248202620436f2e204b47a418131668747470733a2f2f6c6f63616c686f73743a38343433a58201e10c8201dd4e616d652c20416e7363687269667420756e6420452d4d61696c2d4164726573736520646573204469656e737465616e626965746572733a0d0a476f7665726e696b757320476d6248202620436f2e204b470d0a486f6368736368756c72696e6720340d0a3238333539204272656d656e0d0a6b6f6e74616b7440676f7665726e696b75732e64650d0a0d0a48696e7765697320617566206469652066c3bc722064656e204469656e737465616e62696574657273207a757374c3a46e646967656e205374656c6c656e2c20646965206469652045696e68616c74756e672064657220566f7273636872696674656e207a756d20446174656e73636875747a206b6f6e74726f6c6c696572656e3a0d0a446965204c616e64657362656175667472616774652066c3bc7220446174656e73636875747a20756e6420496e666f726d6174696f6e736672656968656974206465722046726569656e2048616e73657374616474204272656d656e0d0a41726e647473747261c39f6520310d0a3237353730204272656d6572686176656e0d0a303432312f3539362d323031300d0a6f666669636540646174656e73636875747a2e6272656d656e2e64650d0a687474703a2f2f7777772e646174656e73636875747a2e6272656d656e2e6465a7818b31818804202a97cf32df5962486b3fb2fc21c70774908add9d699c9a9b491ce302c8ae849e04202d29c23103995d203fba7dc5271da2872ca0bf110d99455f53614b6d7236b83204202f2fcaa87ec0fc2487ceee9718ec272def0f310041c16b2ad8718bc51c3c7d1204206dec4dd3f51fdcac550188e3a91526ba8b693cac0e38562a03993cc877b54a21"#;

    // Construct PAOS response with DIDAuthenticate SOAP message for PACE
    let certificates_xml: String = certificates_b64
        .into_iter()
        .map(|cert| format!("<iso:Certificate>{}</iso:Certificate>", cert))
        .collect::<Vec<String>>()
        .join("");

    let paos_response = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
    <SOAP-ENV:Header>
        <RelatesTo xmlns="http://www.w3.org/2005/03/addressing">{}</RelatesTo>
        <MessageID xmlns="http://www.w3.org/2005/03/addressing">urn:uuid:{}</MessageID>
    </SOAP-ENV:Header>
    <SOAP-ENV:Body>
        <iso:DIDAuthenticate xmlns:iso="urn:iso:std:iso-iec:24727:tech:schema">
            <iso:ConnectionHandle>
                <iso:CardApplication>{}</iso:CardApplication>
                <iso:SlotHandle>00</iso:SlotHandle>
            </iso:ConnectionHandle>
            <iso:DIDName>PIN</iso:DIDName>
            <iso:AuthenticationProtocolData xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Protocol="urn:oid:1.3.162.15480.3.0.14.2" xsi:type="iso:EAC1InputType">
                {}
                <iso:CertificateDescription>{}</iso:CertificateDescription>
                <iso:RequiredCHAT>{}</iso:RequiredCHAT>
                <iso:OptionalCHAT>{}</iso:OptionalCHAT>
                <iso:AuthenticatedAuxiliaryData>67177315060904007f00070301040253083230323530373238</iso:AuthenticatedAuxiliaryData>
                <iso:AcceptedEIDType>CardCertified</iso:AcceptedEIDType>
            </iso:AuthenticationProtocolData>
        </iso:DIDAuthenticate>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"#,
        message_id,
        uuid::Uuid::new_v4(),
        card_application,
        certificates_xml,
        certificate_description,
        EAC_REQUIRED_CHAT,
        EAC_OPTIONAL_CHAT
    );

    debug!("Generated PAOS response: {}", paos_response);

    (
        StatusCode::OK,
        [
            ("Content-Type", "application/xml"),
            ("PAOS-Version", "urn:liberty:paos:2006-08"),
        ],
        paos_response,
    )
        .into_response()
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