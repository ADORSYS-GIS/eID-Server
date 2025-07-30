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

    // Convert raw DER bytes to hex strings for XML (NO base64 encoding!)
    let certificates_hex: Vec<String> = certs
        .iter()
        .map(|cert| {
            let hex = hex::encode(cert);
            debug!("Raw DER certificate as hex ({} bytes): {}", cert.len(), hex);
            hex
        })
        .collect();

    let certificate_description = match temp_service
        .certificate_store
        .generate_certificate_description(&certs)
    {
        Ok(desc) => {
            debug!("Generated certificate description: {}", desc);
            desc
        }
        Err(err) => {
            error!("Failed to generate certificate description: {}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate certificate description".to_string(),
            )
                .into_response();
        }
    };

    // Create certificate XML elements using hex-encoded DER data
    let certificates_xml: String = certificates_hex
        .into_iter()
        .map(|cert| format!("<ns4:Certificate>{}</ns4:Certificate>", cert))
        .collect::<Vec<String>>()
        .join("");

    let paos_response = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns4="urn:iso:std:iso-iec:24727:tech:schema">
                <SOAP-ENV:Header>
                    <RelatesTo xmlns="http://www.w3.org/2005/03/addressing">{}</RelatesTo>
                    <MessageID xmlns="http://www.w3.org/2005/03/addressing">urn:uuid:{}</MessageID>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <ns4:DIDAuthenticate>
                        <ns4:ConnectionHandle>
                            <ns4:CardApplication>{}</ns4:CardApplication>
                            <ns4:SlotHandle>00</ns4:SlotHandle>
                        </ns4:ConnectionHandle>
                        <ns4:DIDName>PIN</ns4:DIDName>
                        <ns4:AuthenticationProtocolData xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Protocol="urn:oid:1.3.162.15480.3.0.14.2" xsi:type="ns4:EAC1InputType">
                            {}
                            <ns4:CertificateDescription xmlns="urn:iso:std:iso-iec:24727:tech:schema">{}</ns4:CertificateDescription>
                            <ns4:RequiredCHAT>{}</ns4:RequiredCHAT>
                            <ns4:OptionalCHAT>{}</ns4:OptionalCHAT>
                            <ns4:AuthenticatedAuxiliaryData>67177315060904007f00070301040253083230323530373238</ns4:AuthenticatedAuxiliaryData>
                            <ns4:AcceptedEIDType>CardCertified</ns4:AcceptedEIDType>
                        </ns4:AuthenticationProtocolData>
                    </ns4:DIDAuthenticate>
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
