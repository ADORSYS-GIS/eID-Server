use crate::{
    domain::eid::{
        ports::{DIDAuthenticate, EIDService, EidService},
        service::DIDAuthenticateService,
        session_manager::SessionManager,
    },
    server::AppState,
};
use axum::{extract::State, http::StatusCode, response::IntoResponse};
use quick_xml::{Reader, events::Event};
use tracing::{debug, error, warn};
use uuid::Uuid;

pub const EAC_REQUIRED_CHAT: &str = "7f4c12060904007f00070301020253050000000004";
pub const EAC_OPTIONAL_CHAT: &str = "7f4c12060904007f0007030102025305000503ff00";

#[derive(Debug)]
pub enum PaosRequest {
    StartPAOS {
        session_identifier: String,
        message_id: Option<String>,
        connection_handle: ConnectionHandle,
    },
    DIDAuthenticateResponse {
        session_identifier: Option<String>,
        message_id: Option<String>,
        result_major: String,
        result_minor: Option<String>,
        result_message: Option<String>,
    },
}

#[derive(Debug)]
pub struct ConnectionHandle {
    pub card_application: String,
}

// Parser for StartPAOS
pub fn parse_start_paos(xml: &str) -> Result<PaosRequest, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut session_identifier = String::new();
    let mut message_id = None;
    let mut card_application = String::new();
    let mut in_start_paos = false;
    let mut in_connection_handle = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"StartPAOS" | b"ns4:StartPAOS" => in_start_paos = true,
                b"SessionIdentifier" | b"ns4:SessionIdentifier" if in_start_paos => {
                    session_identifier = reader
                        .read_text(e.name())
                        .map_err(|e| format!("Failed to read SessionIdentifier: {e}"))?
                        .to_string();
                }
                b"MessageID" if in_start_paos => {
                    message_id = Some(
                        reader
                            .read_text(e.name())
                            .map_err(|e| format!("Failed to read MessageID: {e}"))?
                            .to_string(),
                    );
                }
                b"ConnectionHandle" | b"ns4:ConnectionHandle" if in_start_paos => {
                    in_connection_handle = true;
                }
                b"CardApplication" | b"ns4:CardApplication" if in_connection_handle => {
                    card_application = reader
                        .read_text(e.name())
                        .map_err(|e| format!("Failed to read CardApplication: {e}"))?
                        .to_string();
                }
                _ => {}
            },
            Ok(Event::End(e)) => match e.name().as_ref() {
                b"ConnectionHandle" | b"ns4:ConnectionHandle" => in_connection_handle = false,
                b"StartPAOS" | b"ns4:StartPAOS" => in_start_paos = false,
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parsing error: {e}")),
            _ => {}
        }
        buf.clear();
    }

    if session_identifier.is_empty() {
        return Err("Missing SessionIdentifier in StartPAOS".to_string());
    }
    if card_application.is_empty() {
        return Err("Missing CardApplication in StartPAOS".to_string());
    }

    Ok(PaosRequest::StartPAOS {
        session_identifier,
        message_id,
        connection_handle: ConnectionHandle { card_application },
    })
}

// Updated parser for DIDAuthenticateResponse
pub fn parse_did_authenticate_response(xml: &str) -> Result<PaosRequest, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut session_identifier = None;
    let mut message_id = None;
    let mut result_major = String::new();
    let mut result_minor = None;
    let mut result_message = None;
    let mut in_did_authenticate = false;
    let mut in_result = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"DIDAuthenticateResponse" | b"ns4:DIDAuthenticateResponse" => {
                    in_did_authenticate = true
                }
                b"SessionIdentifier" | b"ns4:SessionIdentifier" if in_did_authenticate => {
                    session_identifier = Some(
                        reader
                            .read_text(e.name())
                            .map_err(|e| format!("Failed to read SessionIdentifier: {e}"))?
                            .to_string(),
                    );
                }
                b"MessageID" if in_did_authenticate => {
                    message_id = Some(
                        reader
                            .read_text(e.name())
                            .map_err(|e| format!("Failed to read MessageID: {e}"))?
                            .to_string(),
                    );
                }
                b"Result" | b"ns2:Result" if in_did_authenticate => in_result = true,
                b"ResultMajor" | b"ns2:ResultMajor" if in_result => {
                    result_major = reader
                        .read_text(e.name())
                        .map_err(|e| format!("Failed to read ResultMajor: {e}"))?
                        .to_string();
                }
                b"ResultMinor" | b"ns2:ResultMinor" if in_result => {
                    result_minor = Some(
                        reader
                            .read_text(e.name())
                            .map_err(|e| format!("Failed to read ResultMinor: {e}"))?
                            .to_string(),
                    );
                }
                b"ResultMessage" | b"ns2:ResultMessage" if in_result => {
                    result_message = Some(
                        reader
                            .read_text(e.name())
                            .map_err(|e| format!("Failed to read ResultMessage: {e}"))?
                            .to_string(),
                    );
                }
                _ => {}
            },
            Ok(Event::End(e)) => match e.name().as_ref() {
                b"Result" | b"ns2:Result" => in_result = false,
                b"DIDAuthenticateResponse" | b"ns4:DIDAuthenticateResponse" => {
                    in_did_authenticate = false
                }
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parsing error: {e}")),
            _ => {}
        }
        buf.clear();
    }

    if result_major.is_empty() {
        return Err("Missing ResultMajor in DIDAuthenticateResponse".to_string());
    }

    Ok(PaosRequest::DIDAuthenticateResponse {
        session_identifier,
        message_id,
        result_major,
        result_minor,
        result_message,
    })
}

// Update the paos_handler to better handle parsing errors
pub async fn paos_handler<S>(State(state): State<AppState<S>>, body: String) -> impl IntoResponse
where
    S: EIDService + EidService + DIDAuthenticate + SessionManager + Send + Sync + 'static,
{
    debug!("Received PAOS request: {}", body);

    // Try parsing as StartPAOS first
    let paos_request = match parse_start_paos(&body) {
        Ok(request) => request,
        Err(start_err) => {
            debug!("Failed to parse as StartPAOS: {}", start_err);
            // Try parsing as DIDAuthenticateResponse
            match parse_did_authenticate_response(&body) {
                Ok(request) => request,
                Err(did_err) => {
                    error!(
                        "Failed to parse PAOS request: StartPAOS error: {}, DIDAuthenticateResponse error: {}. Raw request: {}",
                        start_err, did_err, body
                    );
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("Failed to parse PAOS request: {did_err}"),
                    )
                        .into_response();
                }
            }
        }
    };

    match paos_request {
        PaosRequest::StartPAOS {
            session_identifier,
            message_id,
            connection_handle,
        } => {
            if session_identifier.is_empty() {
                error!("Session identifier is empty in StartPAOS request");
                return (
                    StatusCode::BAD_REQUEST,
                    "Session identifier is required".to_string(),
                )
                    .into_response();
            }

            let message_id = match message_id {
                Some(id) if !id.is_empty() => id,
                _ => {
                    warn!(
                        "Message ID missing or empty in StartPAOS request. Using fallback UUID. Raw request: {}",
                        body
                    );
                    format!("urn:uuid:{}", Uuid::new_v4())
                }
            };

            debug!(
                "Parsed StartPAOS: session_id: {}, message_id: {}",
                session_identifier, message_id
            );

            let _session_info = match state.use_id.get_session(&session_identifier).await {
                Ok(Some(info)) => info,
                Ok(None) => {
                    warn!("Invalid session identifier: {}", session_identifier);
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

            if let Err(err) = state
                .use_id
                .update_session_connection_handles(
                    &session_identifier,
                    vec![connection_handle.card_application.clone()],
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

            debug!("Successfully updated session: {}", session_identifier);

            let temp_service =
                DIDAuthenticateService::new_with_defaults(state.use_id.clone()).await;

            let certificate_der = match temp_service.certificate_store.load_cv_chain().await {
                Ok(der) => der,
                Err(err) => {
                    error!("Failed to load certificate chain: {}", err);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to load certificate chain".to_string(),
                    )
                        .into_response();
                }
            };

            let certs = match temp_service
                .certificate_store
                .split_concatenated_der(&certificate_der)
            {
                Ok(certs) => certs,
                Err(err) => {
                    error!("Failed to split certificate chain: {}", err);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to split certificate chain".to_string(),
                    )
                        .into_response();
                }
            };

            let certificates_hex: Vec<String> = certs.iter().map(hex::encode).collect();

            let certificate_description = match temp_service
                .certificate_store
                .generate_certificate_description(&certs)
            {
                Ok(desc) => desc,
                Err(err) => {
                    error!("Failed to generate certificate description: {}", err);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to generate certificate description".to_string(),
                    )
                        .into_response();
                }
            };

            let certificates_xml: String = certificates_hex
                .into_iter()
                .map(|cert| format!("<ns4:Certificate>{cert}</ns4:Certificate>"))
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
                                <ns4:CertificateDescription>{}</ns4:CertificateDescription>
                                <ns4:RequiredCHAT>{}</ns4:RequiredCHAT>
                                <ns4:OptionalCHAT>{}</ns4:OptionalCHAT>
                                <ns4:AuthenticatedAuxiliaryData>67177315060904007f00070301040253083230323530373330</ns4:AuthenticatedAuxiliaryData>
                                <ns4:AcceptedEIDType>CardCertified</ns4:AcceptedEIDType>
                            </ns4:AuthenticationProtocolData>
                        </ns4:DIDAuthenticate>
                    </SOAP-ENV:Body>
                </SOAP-ENV:Envelope>"#,
                message_id,
                Uuid::new_v4(),
                connection_handle.card_application,
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
        // Update the DIDAuthenticateResponse case in paos_handler
        PaosRequest::DIDAuthenticateResponse {
            session_identifier,
            message_id,
            result_major,
            result_minor,
            result_message,
        } => {
            debug!(
                "Parsed DIDAuthenticateResponse: session_id: {:?}, message_id: {:?}, result_major: {}, result_minor: {:?}, result_message: {:?}",
                session_identifier, message_id, result_major, result_minor, result_message
            );

            // Validate session only if session_identifier is present
            if let Some(session_id) = &session_identifier {
                match state.use_id.get_session(session_id).await {
                    Ok(Some(_)) => {}
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
            }

            let message_id = message_id.unwrap_or_else(|| {
                debug!("No MessageID provided, generating fallback UUID");
                format!("urn:uuid:{}", Uuid::new_v4())
            });

            let (result_major, result_minor, result_message) = if result_major.contains("error") {
                let minor = result_minor.unwrap_or_else(|| {
                    "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#noPermission"
                        .to_string()
                });
                let message =
                    result_message.unwrap_or_else(|| "Authentication process failed".to_string());
                (
                    "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error".to_string(),
                    minor,
                    message,
                )
            } else {
                (
                    "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok".to_string(),
                    "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#success"
                        .to_string(),
                    "Authentication successful".to_string(),
                )
            };

            let paos_response = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
        <SOAP-ENV:Envelope 
            xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" 
            xmlns:ns2="urn:oasis:names:tc:dss:1.0:core:schema" 
            xmlns:ns4="urn:iso:std:iso-iec:24727:tech:schema">
            <SOAP-ENV:Header>
                <RelatesTo xmlns="http://www.w3.org/2005/03/addressing">{}</RelatesTo>
                <MessageID xmlns="http://www.w3.org/2005/03/addressing">urn:uuid:{}</MessageID>
            </SOAP-ENV:Header>
            <SOAP-ENV:Body>
                <ns4:StartPAOSResponse>
                    <ns2:Result>
                        <ns2:ResultMajor>{}</ns2:ResultMajor>
                        <ns2:ResultMinor>{}</ns2:ResultMinor>
                        <ns2:ResultMessage>{}</ns2:ResultMessage>
                    </ns2:Result>
                </ns4:StartPAOSResponse>
            </SOAP-ENV:Body>
        </SOAP-ENV:Envelope>"#,
                message_id,
                Uuid::new_v4(),
                result_major,
                result_minor,
                result_message
            );

            debug!("Generated StartPAOSResponse: {}", paos_response);

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
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::eid::{
        service::{EIDServiceConfig, SessionInfo, UseidService},
        session_manager::InMemorySessionManager,
    };
    use axum::{
        Router,
        body::Body,
        http::{self, Request, StatusCode},
    };
    use chrono::{Duration, Utc};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    // Mock AppState for testing
    async fn create_test_state(session_id: &str) -> AppState<UseidService> {
        let session_manager = Arc::new(InMemorySessionManager::new()) as Arc<dyn SessionManager>;

        // Valid 32-byte hex-encoded PSK (64 characters)
        let valid_psk =
            "6db33c51c46bad9b4db72f131fd33442f57ebe6fd9f62c1346b836b30bd37d3d".to_string();

        let session_info = SessionInfo {
            id: session_id.to_string(),
            expiry: Utc::now() + Duration::minutes(5),
            psk: valid_psk,
            operations: vec![],
            connection_handles: vec![],
            eac_phase: crate::domain::eid::models::EACPhase::EAC1,
            eac1_challenge: None,
        };

        session_manager
            .store_session(session_info)
            .await
            .expect("Failed to store session");

        let use_id_service = UseidService {
            config: EIDServiceConfig {
                max_sessions: 10,
                session_timeout_minutes: 5,
                ecard_server_address: Some("https://test.eid.example.com".to_string()),
                redis_url: None,
            },
            session_manager,
        };

        let use_id_service_arc = Arc::new(use_id_service);

        AppState {
            use_id: Arc::clone(&use_id_service_arc),
            eid_service: Arc::clone(&use_id_service_arc),
        }
    }

    // Test StartPAOS with valid session
    #[tokio::test]
    async fn test_start_paos_valid_session() {
        let session_id = "faf7554cf8a24e51a4dbfa9881121905";
        let state = create_test_state(session_id).await;
        let app = Router::new()
            .route("/eIDService/paos", axum::routing::post(paos_handler))
            .with_state(state);

        let soap_request = format!(
            r#"
            <?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns4="urn:iso:std:iso-iec:24727:tech:schema">
                <SOAP-ENV:Header>
                    <MessageID xmlns="http://www.w3.org/2005/03/addressing">urn:uuid:12345678-1234-1234-1234-1234567890ab</MessageID>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <ns4:StartPAOS>
                        <ns4:SessionIdentifier>{session_id}</ns4:SessionIdentifier>
                        <ns4:ConnectionHandle>
                            <ns4:CardApplication>01</ns4:CardApplication>
                        </ns4:ConnectionHandle>
                    </ns4:StartPAOS>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
            "#,
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/paos")
            .header("Content-Type", "application/xml")
            .header("PAOS-Version", "urn:liberty:paos:2006-08")
            .body(Body::from(soap_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Expected 200 OK for valid StartPAOS request"
        );

        // Verify headers
        let headers = response.headers();
        assert_eq!(headers["Content-Type"], "application/xml");
        assert_eq!(headers["PAOS-Version"], "urn:liberty:paos:2006-08");

        // Verify response body contains DIDAuthenticate
        let body = response
            .into_body()
            .collect()
            .await
            .expect("Failed to collect body")
            .to_bytes();
        let body_str = String::from_utf8(body.to_vec()).expect("Failed to convert body to string");
        assert!(body_str.contains("<ns4:DIDAuthenticate>"));
        assert!(body_str.contains("<ns4:DIDName>PIN</ns4:DIDName>"));
        assert!(body_str.contains("urn:oid:1.3.162.15480.3.0.14.2"));
    }

    // Test StartPAOS with invalid session
    #[tokio::test]
    async fn test_start_paos_invalid_session() {
        let state = create_test_state("valid_session").await;
        let app = Router::new()
            .route("/eIDService/paos", axum::routing::post(paos_handler))
            .with_state(state);

        let soap_request = r#"
            <?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns4="urn:iso:std:iso-iec:24727:tech:schema">
                <SOAP-ENV:Header>
                    <MessageID xmlns="http://www.w3.org/2005/03/addressing">urn:uuid:12345678-1234-1234-1234-1234567890ab</MessageID>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <ns4:StartPAOS>
                        <ns4:SessionIdentifier>invalid_session</ns4:SessionIdentifier>
                        <ns4:ConnectionHandle>
                            <ns4:CardApplication>01</ns4:CardApplication>
                        </ns4:ConnectionHandle>
                    </ns4:StartPAOS>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
        "#;

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/paos")
            .header("Content-Type", "application/xml")
            .header("PAOS-Version", "urn:liberty:paos:2006-08")
            .body(Body::from(soap_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Expected 401 Unauthorized for invalid session"
        );

        let body = response
            .into_body()
            .collect()
            .await
            .expect("Failed to collect body")
            .to_bytes();
        let body_str = String::from_utf8(body.to_vec()).expect("Failed to convert body to string");
        assert_eq!(body_str, "Invalid session identifier");
    }

    // Test DIDAuthenticateResponse with valid session
    #[tokio::test]
    async fn test_did_authenticate_response_valid_session() {
        let session_id = "faf7554cf8a24e51a4dbfa9881121905";
        let state = create_test_state(session_id).await;
        let app = Router::new()
            .route("/eIDService/paos", axum::routing::post(paos_handler))
            .with_state(state);

        let soap_request = format!(
            r#"
            <?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns2="urn:oasis:names:tc:dss:1.0:core:schema" xmlns:ns4="urn:iso:std:iso-iec:24727:tech:schema">
                <SOAP-ENV:Header>
                    <MessageID xmlns="http://www.w3.org/2005/03/addressing">urn:uuid:98765432-1234-1234-1234-1234567890ab</MessageID>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <ns4:DIDAuthenticateResponse>
                        <ns4:SessionIdentifier>{session_id}</ns4:SessionIdentifier>
                        <ns2:Result>
                            <ns2:ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</ns2:ResultMajor>
                            <ns2:ResultMinor>http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#success</ns2:ResultMinor>
                            <ns2:ResultMessage>Authentication successful</ns2:ResultMessage>
                        </ns2:Result>
                    </ns4:DIDAuthenticateResponse>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
            "#,
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/paos")
            .header("Content-Type", "application/xml")
            .header("PAOS-Version", "urn:liberty:paos:2006-08")
            .body(Body::from(soap_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Expected 200 OK for valid DIDAuthenticateResponse"
        );

        let headers = response.headers();
        assert_eq!(headers["Content-Type"], "application/xml");
        assert_eq!(headers["PAOS-Version"], "urn:liberty:paos:2006-08");

        let body = response
            .into_body()
            .collect()
            .await
            .expect("Failed to collect body")
            .to_bytes();
        let body_str = String::from_utf8(body.to_vec()).expect("Failed to convert body to string");
        assert!(body_str.contains("<ns4:StartPAOSResponse>"));
        assert!(body_str.contains("http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok"));
        assert!(body_str.contains("Authentication successful"));
    }

    // Test DIDAuthenticateResponse without session identifier
    #[tokio::test]
    async fn test_did_authenticate_response_no_session() {
        let state = create_test_state("valid_session").await;
        let app = Router::new()
            .route("/eIDService/paos", axum::routing::post(paos_handler))
            .with_state(state);

        let soap_request = r#"
            <?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns2="urn:oasis:names:tc:dss:1.0:core:schema" xmlns:ns4="urn:iso:std:iso-iec:24727:tech:schema">
                <SOAP-ENV:Header>
                    <MessageID xmlns="http://www.w3.org/2005/03/addressing">urn:uuid:98765432-1234-1234-1234-1234567890ab</MessageID>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <ns4:DIDAuthenticateResponse>
                        <ns2:Result>
                            <ns2:ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</ns2:ResultMajor>
                            <ns2:ResultMinor>http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#success</ns2:ResultMinor>
                            <ns2:ResultMessage>Authentication successful</ns2:ResultMessage>
                        </ns2:Result>
                    </ns4:DIDAuthenticateResponse>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
        "#;

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/paos")
            .header("Content-Type", "application/xml")
            .header("PAOS-Version", "urn:liberty:paos:2006-08")
            .body(Body::from(soap_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Expected 200 OK for DIDAuthenticateResponse without session"
        );

        let headers = response.headers();
        assert_eq!(headers["Content-Type"], "application/xml");
        assert_eq!(headers["PAOS-Version"], "urn:liberty:paos:2006-08");

        let body = response
            .into_body()
            .collect()
            .await
            .expect("Failed to collect body")
            .to_bytes();
        let body_str = String::from_utf8(body.to_vec()).expect("Failed to convert body to string");
        assert!(body_str.contains("<ns4:StartPAOSResponse>"));
        assert!(body_str.contains("http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok"));
        assert!(body_str.contains("Authentication successful"));
    }

    // Test DIDAuthenticateResponse with invalid session
    #[tokio::test]
    async fn test_did_authenticate_response_invalid_session() {
        let state = create_test_state("valid_session").await;
        let app = Router::new()
            .route("/eIDService/paos", axum::routing::post(paos_handler))
            .with_state(state);

        let soap_request = r#"
            <?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns2="urn:oasis:names:tc:dss:1.0:core:schema" xmlns:ns4="urn:iso:std:iso-iec:24727:tech:schema">
                <SOAP-ENV:Header>
                    <MessageID xmlns="http://www.w3.org/2005/03/addressing">urn:uuid:98765432-1234-1234-1234-1234567890ab</MessageID>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <ns4:DIDAuthenticateResponse>
                        <ns4:SessionIdentifier>invalid_session</ns4:SessionIdentifier>
                        <ns2:Result>
                            <ns2:ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</ns2:ResultMajor>
                            <ns2:ResultMinor>http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#success</ns2:ResultMinor>
                            <ns2:ResultMessage>Authentication successful</ns2:ResultMessage>
                        </ns2:Result>
                    </ns4:DIDAuthenticateResponse>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
        "#;

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/paos")
            .header("Content-Type", "application/xml")
            .header("PAOS-Version", "urn:liberty:paos:2006-08")
            .body(Body::from(soap_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Expected 401 Unauthorized for invalid session"
        );

        let body = response
            .into_body()
            .collect()
            .await
            .expect("Failed to collect body")
            .to_bytes();
        let body_str = String::from_utf8(body.to_vec()).expect("Failed to convert body to string");
        assert_eq!(body_str, "Invalid session identifier");
    }

    // Test invalid XML
    #[tokio::test]
    async fn test_invalid_xml() {
        let state = create_test_state("valid_session").await;
        let app = Router::new()
            .route("/eIDService/paos", axum::routing::post(paos_handler))
            .with_state(state);

        let soap_request = r#"
            <?xml version="1.0" encoding="UTF-8"?>
            <InvalidXML>This is not a valid PAOS request</InvalidXML>
        "#;

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/paos")
            .header("Content-Type", "application/xml")
            .header("PAOS-Version", "urn:liberty:paos:2006-08")
            .body(Body::from(soap_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Expected 400 Bad Request for invalid XML"
        );

        let body = response
            .into_body()
            .collect()
            .await
            .expect("Failed to collect body")
            .to_bytes();
        let body_str = String::from_utf8(body.to_vec()).expect("Failed to convert body to string");
        assert!(body_str.contains("Failed to parse PAOS request"));
    }
}
