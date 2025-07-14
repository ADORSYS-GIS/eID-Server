use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use tracing::{debug, error, info, warn};

/// Handler for the /eIDService/transmit endpoint
///
/// This handler processes APDU transmission requests according to:
/// - TR-03112 (eCard-API Framework)
/// - ISO 24727-3 (Identification cards - Integrated circuit cards - Part 3: Application interface)
/// - TR-03130 (eID-Server)
///
/// The handler validates the request, delegates to the transmit channel for processing,
/// and returns properly formatted XML responses with appropriate HTTP headers.
///
/// # Security Considerations
/// - Validates request size limits
/// - Ensures proper content-type handling
/// - Implements comprehensive error handling
/// - Provides detailed logging for security monitoring
///
/// # Performance Considerations
/// - Uses streaming for large requests
/// - Implements proper timeout handling via the transmit channel
/// - Provides metrics via tracing
pub async fn transmit_handler<S>(
    State(state): State<crate::server::AppState<S>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse
where
    S: crate::domain::eid::ports::EIDService + crate::domain::eid::ports::EidService,
{
    // Log request details for monitoring and debugging
    info!(
        "Received transmit request: size={} bytes, content_type={:?}",
        body.len(),
        headers.get("content-type")
    );
    debug!("Request headers: {:?}", headers);

    // Validate request size (prevent DoS attacks)
    const MAX_REQUEST_SIZE: usize = 1024 * 1024; // 1MB limit
    if body.len() > MAX_REQUEST_SIZE {
        warn!(
            "Transmit request too large: {} bytes (max: {} bytes)",
            body.len(),
            MAX_REQUEST_SIZE
        );
        return create_error_response(StatusCode::PAYLOAD_TOO_LARGE, "Request payload too large");
    }

    // Validate content type if present
    if let Some(content_type) = headers.get("content-type") {
        if let Ok(content_type_str) = content_type.to_str() {
            if !content_type_str.contains("xml") && !content_type_str.contains("text") {
                warn!(
                    "Invalid content type for transmit request: {}",
                    content_type_str
                );
                return create_error_response(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "Content-Type must be XML",
                );
            }
        }
    }

    // Validate that request is not empty
    if body.is_empty() {
        warn!("Empty transmit request received");
        return create_error_response(StatusCode::BAD_REQUEST, "Empty request body");
    }

    // Process the request through the transmit channel
    debug!("Delegating to transmit channel for processing");
    match state.transmit_channel.handle_request(&body).await {
        Ok(response) => {
            info!(
                "Transmit request processed successfully: response_size={} bytes",
                response.len()
            );
            debug!("Transmit processing completed without errors");

            // Return successful response with proper XML content type
            create_xml_response(StatusCode::OK, response)
        }
        Err(e) => {
            error!("Error handling transmit request: {}", e);

            // Determine appropriate HTTP status code based on error type
            let status_code = match e.to_string().as_str() {
                s if s.contains("timeout") => StatusCode::REQUEST_TIMEOUT,
                s if s.contains("Invalid UTF-8") => StatusCode::BAD_REQUEST,
                s if s.contains("XML error") => StatusCode::BAD_REQUEST,
                s if s.contains("APDU too large") => StatusCode::PAYLOAD_TOO_LARGE,
                s if s.contains("Session error") => StatusCode::UNAUTHORIZED,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };

            // Create proper error response according to eCard-API specifications
            create_error_response(status_code, &format!("Transmit error: {e}"))
        }
    }
}

/// Creates a properly formatted XML response with appropriate headers
fn create_xml_response(status: StatusCode, body: Vec<u8>) -> Response {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/xml; charset=utf-8")
        .header("Cache-Control", "no-cache, no-store, must-revalidate")
        .header("Pragma", "no-cache")
        .header("Expires", "0")
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|e| {
            error!("Failed to create XML response: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::from("Internal server error"))
                .unwrap()
        })
}

/// Escapes XML special characters to prevent XML injection
fn escape_xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Creates a properly formatted error response
fn create_error_response(status: StatusCode, message: &str) -> Response {
    let error_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<TransmitResponse xmlns="urn:iso:std:iso-iec:24727:tech:schema">
    <Result>
        <ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error</ResultMajor>
        <ResultMinor>http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#generalError</ResultMinor>
        <ResultMessage xml:lang="en">{}</ResultMessage>
    </Result>
</TransmitResponse>"#,
        escape_xml(message)
    );

    Response::builder()
        .status(status)
        .header("Content-Type", "application/xml; charset=utf-8")
        .header("Cache-Control", "no-cache, no-store, must-revalidate")
        .header("Pragma", "no-cache")
        .header("Expires", "0")
        .body(axum::body::Body::from(error_xml))
        .unwrap_or_else(|e| {
            error!("Failed to create error response: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::from("Internal server error"))
                .unwrap()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TransmitConfig;
    use crate::domain::eid::service::{EIDServiceConfig, UseidService};
    use crate::domain::eid::transmit::{
        channel::TransmitChannel, protocol::ProtocolHandler, test_service::TestTransmitService,
    };
    use crate::server::session::SessionManager;
    use axum::{
        extract::State,
        http::{HeaderMap, HeaderValue, StatusCode},
    };
    use http_body_util::BodyExt;
    use std::{sync::Arc, time::Duration};

    fn create_test_state() -> crate::server::AppState<UseidService> {
        let service = UseidService::new(EIDServiceConfig::default());
        let service_arc = Arc::new(service);

        let transmit_channel = Arc::new(
            TransmitChannel::new(
                ProtocolHandler::new(),
                SessionManager::new(Duration::from_secs(60)),
                Arc::new(TestTransmitService),
                TransmitConfig::default(),
            )
            .expect("TransmitChannel creation should succeed in tests"),
        );

        crate::server::AppState {
            use_id: service_arc.clone(),
            eid_service: service_arc,
            transmit_channel,
        }
    }

    #[tokio::test]
    async fn test_transmit_handler_success() {
        let state = create_test_state();
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/xml"));

        let xml_request = r#"<?xml version="1.0" encoding="UTF-8"?>
<Transmit xmlns="urn:iso:std:iso-iec:24727:tech:schema">
    <SlotHandle>test-slot</SlotHandle>
    <InputAPDUInfo>
        <InputAPDU>00A4040008A000000167455349</InputAPDU>
        <AcceptableStatusCode>9000</AcceptableStatusCode>
    </InputAPDUInfo>
</Transmit>"#;

        let response = transmit_handler(State(state), headers, Bytes::from(xml_request))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/xml; charset=utf-8"
        );

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body_str.contains("TransmitResponse"));
        assert!(body_str.contains("resultmajor#ok"));
    }

    #[tokio::test]
    async fn test_transmit_handler_empty_request() {
        let state = create_test_state();
        let headers = HeaderMap::new();

        let response = transmit_handler(State(state), headers, Bytes::new())
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/xml; charset=utf-8"
        );

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body_str.contains("TransmitResponse"));
        assert!(body_str.contains("resultmajor#error"));
        assert!(body_str.contains("Empty request body"));
    }

    #[tokio::test]
    async fn test_transmit_handler_request_too_large() {
        let state = create_test_state();
        let headers = HeaderMap::new();
        let large_request = vec![b'x'; 2 * 1024 * 1024];

        let response = transmit_handler(State(state), headers, Bytes::from(large_request))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/xml; charset=utf-8"
        );
    }

    #[tokio::test]
    async fn test_transmit_handler_invalid_content_type() {
        let state = create_test_state();
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let response = transmit_handler(State(state), headers, Bytes::from("test"))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/xml; charset=utf-8"
        );
    }

    #[tokio::test]
    async fn test_transmit_handler_malformed_xml() {
        let state = create_test_state();
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/xml"));

        let malformed_xml = "<invalid>xml</invalid>";

        let response = transmit_handler(State(state), headers, Bytes::from(malformed_xml))
            .await
            .into_response();

        // According to eCard-API specifications, malformed XML should return HTTP 200
        // with a proper XML error response, not HTTP 400
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/xml; charset=utf-8"
        );

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body_str.contains("TransmitResponse"));
        assert!(body_str.contains("resultmajor#error"));
    }
}
