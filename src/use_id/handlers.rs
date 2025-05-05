use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::sync::Arc;
use tracing::{debug, error};

use crate::use_id::models::{UseIDRequest, soap};

use super::service::EIDService;

pub async fn use_id_handler(
    State(service): State<Arc<EIDService>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    // Check content type
    if !is_soap_content_type(&headers) {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Expected SOAP XML content type".to_string(),
        )
            .into_response();
    }

    // Parse the SOAP request
    let use_id_request = match soap::deserialize_soap_request::<UseIDRequest>(&body) {
        Ok(request) => request,
        Err(err) => {
            error!("Failed to parse SOAP request: {}", err);
            return (
                StatusCode::BAD_REQUEST,
                format!("Failed to parse SOAP request: {}", err),
            )
                .into_response();
        }
    };

    debug!(
        "Received UseID request with {} operations",
        use_id_request.use_operations.use_operations.len()
    );

    // Process the request
    let response = match service.handle_use_id(use_id_request).await {
        Ok(response) => response,
        Err(err) => {
            error!("Error processing useID request: {}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            )
                .into_response();
        }
    };

    // Serialize the response
    match soap::serialize_soap_response(response) {
        Ok(soap_response) => {
            debug!("Successfully generated SOAP response");
            (
                StatusCode::OK,
                create_soap_response_headers(),
                soap_response,
            )
                .into_response()
        }
        Err(err) => {
            error!("Failed to serialize SOAP response: {}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create SOAP response".to_string(),
            )
                .into_response()
        }
    }
}

/// Check if the content type is appropriate for SOAP
fn is_soap_content_type(headers: &HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.contains("text/xml")
                || v.contains("application/soap+xml")
                || v.contains("application/xml")
        })
        .unwrap_or(false)
}

/// Create headers for SOAP response
fn create_soap_response_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "Content-Type",
        "application/soap+xml; charset=utf-8".parse().unwrap(),
    );
    headers
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_id::models::{
        PSK, UseIDRequest, UseIDResponse, UseOperation, UseOperations, soap,
    };
    use crate::use_id::service::{EIDService, EIDServiceConfig};
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use std::sync::Arc;
    use yaserde::de::from_str;

    fn create_test_service() -> Arc<EIDService> {
        Arc::new(EIDService::new(EIDServiceConfig {
            max_sessions: 10,
            session_timeout_minutes: 5,
            ecard_server_address: Some("https://test.eid.example.com/ecard".to_string()),
        }))
    }

    fn create_sample_soap_request() -> String {
        let request = UseIDRequest {
            use_operations: UseOperations {
                use_operations: vec![UseOperation {
                    id: "test_operation".to_string(),
                }],
            },
            age_verification_request: None,
            place_verification_request: None,
            transaction_info: None,
            transaction_attestation_request: None,
            level_of_assurance_request: None,
            eid_type_request: None,
            psk: Some(PSK {
                value: "test_psk".to_string(),
            }),
        };

        let envelope = soap::SoapEnvelope::<UseIDRequest>::new(request);
        yaserde::ser::to_string(&envelope).expect("Failed to serialize SOAP request")
    }

    #[tokio::test]
    async fn test_use_id_handler_valid_request() {
        let service = create_test_service();
        let soap_request = create_sample_soap_request();

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/useID")
            .header("content-type", "application/soap+xml")
            .body(Body::from(soap_request))
            .unwrap();

        let response = use_id_handler(
            State(service),
            request.headers().clone(),
            String::from_utf8(
                http_body_util::BodyExt::collect(request.into_body())
                    .await
                    .unwrap()
                    .to_bytes()
                    .to_vec(),
            )
            .unwrap(),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok());
        assert_eq!(content_type, Some("application/soap+xml; charset=utf-8"));

        let body_bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        let soap_response: soap::SoapEnvelope<UseIDResponse> = from_str(&body_str).unwrap();

        assert_eq!(
            soap_response.body.content.result.result_major,
            "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok"
        );
        assert!(soap_response.body.content.session.session_identifier.len() > 0);
        assert_eq!(soap_response.body.content.psk.unwrap().value, "test_psk");
    }

    #[tokio::test]
    async fn test_use_id_handler_invalid_content_type() {
        let service = create_test_service();
        let soap_request = create_sample_soap_request();

        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());

        let response = use_id_handler(State(service), headers, soap_request)
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let body_bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert_eq!(body_str, "Expected SOAP XML content type");
    }

    #[tokio::test]
    async fn test_use_id_handler_invalid_soap() {
        let service = create_test_service();
        let invalid_soap = "<invalid>xml</invalid>";

        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/soap+xml".parse().unwrap());

        let response = use_id_handler(State(service), headers, invalid_soap.to_string())
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body_str.contains("Failed to parse SOAP request"));
    }

    #[test]
    fn test_is_soap_content_type() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/soap+xml".parse().unwrap());
        assert!(is_soap_content_type(&headers));

        headers.insert("content-type", "text/xml".parse().unwrap());
        assert!(is_soap_content_type(&headers));

        headers.insert("content-type", "application/xml".parse().unwrap());
        assert!(is_soap_content_type(&headers));

        headers.insert("content-type", "application/json".parse().unwrap());
        assert!(!is_soap_content_type(&headers));

        let empty_headers = HeaderMap::new();
        assert!(!is_soap_content_type(&empty_headers));
    }
}
