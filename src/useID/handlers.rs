
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::sync::Arc;
use tracing::{debug, error};

use crate::useID::models::{soap, UseIDRequest};

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

    debug!("Received UseID request with {} operations", 
           use_id_request.use_operations.use_operations.len());

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
    headers.insert("Content-Type", "application/soap+xml; charset=utf-8".parse().unwrap());
    headers
}