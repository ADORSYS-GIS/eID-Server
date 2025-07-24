use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::Utc;
use std::sync::Arc;
use tracing::{debug, error, info};

use crate::{
    domain::eid::ports::{EIDService, EidService},
    eid::get_result::{
        builder::build_get_result_response,
        error::GetResultError,
        model::{GetResultRequest, GetResultResponse},
        parser::parse_get_result_request,
    },
    server::AppState,
};

/// Handler for getResult requests
pub async fn get_result_handler<S: EIDService + EidService>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    debug!("Received get_result request");
    debug!("Headers: {:?}", headers);
    debug!("Body: {}", body);

    // Validate content type
    if !is_soap_content_type(&headers) {
        error!("Invalid content type for SOAP request");
        return (
            StatusCode::BAD_REQUEST,
            create_soap_response_headers(),
            "Invalid content type. Expected application/soap+xml or text/xml".to_string(),
        );
    }

    // Parse the request
    let request = match parse_get_result_request(&body) {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to parse get_result request: {:?}", e);
            return (
                StatusCode::BAD_REQUEST,
                create_soap_response_headers(),
                format!("Failed to parse request: {e}"),
            );
        }
    };

    debug!("Parsed request: {:?}", request);

    // Handle session management and validation in the handler layer (HTTP-specific concerns)
    let response = match get_result(&state.eid_service, request) {
        Ok(resp) => resp,
        Err(e) => {
            error!("Handler error: {:?}", e);
            return handle_get_result_error(e);
        }
    };

    // Build the XML response
    match build_get_result_response(response) {
        Ok(xml) => {
            info!("Successfully processed get_result request");
            (StatusCode::OK, create_soap_response_headers(), xml)
        }
        Err(e) => {
            error!("Failed to build response: {e:?}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                create_soap_response_headers(),
                format!("Failed to build response: {e}"),
            )
        }
    }
}

/// Handle get_result specific errors
fn handle_get_result_error(error: GetResultError) -> (StatusCode, HeaderMap, String) {
    let (status, error_message) = match error {
        GetResultError::NoResultYet => (
            StatusCode::ACCEPTED,
            "Result not available yet. Try again later.".to_string(),
        ),
        GetResultError::InvalidSession => (
            StatusCode::BAD_REQUEST,
            "Session expired or already used and deleted.".to_string(),
        ),
        GetResultError::InvalidRequestCounter => (
            StatusCode::BAD_REQUEST,
            "RequestCounter is invalid or reused.".to_string(),
        ),
        GetResultError::DeniedDocument => (
            StatusCode::FORBIDDEN,
            "eID Type not allowed or insufficient assurance level.".to_string(),
        ),
        GetResultError::InvalidDocument => (
            StatusCode::BAD_REQUEST,
            "Document failed validity check.".to_string(),
        ),
        GetResultError::GenericError(msg) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Internal error: {msg}"),
        ),
    };

    (status, create_soap_response_headers(), error_message)
}

/// Check if the request has a valid SOAP content type
fn is_soap_content_type(headers: &HeaderMap) -> bool {
    if let Some(content_type) = headers.get("content-type") {
        if let Ok(content_type_str) = content_type.to_str() {
            return content_type_str.contains("application/soap+xml")
                || content_type_str.contains("text/xml");
        }
    }
    false
}

/// Create appropriate headers for SOAP responses
fn create_soap_response_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(content_type) = "application/soap+xml; charset=utf-8".parse() {
        headers.insert("content-type", content_type);
    }
    headers
}

/// Handle get_result with proper separation of concerns
/// This function handles HTTP-specific concerns (session management, request validation)
/// while delegating external component interactions to the service layer
fn get_result<S: EIDService + EidService>(
    service: &Arc<S>,
    request: GetResultRequest,
) -> Result<GetResultResponse, GetResultError> {
    debug!(
        "Handler managing get_result request for session: {}",
        request.session.id
    );

    // Session management
    let mut sessions = service.get_sessions().write().map_err(|e| {
        GetResultError::GenericError(format!("Failed to acquire session write lock: {e}"))
    })?;
    let now = Utc::now();

    // Clean up expired sessions
    sessions.retain(|session| session.expiry > now);

    // Find the session
    let session_index = sessions
        .iter()
        .position(|s| s.id == request.session.id)
        .ok_or(GetResultError::InvalidSession)?;

    let session = &mut sessions[session_index];

    // Validate request counter
    let expected_counter = session.request_counter + 1;
    if request.request_counter != expected_counter {
        return Err(GetResultError::InvalidRequestCounter);
    }

    // Update request counter
    session.request_counter = request.request_counter;

    // Check if authentication is completed
    if !session.authentication_completed {
        return Err(GetResultError::NoResultYet);
    }

    // Get authentication data
    let authentication_data =
        session
            .authentication_data
            .as_ref()
            .ok_or(GetResultError::GenericError(
                "No authentication data available".to_string(),
            ))?;

    let response = service.create_get_result_response_from_data(authentication_data)?;

    // Session cleanup
    sessions.remove(session_index);

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::eid::service::{EIDServiceConfig, UseidService};
    use axum::http::HeaderValue;

    fn create_test_state() -> AppState<UseidService> {
        let config = EIDServiceConfig::default();
        let service = UseidService::new(config);
        AppState {
            use_id: std::sync::Arc::new(service.clone()),
            eid_service: std::sync::Arc::new(service),
        }
    }

    #[tokio::test]
    async fn test_get_result_handler_invalid_content_type() {
        let state = create_test_state();
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        let body = "test".to_string();

        let response = get_result_handler(State(state), headers, body).await;
        let (parts, _) = response.into_response().into_parts();
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_result_handler_invalid_xml() {
        let state = create_test_state();
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/soap+xml"),
        );
        let body = "invalid xml".to_string();

        let response = get_result_handler(State(state), headers, body).await;
        let (parts, _) = response.into_response().into_parts();
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_is_soap_content_type_valid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/soap+xml"),
        );
        assert!(is_soap_content_type(&headers));

        headers.clear();
        headers.insert("content-type", HeaderValue::from_static("text/xml"));
        assert!(is_soap_content_type(&headers));
    }

    #[test]
    fn test_is_soap_content_type_invalid() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        assert!(!is_soap_content_type(&headers));

        let empty_headers = HeaderMap::new();
        assert!(!is_soap_content_type(&empty_headers));
    }
}
