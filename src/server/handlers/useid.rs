use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::{Duration, Utc};
use rand::{Rng, distr::Alphanumeric};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};
use uuid::Uuid;

use crate::domain::eid::models::useid::{
    PSK, ResultStatus, Session, UseIDRequest, UseIDResponse, soap,
};

/// Configuration for the eID Service
#[derive(Clone, Debug)] // Added Debug
pub struct EIDServiceConfig {
    /// Maximum number of concurrent sessions
    pub max_sessions: usize,
    /// Session timeout in minutes
    pub session_timeout_minutes: i64,
    /// Optional eCard server address to return in responses
    pub ecard_server_address: Option<String>,
}

impl Default for EIDServiceConfig {
    fn default() -> Self {
        Self {
            max_sessions: 1000,
            session_timeout_minutes: 5,
            ecard_server_address: None,
        }
    }
}

/// Session information stored by the server
#[derive(Clone, Debug)]
pub struct SessionInfo {
    pub id: String,
    pub expiry: chrono::DateTime<Utc>,
    pub psk: Option<String>,
    pub operations: Vec<String>,
}

/// Main service for handling useID requests
#[derive(Clone, Debug)]
pub struct EIDService {
    config: EIDServiceConfig,
    sessions: Arc<RwLock<Vec<SessionInfo>>>,
}

impl EIDService {
    pub fn new(config: EIDServiceConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Handle a useID request according to TR-03130
    pub async fn handle_use_id(&self, request: UseIDRequest) -> Result<UseIDResponse> {
        // Validate the request
        if request.use_operations.use_operations.is_empty() {
            return Ok(UseIDResponse {
                result: ResultStatus::error(
                    "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/parameterError",
                    Some("UseOperations must contain at least one operation"),
                ),
                session: Session {
                    session_identifier: "".to_string(),
                    timeout: "0".to_string(),
                },
                ecard_server_address: None,
                psk: None,
            });
        }

        // Check if we've reached the maximum number of sessions
        if self.sessions.read().await.len() >= self.config.max_sessions {
            return Ok(UseIDResponse {
                result: ResultStatus::error(
                    "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/tooManySessions",
                    Some("Maximum number of sessions reached"),
                ),
                session: Session {
                    session_identifier: "".to_string(),
                    timeout: "0".to_string(),
                },
                ecard_server_address: None,
                psk: None,
            });
        }

        // Generate a session ID
        let session_id = Uuid::new_v4().to_string();

        // Generate or use provided PSK
        let psk = match &request.psk {
            Some(psk) => psk.value.clone(),
            None => self.generate_psk(),
        };

        // Calculate session expiry time
        let expiry = Utc::now() + Duration::minutes(self.config.session_timeout_minutes);

        // Create session info
        let session_info = SessionInfo {
            id: session_id.clone(),
            expiry,
            psk: Some(psk.clone()),
            operations: request
                .use_operations
                .use_operations
                .iter()
                .map(|op| op.id.clone())
                .collect(),
        };

        // Store the session
        {
            let mut sessions = self.sessions.write().await;

            // Remove expired sessions first
            let now = Utc::now();
            sessions.retain(|session| session.expiry > now);

            // Add new session
            sessions.push(session_info.clone());

            info!(
                "Created new session: {}, expires: {}, operations: {:?}",
                session_id, expiry, session_info.operations
            );
        }

        // Build response
        Ok(UseIDResponse {
            result: ResultStatus::success(),
            session: Session {
                session_identifier: session_id,
                timeout: expiry.to_rfc3339(),
            },
            ecard_server_address: self.config.ecard_server_address.clone(),
            psk: Some(PSK { value: psk }),
        })
    }

    /// Generate a random PSK for secure communication
    fn generate_psk(&self) -> String {
        // Generate a 32-character random PSK
        rand::rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }

    /// Clean up expired sessions (can be called periodically)
    pub async fn cleanup_expired_sessions(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let before_count = sessions.len();
        let now = Utc::now();
        sessions.retain(|session| session.expiry > now);
        let removed = before_count - sessions.len();

        if removed > 0 {
            info!("Removed {} expired sessions", removed);
        }

        removed
    }

    /// Get a session by ID
    pub async fn get_session(&self, session_id: &str) -> Option<SessionInfo> {
        let sessions = self.sessions.read().await;
        let now = Utc::now();

        sessions
            .iter()
            .find(|s| s.id == session_id && s.expiry > now)
            .cloned()
    }
}

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
    let use_id_request = match soap::deserialize_soap_request(&body) {
        Ok(request) => request,
        Err(err) => {
            error!("Failed to parse SOAP request: {}", err);
            return (
                StatusCode::BAD_REQUEST,
                format!("Failed to parse SOAP request: {err}"),
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

// ---- Tests Section ----

#[cfg(test)]
mod tests {
    use crate::domain::eid::models::useid::{SoapEnvelope, UseOperation, UseOperations};

    use super::*;

    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use http_body_util;
    use quick_xml::de::from_str;
    use std::sync::Arc;

    fn create_test_service() -> EIDService {
        EIDService::new(EIDServiceConfig {
            max_sessions: 10,
            session_timeout_minutes: 5,
            ecard_server_address: Some("https://test.eid.example.com/ecard".to_string()),
        })
    }

    #[tokio::test]
    async fn test_handle_use_id_empty_operations() {
        let service = create_test_service();
        let request = UseIDRequest {
            use_operations: UseOperations {
                use_operations: vec![],
            },
            age_verification_request: None,
            place_verification_request: None,
            transaction_info: None,
            transaction_attestation_request: None,
            level_of_assurance_request: None,
            eid_type_request: None,
            psk: None,
        };

        let response = service.handle_use_id(request).await.unwrap();

        assert_eq!(
            response.result.result_major,
            "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error"
        );
        assert_eq!(
            response.result.result_minor.unwrap(),
            "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/parameterError"
        );
        assert_eq!(response.session.session_identifier, "");
        assert_eq!(response.session.timeout, "0");
    }

    #[tokio::test]
    async fn test_handle_use_id_max_sessions() {
        let service = create_test_service();

        // Fill up sessions
        for _ in 0..10 {
            let request = UseIDRequest {
                use_operations: UseOperations {
                    use_operations: vec![UseOperation {
                        id: "test".to_string(),
                    }],
                },
                age_verification_request: None,
                place_verification_request: None,
                transaction_info: None,
                transaction_attestation_request: None,
                level_of_assurance_request: None,
                eid_type_request: None,
                psk: None,
            };
            service.handle_use_id(request).await.unwrap();
        }

        // Try one more request
        let request = UseIDRequest {
            use_operations: UseOperations {
                use_operations: vec![UseOperation {
                    id: "test".to_string(),
                }],
            },
            age_verification_request: None,
            place_verification_request: None,
            transaction_info: None,
            transaction_attestation_request: None,
            level_of_assurance_request: None,
            eid_type_request: None,
            psk: None,
        };

        let response = service.handle_use_id(request).await.unwrap();

        assert_eq!(
            response.result.result_major,
            "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error"
        );
        assert_eq!(
            response.result.result_minor.unwrap(),
            "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/tooManySessions"
        );
    }

    #[tokio::test]
    async fn test_session_cleanup() {
        let config = EIDServiceConfig {
            max_sessions: 10,
            session_timeout_minutes: -1, // Expired immediately
            ecard_server_address: None,
        };
        let service = EIDService::new(config);

        // Create a session
        let request = UseIDRequest {
            use_operations: UseOperations {
                use_operations: vec![UseOperation {
                    id: "test".to_string(),
                }],
            },
            age_verification_request: None,
            place_verification_request: None,
            transaction_info: None,
            transaction_attestation_request: None,
            level_of_assurance_request: None,
            eid_type_request: None,
            psk: None,
        };
        let response = service.handle_use_id(request).await.unwrap();

        let session_id = response.session.session_identifier;
        assert!(!session_id.is_empty());

        // Clean up
        let removed = service.cleanup_expired_sessions().await;
        assert_eq!(removed, 1);

        // Verify session is gone
        let session = service.get_session(&session_id).await;
        assert!(session.is_none());
    }

    #[test]
    fn test_generate_psk_length() {
        let service = create_test_service();
        let psk = service.generate_psk();
        assert_eq!(psk.len(), 32);
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

        let envelope = SoapEnvelope::new(request);
        quick_xml::se::to_string(&envelope).expect("Failed to serialize SOAP request")
    }

    #[tokio::test]
    async fn test_use_id_handler_valid_request() {
        let service = Arc::new(create_test_service());
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
        let soap_response: SoapEnvelope<UseIDResponse> = from_str(&body_str).unwrap();

        assert_eq!(
            soap_response.body.content.result.result_major,
            "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok"
        );
        assert!(
            !soap_response
                .body
                .content
                .session
                .session_identifier
                .is_empty()
        );
        assert_eq!(soap_response.body.content.psk.unwrap().value, "test_psk");
    }

    #[tokio::test]
    async fn test_use_id_handler_invalid_content_type() {
        let service = Arc::new(create_test_service());
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
        let service = Arc::new(create_test_service());
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
