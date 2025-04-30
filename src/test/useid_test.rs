#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use eid_server::useID::{
        models::{soap, Result, Session, UseIDRequest, UseIDResponse, UseOperation, UseOperations, PSK},
        service::{EIDService, EIDServiceConfig, SessionInfo},
    };
    use std::sync::Arc;
    use tower::ServiceExt;
    use yaserde::ser::to_string;

    // Helper function to create a test service
    fn create_test_service() -> Arc<EIDService> {
        let config = EIDServiceConfig {
            max_sessions: 10,
            session_timeout_minutes: 5,
            ecard_server_address: Some("https://test.eid.example.com/ecard".to_string()),
        };
        Arc::new(EIDService::new(config))
    }

    // Helper function to create a sample SOAP request
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
        
        let envelope = soap::SoapEnvelope::new(request);
        to_string(&envelope).expect("Failed to serialize SOAP request")
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

        let app = Router::new()
            .route("/eIDService/useID", post(use_id_handler))
            .with_state(service);

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        
        let content_type = response.headers().get("content-type")
            .and_then(|v| v.to_str().ok());
        assert_eq!(content_type, Some("application/soap+xml; charset=utf-8"));

        let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        let soap_response: soap::SoapEnvelope<UseIDResponse> = 
            yaserde::de::from_str(&body_str).unwrap();
        
        assert_eq!(soap_response.body.content.result.result_major, 
            "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok");
        assert!(soap_response.body.content.session.session_identifier.len() > 0);
        assert_eq!(soap_response.body.content.psk.unwrap().value, "test_psk");
    }

    #[tokio::test]
    async fn test_use_id_handler_invalid_content_type() {
        let service = create_test_service();
        let soap_request = create_sample_soap_request();

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/useID")
            .header("content-type", "application/json")
            .body(Body::from(soap_request))
            .unwrap();

        let app = Router::new()
            .route("/eIDService/useID", post(use_id_handler))
            .with_state(service);

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        
        let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert_eq!(body_str, "Expected SOAP XML content type");
    }

    #[tokio::test]
    async fn test_use_id_handler_invalid_soap() {
        let service = create_test_service();
        let invalid_soap = "<invalid>xml</invalid>";

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/useID")
            .header("content-type", "application/soap+xml")
            .body(Body::from(invalid_soap))
            .unwrap();

        let app = Router::new()
            .route("/eIDService/useID", post(use_id_handler))
            .with_state(service);

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        
        let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body_str.contains("Failed to parse SOAP request"));
    }

    #[tokio::test]
    async fn test_eid_service_empty_operations() {
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

        assert_eq!(response.result.result_major, 
            "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error");
        assert_eq!(response.result.result_minor.unwrap(), 
            "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/parameterError");
        assert_eq!(response.session.session_identifier, "");
        assert_eq!(response.session.timeout, "0");
    }

    #[tokio::test]
    async fn test_eid_service_max_sessions() {
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

        assert_eq!(response.result.result_major, 
            "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error");
        assert_eq!(response.result.result_minor.unwrap(), 
            "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/tooManySessions");
    }

    #[tokio::test]
    async fn test_session_cleanup() {
        let config = EIDServiceConfig {
            max_sessions: 10,
            session_timeout_minutes: -1, // Expired immediately
            ecard_server_address: None,
        };
        let service = Arc::new(EIDService::new(config));

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

    #[tokio::test]
    async fn test_soap_serialization_deserialization() {
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

        let serialized = soap::serialize_soap_response(request.clone()).unwrap();
        let deserialized = soap::deserialize_soap_request::<UseIDRequest>(&serialized).unwrap();

        assert_eq!(request.use_operations.use_operations[0].id, 
            deserialized.use_operations.use_operations[0].id);
        assert_eq!(request.psk.unwrap().value, 
            deserialized.psk.unwrap().value);
    }
}