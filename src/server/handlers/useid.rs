use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::sync::Arc;
use tracing::{debug, error};

use crate::{
    domain::eid::{
        models::use_id::{builder::build_use_id_response, parser::parse_use_id_request},
        ports::EidService,
    },
    server::AppState,
};

pub async fn use_id_handler<S: EidService>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    // Log the raw SOAP body for debugging
    debug!("Received raw SOAP body: {}", body);

    // Check content type
    if !is_soap_content_type(&headers) {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Expected SOAP XML content type".to_string(),
        )
            .into_response();
    }

    // Parse the SOAP request
    let use_id_request = match parse_use_id_request(&body) {
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

    // Process the request
    let response = match state.use_id.handle_use_id(use_id_request) {
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
    match build_use_id_response(&response) {
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
    use crate::{
        domain::eid::{
            models::use_id::model::{
                AgeVerificationRequest, PlaceVerificationRequest, UseIDRequest,
            },
            service::{EIDService, EIDServiceConfig},
        },
        eid::common::models::{AttributeRequester, OperationsRequester, ResultCode},
    };
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use http_body_util;
    use quick_xml::{Reader, events::Event};
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
            _use_operations: OperationsRequester {
                document_type: AttributeRequester::ALLOWED,
                issuing_state: AttributeRequester::ALLOWED,
                date_of_expiry: AttributeRequester::ALLOWED,
                given_names: AttributeRequester::ALLOWED,
                family_names: AttributeRequester::ALLOWED,
                artistic_name: AttributeRequester::ALLOWED,
                academic_title: AttributeRequester::ALLOWED,
                date_of_birth: AttributeRequester::ALLOWED,
                place_of_birth: AttributeRequester::ALLOWED,
                nationality: AttributeRequester::ALLOWED,
                birth_name: AttributeRequester::ALLOWED,
                place_of_residence: AttributeRequester::ALLOWED,
                community_id: None,
                residence_permit_id: None,
                restricted_id: AttributeRequester::ALLOWED,
                age_verification: AttributeRequester::ALLOWED,
                place_verification: AttributeRequester::ALLOWED,
            },
            _age_verification: AgeVerificationRequest { _age: 18 },
            _place_verification: PlaceVerificationRequest {
                _community_id: "".to_string(),
            },
            _transaction_info: None,
            _transaction_attestation_request: None,
            _level_of_assurance: None,
            _eid_type_request: None,
            _psk: None,
        };

        let response = service.handle_use_id(request).unwrap();

        assert_eq!(
            response.result.result_major,
            ResultCode::InvalidRequest.to_string()
        );
        assert_eq!(response.session.id, "");
    }

    #[test]
    fn test_generate_psk_length() {
        let service = create_test_service();
        let psk = service.generate_psk();
        assert_eq!(psk.len(), 32);
    }

    fn create_sample_soap_request() -> String {
        r#"
        <?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/">
            <soapenv:Body>
                <useIDRequest>
                    <UseOperations>
                        <eid:DocumentType>REQUIRED</eid:DocumentType>
                        <eid:IssuingState>REQUIRED</eid:IssuingState>
                        <eid:DateOfExpiry>REQUIRED</eid:DateOfExpiry>
                        <eid:GivenNames>REQUIRED</eid:GivenNames>
                        <eid:FamilyNames>REQUIRED</eid:FamilyNames>
                        <eid:ArtisticName>ALLOWED</eid:ArtisticName>
                        <eid:AcademicTitle>ALLOWED</eid:AcademicTitle>
                        <eid:DateOfBirth>REQUIRED</eid:DateOfBirth>
                        <eid:PlaceOfBirth>REQUIRED</eid:PlaceOfBirth>
                        <eid:Nationality>REQUIRED</eid:Nationality>
                        <eid:BirthName>REQUIRED</eid:BirthName>
                        <eid:PlaceOfResidence>REQUIRED</eid:PlaceOfResidence>
                        <eid:CommunityID>PROHIBITED</eid:CommunityID>
                        <eid:ResidencePermitI>PROHIBITED</eid:ResidencePermitI>
                        <eid:RestrictedID>REQUIRED</eid:RestrictedID>
                        <eid:AgeVerification>REQUIRED</eid:AgeVerification>
                        <eid:PlaceVerification>REQUIRED</eid:PlaceVerification>
                    </UseOperations>
                    <AgeVerificationRequest>
                        <eid:Age>18</eid:Age>
                    </AgeVerificationRequest>
                    <eid:PlaceVerificationRequest>
                        <eid:CommunityID>027605</eid:CommunityID>
                    </eid:PlaceVerificationRequest>
                    <eid:TransactionAttestationRequest>
                        <eid:TransactionAttestationFormat>http://bsi.bund.de/eID/ExampleAttestationFormat</eid:TransactionAttestationFormat>
                        <eid:TransactionContext>id599456-df</eid:TransactionContext>
                    </eid:TransactionAttestationRequest>
                    <eid:LevelOfAssuranceRequest>http://bsi.bund.de/eID/LoA/hoch</eid:LevelOfAssuranceRequest>
                    <eid:EIDTypeRequest>
                        <eid:SECertified>ALLOWED</eid:SECertified>
                        <eid:SEEndorsed>ALLOWED</eid:SEEndorsed>
                    </eid:EIDTypeRequest>
                </useIDRequest>
            </soapenv:Body>
        </soapenv:Envelope>
        "#.to_string()
    }

    #[tokio::test]
    async fn test_use_id_handler_valid_request() {
        let service = create_test_service();
        let state = Arc::new(AppState {
            use_id: Arc::new(service),
        });
        let soap_request = create_sample_soap_request();

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/useID")
            .header("content-type", "application/soap+xml")
            .body(Body::from(soap_request))
            .unwrap();

        let response = use_id_handler(
            State(state),
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

        // Check status and print debug info if not OK
        let status = response.status();
        if status != StatusCode::OK {
            let body_bytes = http_body_util::BodyExt::collect(response.into_body())
                .await
                .unwrap()
                .to_bytes();
            let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
            eprintln!("Response status: {status}, body: {body_str}");
            panic!("Expected 200 OK, got {status}");
        }

        // Proceed with remaining assertions
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

        // Parse the XML manually to extract required fields
        let mut reader = Reader::from_str(&body_str);
        reader.config_mut().trim_text(true);
        let mut buf = Vec::new();
        let mut result_major = None;
        let mut session_id = None;
        let mut psk_key = None;
        let mut current_tag = String::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    current_tag = String::from_utf8(e.name().as_ref().to_vec()).unwrap();
                }
                Ok(Event::Text(e)) => {
                    let text = e.unescape().unwrap().into_owned();
                    match current_tag.as_str() {
                        "ResultMajor" => {
                            // Map the response URI to ResultCode::Ok
                            if text == "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok" {
                                result_major = Some(ResultCode::Ok.to_string());
                            } else {
                                result_major = Some(text);
                            }
                        }
                        "eid:ID" => {
                            if psk_key.is_none() {
                                // Assume eid:ID under eid:Session
                                session_id = Some(text);
                            }
                        }
                        "eid:Key" => psk_key = Some(text),
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => panic!(
                    "Error parsing XML at position {}: {:?}",
                    reader.buffer_position(),
                    e
                ),
                _ => {}
            }
            buf.clear();
        }

        // Verify the extracted fields
        assert_eq!(result_major, Some(ResultCode::Ok.to_string()));
        assert!(session_id.is_some() && !session_id.unwrap().is_empty());
        // Since request omits Psk, handler generates a random 32-char PSK
        assert!(psk_key.is_some() && psk_key.unwrap().len() == 32);
    }

    #[tokio::test]
    async fn test_use_id_handler_invalid_content_type() {
        let service = create_test_service();
        let state = Arc::new(AppState {
            use_id: Arc::new(service),
        });
        let soap_request = create_sample_soap_request();

        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());

        let response = use_id_handler(State(state), headers, soap_request)
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
        let state = Arc::new(AppState {
            use_id: Arc::new(service),
        });
        let invalid_soap = "<invalid>xml</invalid>";

        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/soap+xml".parse().unwrap());

        let response = use_id_handler(State(state), headers, invalid_soap.to_string())
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
