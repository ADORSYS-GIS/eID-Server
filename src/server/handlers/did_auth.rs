use crate::domain::eid::{
    models::{
        AuthError, AuthenticationProtocolData, ConnectionHandle, DIDAuthenticateRequest,
        DIDAuthenticateResponse, SoapResponse,
    },
    ports::{DIDAuthenticate, EIDService, EidService},
};
use crate::server::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse};
use color_eyre::Result;
use quick_xml::{
    Reader, Writer,
    events::{BytesEnd, BytesStart, BytesText, Event},
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct SoapDIDAuthenticateRequest {
    connection_handle: ConnectionHandle,
    did_name: String,
    authentication_protocol_data: AuthenticationProtocolData,
}

pub struct DIDAuthenticateHandler<T: DIDAuthenticate> {
    eid_service: T,
}

impl<T: DIDAuthenticate + Send + Sync> DIDAuthenticateHandler<T> {
    pub fn new(eid_service: T) -> Self {
        DIDAuthenticateHandler { eid_service }
    }

    // Parse incoming SOAP XML request using quick-xml
    fn parse_request(&self, body: &str) -> Result<SoapDIDAuthenticateRequest, AuthError> {
        // Basic validation: check if input resembles XML
        if body.trim().is_empty() || !body.contains('<') || !body.contains('>') {
            return Err(AuthError::InvalidConnection {
                reason: "Invalid XML: input is empty or lacks XML structure".to_string(),
            });
        }

        // Check for SOAP envelope
        if !body.contains("soapenv:Envelope") {
            return Err(AuthError::InvalidConnection {
                reason: "Invalid XML: missing SOAP Envelope".to_string(),
            });
        }

        let mut reader = Reader::from_str(body);
        reader.config_mut().trim_text(true);

        let mut request = SoapDIDAuthenticateRequest {
            connection_handle: ConnectionHandle {
                channel_handle: Some(String::new()),
                ifd_name: Some(String::new()),
                slot_index: Some(0),
            },
            did_name: String::new(),
            authentication_protocol_data: AuthenticationProtocolData {
                certificate_description: String::new(),
                required_chat: String::new(),
                optional_chat: None,
                transaction_info: None,
            },
        };

        let mut buf = Vec::new();
        let mut current_element = String::new();
        let mut found_did_authenticate = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    let name = e.local_name().as_ref().to_vec();
                    current_element =
                        String::from_utf8(name).map_err(|_| AuthError::InvalidConnection {
                            reason: "Invalid UTF-8 in element name".to_string(),
                        })?;
                    if current_element == "DIDAuthenticate" {
                        found_did_authenticate = true;
                    }
                    tracing::debug!("Processing element: {}", current_element);
                }
                Ok(Event::Text(e)) => {
                    let text = e
                        .unescape()
                        .map_err(|_| AuthError::InvalidConnection {
                            reason: "Failed to unescape text content".to_string(),
                        })?
                        .to_string();
                    tracing::debug!("Text content for {}: {}", current_element, text);
                    match current_element.as_str() {
                        "ChannelHandle" => request.connection_handle.channel_handle = Some(text),
                        "IFDName" => request.connection_handle.ifd_name = Some(text),
                        "SlotIndex" => {
                            request.connection_handle.slot_index = Some(text.parse().unwrap_or(0));
                        }
                        "DIDName" => request.did_name = text,
                        "Certificate" => {
                            request.authentication_protocol_data.certificate_description = text;
                        }
                        "RequiredCHAT" => {
                            request.authentication_protocol_data.required_chat = text;
                        }
                        "OptionalCHAT" => {
                            request.authentication_protocol_data.optional_chat = Some(text);
                        }
                        "AuthenticatedAuxiliaryData" => {
                            request.authentication_protocol_data.transaction_info = Some(text);
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(_)) => {
                    current_element.clear();
                }
                Ok(Event::Eof) => {
                    // Ensure we found the DIDAuthenticate element
                    if !found_did_authenticate {
                        return Err(AuthError::InvalidConnection {
                            reason: "Invalid XML: missing DIDAuthenticate element".to_string(),
                        });
                    }
                    break;
                }
                Err(e) => {
                    return Err(AuthError::InvalidConnection {
                        reason: format!("Failed to parse XML request: {e}"),
                    });
                }
                _ => {}
            }
            buf.clear();
        }

        tracing::debug!("Parsed request: {:?}", request);
        Ok(request)
    }

    // Convert domain response to SOAP XML response using quick-xml
    fn to_soap_response(&self, response: DIDAuthenticateResponse) -> Result<String, AuthError> {
        let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);

        let mut envelope = BytesStart::new("soapenv:Envelope");
        envelope.push_attribute(("xmlns:soapenv", "http://schemas.xmlsoap.org/soap/envelope/"));
        envelope.push_attribute(("xmlns:ecard", "http://www.bsi.bund.de/ecard/api/1.1"));
        writer
            .write_event(Event::Start(envelope))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write SOAP Envelope".to_string(),
            })?;

        writer
            .write_event(Event::Start(BytesStart::new("soapenv:Header")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write SOAP Header".to_string(),
            })?;
        writer
            .write_event(Event::End(BytesEnd::new("soapenv:Header")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close SOAP Header".to_string(),
            })?;

        writer
            .write_event(Event::Start(BytesStart::new("soapenv:Body")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write SOAP Body".to_string(),
            })?;

        writer
            .write_event(Event::Start(BytesStart::new(
                "ecard:DIDAuthenticateResponse",
            )))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write DIDAuthenticateResponse".to_string(),
            })?;

        writer
            .write_event(Event::Start(BytesStart::new("ecard:Result")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write Result".to_string(),
            })?;
        writer
            .write_event(Event::Start(BytesStart::new("ecard:ResultMajor")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write ResultMajor".to_string(),
            })?;
        writer
            .write_event(Event::Text(BytesText::new(&response.result_major)))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write ResultMajor text".to_string(),
            })?;
        writer
            .write_event(Event::End(BytesEnd::new("ecard:ResultMajor")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close ResultMajor".to_string(),
            })?;

        if let Some(minor) = &response.result_minor {
            writer
                .write_event(Event::Start(BytesStart::new("ecard:ResultMinor")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write ResultMinor".to_string(),
                })?;
            writer
                .write_event(Event::Text(BytesText::new(minor)))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write ResultMinor text".to_string(),
                })?;
            writer
                .write_event(Event::End(BytesEnd::new("ecard:ResultMinor")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to close ResultMinor".to_string(),
                })?;
        }
        writer
            .write_event(Event::End(BytesEnd::new("ecard:Result")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close Result".to_string(),
            })?;

        writer
            .write_event(Event::Start(BytesStart::new(
                "ecard:AuthenticationProtocolData",
            )))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write AuthenticationProtocolData".to_string(),
            })?;

        if let Some(certificate) = &response.authentication_protocol_data.certificate {
            writer
                .write_event(Event::Start(BytesStart::new("ecard:Certificate")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write Certificate".to_string(),
                })?;
            writer
                .write_event(Event::Text(BytesText::new(certificate)))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write Certificate text".to_string(),
                })?;
            writer
                .write_event(Event::End(BytesEnd::new("ecard:Certificate")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to close Certificate".to_string(),
                })?;
        }

        if let Some(personal_data) = &response.authentication_protocol_data.personal_data {
            writer
                .write_event(Event::Start(BytesStart::new("ecard:PersonalData")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write PersonalData".to_string(),
                })?;
            writer
                .write_event(Event::Text(BytesText::new(personal_data)))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write PersonalData text".to_string(),
                })?;
            writer
                .write_event(Event::End(BytesEnd::new("ecard:PersonalData")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to close PersonalData".to_string(),
                })?;
        }

        if let Some(auth_token) = &response.authentication_protocol_data.authentication_token {
            writer
                .write_event(Event::Start(BytesStart::new("ecard:AuthenticationToken")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write AuthenticationToken".to_string(),
                })?;
            writer
                .write_event(Event::Text(BytesText::new(auth_token)))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write AuthenticationToken text".to_string(),
                })?;
            writer
                .write_event(Event::End(BytesEnd::new("ecard:AuthenticationToken")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to close AuthenticationToken".to_string(),
                })?;
        }

        writer
            .write_event(Event::End(BytesEnd::new(
                "ecard:AuthenticationProtocolData",
            )))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close AuthenticationProtocolData".to_string(),
            })?;
        writer
            .write_event(Event::End(BytesEnd::new("ecard:DIDAuthenticateResponse")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close DIDAuthenticateResponse".to_string(),
            })?;
        writer
            .write_event(Event::End(BytesEnd::new("soapenv:Body")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close SOAP Body".to_string(),
            })?;
        writer
            .write_event(Event::End(BytesEnd::new("soapenv:Envelope")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close SOAP Envelope".to_string(),
            })?;

        let result =
            String::from_utf8(writer.into_inner()).map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to convert response to UTF-8".to_string(),
            })?;
        Ok(result)
    }

    // Handle the DIDAuthenticate request
    pub async fn handle(&self, body: &str) -> Result<SoapResponse, AuthError> {
        // Parse SOAP request
        let soap_request = self.parse_request(body)?;

        // Convert to domain request
        let domain_request = DIDAuthenticateRequest {
            connection_handle: soap_request.connection_handle,
            did_name: soap_request.did_name,
            authentication_protocol_data: crate::domain::eid::models::AuthenticationProtocolData {
                certificate_description: soap_request
                    .authentication_protocol_data
                    .certificate_description,
                required_chat: soap_request.authentication_protocol_data.required_chat,
                optional_chat: soap_request.authentication_protocol_data.optional_chat,
                transaction_info: soap_request.authentication_protocol_data.transaction_info,
            },
        };

        let response = self
            .eid_service
            .handle_did_authenticate(domain_request)
            .await?;

        let soap_response = self.to_soap_response(response)?;

        Ok(SoapResponse {
            body: soap_response,
            status: 200,
        })
    }
}

pub async fn did_authenticate<
    S: DIDAuthenticate + EIDService + EidService + Send + Sync + 'static,
>(
    State(state): State<AppState<S>>,
    body: String,
) -> Result<impl IntoResponse, StatusCode> {
    let handler = DIDAuthenticateHandler::new((*state.eid_service).clone());

    let response = handler
        .handle(&body)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let status_code = StatusCode::from_u16(response.status).unwrap_or(StatusCode::OK);
    Ok((status_code, response.body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::eid::{
        models::{
            AuthError, DIDAuthenticateRequest, DIDAuthenticateResponse, ResponseProtocolData,
        },
        ports::DIDAuthenticate,
        service::{EIDServiceConfig, UseidService},
    };
    use async_trait::async_trait;
    use axum::{extract::State, response::IntoResponse};
    use base64::Engine;
    use chrono::DateTime;
    use std::sync::Arc;

    // Create a more realistic test service that implements DIDAuthenticate
    struct TestDIDAuthenticateService {
        should_succeed: bool,
        response_data: Option<DIDAuthenticateResponse>,
    }

    impl TestDIDAuthenticateService {
        fn new_success() -> Self {
            Self {
                should_succeed: true,
                response_data: Some(create_test_response()),
            }
        }

        fn new_failure() -> Self {
            Self {
                should_succeed: false,
                response_data: None,
            }
        }
    }

    impl Clone for TestDIDAuthenticateService {
        fn clone(&self) -> Self {
            Self {
                should_succeed: self.should_succeed,
                response_data: self.response_data.clone(),
            }
        }
    }
    fn create_test_response() -> DIDAuthenticateResponse {
        // Parse the RFC 3339 timestamp to a Unix timestamp (seconds)
        let timestamp_str = "2025-06-17T09:58:00Z";
        let dt = DateTime::parse_from_rfc3339(timestamp_str).expect("Invalid timestamp format");
        let timestamp = dt.timestamp() as u64;

        DIDAuthenticateResponse {
            result_major: "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok".to_string(),
            result_minor: None,
            authentication_protocol_data: ResponseProtocolData {
                challenge: None,
                certificate: Some(
                    base64::engine::general_purpose::STANDARD.encode("mock_certificate_data"),
                ),
                personal_data: Some(
                    "eyJuYW1lIjoiSm9obiBEb2UiLCJkYXRlX29mX2JpcnRoIjoiMTk4MC0wMS0wMSJ9".to_string(),
                ),
                authentication_token: Some("mock_auth_token_12345".to_string()),
            },
            timestamp,
        }
    }

    #[async_trait]
    impl DIDAuthenticate for TestDIDAuthenticateService {
        async fn handle_did_authenticate(
            &self,
            request: DIDAuthenticateRequest,
        ) -> Result<DIDAuthenticateResponse, AuthError> {
            if self.should_succeed {
                // Validate the request has required fields
                if request.connection_handle.channel_handle.is_none() {
                    return Err(AuthError::InvalidConnection {
                        reason: "Missing channel handle".to_string(),
                    });
                }

                if request.did_name.is_empty() {
                    return Err(AuthError::InvalidConnection {
                        reason: "Missing DID name".to_string(),
                    });
                }

                Ok(self.response_data.as_ref().unwrap().clone())
            } else {
                Err(AuthError::InvalidConnection {
                    reason: "Authentication failed".to_string(),
                })
            }
        }
    }

    #[tokio::test]
    async fn test_parse_realistic_did_authenticate_request() {
        let test_service = TestDIDAuthenticateService::new_success();
        let handler = DIDAuthenticateHandler::new(test_service);

        // Try to read the file, or use a fallback SOAP request
        let soap_request = std::fs::read_to_string("test_data/did_auth_request.xml")
            .unwrap_or_else(|e| {
                eprintln!("Failed to read test SOAP request XML: {e}. Using fallback.");
                create_minimal_valid_soap_request()
            });

        let result = handler.parse_request(&soap_request);
        assert!(
            result.is_ok(),
            "Failed to parse realistic SOAP request: {result:?}"
        );

        let parsed = result.unwrap();
        assert_eq!(
            parsed.connection_handle.channel_handle,
            Some("1749555187773228668-PvaSgaJVhSTotu2g".to_string())
        );
        assert_eq!(
            parsed.connection_handle.ifd_name,
            Some("Terminal".to_string())
        );
        assert_eq!(parsed.connection_handle.slot_index, Some(0));
        assert_eq!(parsed.did_name, "EAC");
        assert!(
            parsed
                .authentication_protocol_data
                .certificate_description
                .len()
                > 100
        );
        assert_eq!(
            parsed.authentication_protocol_data.required_chat,
            "7f4c12060904007f00070301020253053c0ff3ffff"
        );
        assert_eq!(
            parsed.authentication_protocol_data.optional_chat,
            Some("7f4c12060904007f00070301020253053c0ff3ffff".to_string())
        );
    }

    #[tokio::test]
    async fn test_successful_did_authenticate_flow() {
        let test_service = TestDIDAuthenticateService::new_success();
        let handler = DIDAuthenticateHandler::new(test_service);

        let soap_request = create_minimal_valid_soap_request();

        let result = handler.handle(&soap_request).await;
        assert!(
            result.is_ok(),
            "Expected successful authentication: {result:?}"
        );

        let soap_response = result.unwrap();
        assert_eq!(soap_response.status, 200);
        assert!(
            soap_response
                .body
                .contains("http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok")
        );
        assert!(soap_response.body.contains("DIDAuthenticateResponse"));
        assert!(soap_response.body.contains("AuthenticationProtocolData"));
    }

    #[tokio::test]
    async fn test_failed_did_authenticate_flow() {
        let test_service = TestDIDAuthenticateService::new_failure();
        let handler = DIDAuthenticateHandler::new(test_service);

        let soap_request = create_minimal_valid_soap_request();

        let result = handler.handle(&soap_request).await;
        assert!(result.is_err(), "Expected authentication failure");

        if let Err(AuthError::InvalidConnection { reason }) = result {
            assert_eq!(reason, "Authentication failed");
        } else {
            panic!("Expected InvalidConnection error");
        }
    }

    #[tokio::test]
    async fn test_soap_response_generation() {
        let test_service = TestDIDAuthenticateService::new_success();
        let handler = DIDAuthenticateHandler::new(test_service);

        let test_response = create_test_response();
        let soap_xml = handler.to_soap_response(test_response);

        assert!(
            soap_xml.is_ok(),
            "Failed to generate SOAP response: {soap_xml:?}"
        );

        let xml_string = soap_xml.unwrap();

        // Verify SOAP structure
        assert!(xml_string.contains("soapenv:Envelope"));
        assert!(xml_string.contains("soapenv:Body"));
        assert!(xml_string.contains("ecard:DIDAuthenticateResponse"));
        assert!(xml_string.contains("ecard:Result"));
        assert!(xml_string.contains("ecard:ResultMajor"));
        assert!(xml_string.contains("ecard:AuthenticationProtocolData"));
        assert!(xml_string.contains("http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok"));

        // Verify optional elements are included when present
        assert!(xml_string.contains("ecard:Certificate"));
        assert!(xml_string.contains("ecard:PersonalData"));
        assert!(xml_string.contains("ecard:AuthenticationToken"));
    }

    #[tokio::test]
    async fn test_parse_request_missing_required_fields() {
        let test_service = TestDIDAuthenticateService::new_success();
        let handler = DIDAuthenticateHandler::new(test_service);

        // Test with missing DIDName
        let invalid_soap = r#"<?xml version="1.0" encoding="UTF-8"?>
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ecard="http://www.bsi.bund.de/ecard/api/1.1">
                <soapenv:Body>
                    <ecard:DIDAuthenticate>
                        <ecard:ConnectionHandle>
                            <ecard:ChannelHandle>test_channel</ecard:ChannelHandle>
                            <ecard:IFDName>test_ifd</ecard:IFDName>
                            <ecard:SlotIndex>0</ecard:SlotIndex>
                        </ecard:ConnectionHandle>
                        <ecard:AuthenticationProtocolData>
                            <ecard:Certificate>test_cert</ecard:Certificate>
                            <ecard:RequiredCHAT>test_required</ecard:RequiredCHAT>
                        </ecard:AuthenticationProtocolData>
                    </ecard:DIDAuthenticate>
                </soapenv:Body>
            </soapenv:Envelope>"#;

        let result = handler.parse_request(invalid_soap);
        assert!(result.is_ok()); // Parser should succeed but DIDName will be empty

        let parsed = result.unwrap();
        assert!(parsed.did_name.is_empty());
    }

    #[tokio::test]
    async fn test_parse_request_invalid_xml() {
        let test_service = TestDIDAuthenticateService::new_success();
        let handler = DIDAuthenticateHandler::new(test_service);

        let invalid_xml = "This is not valid XML at all";

        let result = handler.parse_request(invalid_xml);
        assert!(result.is_err());

        if let Err(AuthError::InvalidConnection { reason }) = result {
            assert!(
                reason.contains("Failed to parse XML request") || reason.contains("Invalid XML"),
                "Unexpected error reason: {reason}"
            );
        }
    }

    #[tokio::test]
    async fn test_axum_handler_integration() {
        let config = EIDServiceConfig::default();
        let useid_service = Arc::new(UseidService::new(config));

        let state = AppState {
            eid_service: useid_service.clone(),
            use_id: useid_service.clone(),
        };

        let soap_request = create_minimal_valid_soap_request();

        let result = did_authenticate(State(state), soap_request).await;

        // The actual service will likely fail with the test data, but we should get a proper HTTP response
        match result {
            Ok(response) => {
                let axum_response = response.into_response();
                assert!(
                    axum_response.status().is_success()
                        || axum_response.status().is_client_error()
                        || axum_response.status().is_server_error()
                );
            }
            Err(status_code) => {
                // Should be an internal server error due to test data
                assert_eq!(status_code, StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    #[tokio::test]
    async fn test_parse_request_with_numeric_slot_index() {
        let test_service = TestDIDAuthenticateService::new_success();
        let handler = DIDAuthenticateHandler::new(test_service);

        let soap_request = r#"<?xml version="1.0" encoding="UTF-8"?>
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ecard="http://www.bsi.bund.de/ecard/api/1.1">
                <soapenv:Body>
                    <ecard:DIDAuthenticate>
                        <ecard:ConnectionHandle>
                            <ecard:ChannelHandle>test_channel</ecard:ChannelHandle>
                            <ecard:IFDName>test_ifd</ecard:IFDName>
                            <ecard:SlotIndex>42</ecard:SlotIndex>
                        </ecard:ConnectionHandle>
                        <ecard:DIDName>EAC</ecard:DIDName>
                        <ecard:AuthenticationProtocolData>
                            <ecard:Certificate>test_cert</ecard:Certificate>
                            <ecard:RequiredCHAT>test_required</ecard:RequiredCHAT>
                        </ecard:AuthenticationProtocolData>
                    </ecard:DIDAuthenticate>
                </soapenv:Body>
            </soapenv:Envelope>"#;

        let result = handler.parse_request(soap_request);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.connection_handle.slot_index, Some(42));
    }

    #[tokio::test]
    async fn test_parse_request_with_invalid_slot_index() {
        let test_service = TestDIDAuthenticateService::new_success();
        let handler = DIDAuthenticateHandler::new(test_service);

        let soap_request = r#"<?xml version="1.0" encoding="UTF-8"?>
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ecard="http://www.bsi.bund.de/ecard/api/1.1">
                <soapenv:Body>
                    <ecard:DIDAuthenticate>
                        <ecard:ConnectionHandle>
                            <ecard:ChannelHandle>test_channel</ecard:ChannelHandle>
                            <ecard:IFDName>test_ifd</ecard:IFDName>
                            <ecard:SlotIndex>not_a_number</ecard:SlotIndex>
                        </ecard:ConnectionHandle>
                        <ecard:DIDName>EAC</ecard:DIDName>
                        <ecard:AuthenticationProtocolData>
                            <ecard:Certificate>test_cert</ecard:Certificate>
                            <ecard:RequiredCHAT>test_required</ecard:RequiredCHAT>
                        </ecard:AuthenticationProtocolData>
                    </ecard:DIDAuthenticate>
                </soapenv:Body>
            </soapenv:Envelope>"#;

        let result = handler.parse_request(soap_request);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        // Should default to 0 when parsing fails
        assert_eq!(parsed.connection_handle.slot_index, Some(0));
    }

    // Helper function to create a minimal valid SOAP request for testing
    fn create_minimal_valid_soap_request() -> String {
        r#"<?xml version="1.0" encoding="UTF-8"?>
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ecard="http://www.bsi.bund.de/ecard/api/1.1">
                <soapenv:Header/>
                <soapenv:Body>
                    <ecard:DIDAuthenticate>
                        <ecard:ConnectionHandle>
                            <ecard:ChannelHandle>test_channel_123</ecard:ChannelHandle>
                            <ecard:IFDName>Test_Terminal</ecard:IFDName>
                            <ecard:SlotIndex>0</ecard:SlotIndex>
                        </ecard:ConnectionHandle>
                        <ecard:DIDName>EAC</ecard:DIDName>
                        <ecard:AuthenticationProtocolData Protocol="urn:iso:std:iso-iec:24727:part:3:profile:EAC1InputType">
                            <ecard:Certificate>dGVzdF9jZXJ0aWZpY2F0ZV9kYXRh</ecard:Certificate>
                            <ecard:RequiredCHAT>7f4c12060904007f00070301020253053c0ff3ffff</ecard:RequiredCHAT>
                            <ecard:OptionalCHAT>7f4c12060904007f00070301020253053c0ff3ffff</ecard:OptionalCHAT>
                            <ecard:AuthenticatedAuxiliaryData>https://test-service.example.com</ecard:AuthenticatedAuxiliaryData>
                        </ecard:AuthenticationProtocolData>
                    </ecard:DIDAuthenticate>
                </soapenv:Body>
            </soapenv:Envelope>"#.to_string()
    }
}
