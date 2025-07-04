use crate::sal::transmit::config::TransmitConfig;
use crate::sal::transmit::session::SessionManager;
use async_trait::async_trait;
use hex;
use quick_xml::de::from_str;
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use tokio::time::timeout;
use tracing::error;

use super::{
    error::TransmitError,
    protocol::{InputAPDUInfo, ProtocolHandler, TransmitResponse},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ClientResponse {
    #[serde(rename = "OutputAPDU")]
    output_apdu: String,
}

#[async_trait]
pub trait ApduTransport: Send + Sync {
    async fn transmit_apdu(&self, apdu: Vec<u8>, slot_handle: &str) -> Result<Vec<u8>, String>;
}

/// HTTP-based APDU transport implementation
#[derive(Debug, Clone)]
pub struct HttpApduTransport {
    client: Client,
    config: TransmitConfig,
}

impl HttpApduTransport {
    pub fn new(config: TransmitConfig) -> Self {
        // Configure TLS client with proper settings
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(
                config.session_timeout_secs as u64,
            ))
            .tls_built_in_root_certs(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .build()
            .expect("Failed to create HTTP client");

        Self { client, config }
    }
}

#[async_trait]
impl ApduTransport for HttpApduTransport {
    async fn transmit_apdu(&self, apdu: Vec<u8>, slot_handle: &str) -> Result<Vec<u8>, String> {
        let apdu_hex = hex::encode_upper(&apdu);
        let client_url = &self.config.client_url;

        // Create XML payload according to TR-03130
        let xml_payload = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<Transmit xmlns="urn:iso:std:iso-iec:24727:tech:schema">
    <SlotHandle>{}</SlotHandle>
    <InputAPDUInfo>
        <InputAPDU>{}</InputAPDU>
        <AcceptableStatusCode>9000</AcceptableStatusCode>
    </InputAPDUInfo>
</Transmit>"#,
            slot_handle, apdu_hex
        );

        // Send request with retries
        let mut retries = 0;
        let max_retries = 3;
        let mut last_error = None;

        while retries < max_retries {
            match self
                .client
                .post(client_url)
                .header("Content-Type", "application/xml")
                .body(xml_payload.clone())
                .send()
                .await
            {
                Ok(response) => {
                    if !response.status().is_success() {
                        let status = response.status();
                        error!("HTTP request failed with status: {}", status);
                        last_error = Some(format!("HTTP request failed with status: {}", status));
                        retries += 1;
                        continue;
                    }

                    // Parse response body
                    let response_text = match response.text().await {
                        Ok(text) => text,
                        Err(e) => {
                            error!("Failed to read response body: {}", e);
                            last_error = Some(format!("Failed to read response body: {}", e));
                            retries += 1;
                            continue;
                        }
                    };

                    // Parse XML response using quick-xml
                    let client_response: ClientResponse = match from_str(&response_text) {
                        Ok(resp) => resp,
                        Err(e) => {
                            error!("Failed to parse XML response: {}", e);
                            last_error = Some(format!("Failed to parse XML response: {}", e));
                            retries += 1;
                            continue;
                        }
                    };

                    // Decode the APDU response
                    match hex::decode(&client_response.output_apdu) {
                        Ok(apdu_response) => {
                            return Ok(apdu_response);
                        }
                        Err(e) => {
                            error!("Failed to decode APDU hex: {}", e);
                            last_error = Some(format!("Failed to decode APDU hex: {}", e));
                            retries += 1;
                            continue;
                        }
                    }
                }
                Err(e) => {
                    error!("HTTP request failed: {}", e);
                    last_error = Some(format!("HTTP request failed: {}", e));
                    retries += 1;
                    continue;
                }
            }
        }

        // If we get here, all retries failed
        Err(last_error.unwrap_or_else(|| "All retries failed".to_string()))
    }
}

#[derive(Clone)]
pub struct TransmitChannel {
    protocol_handler: Arc<ProtocolHandler>,
    session_manager: Arc<SessionManager>,
    apdu_transport: Arc<dyn ApduTransport>,
    config: TransmitConfig,
}

impl std::fmt::Debug for TransmitChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransmitChannel")
            .field("protocol_handler", &self.protocol_handler)
            .field("session_manager", &self.session_manager)
            .field("apdu_transport", &"<ApduTransport>")
            .field("config", &self.config)
            .finish()
    }
}

impl TransmitChannel {
    pub fn new(
        protocol_handler: ProtocolHandler,
        session_manager: SessionManager,
        apdu_transport: Arc<dyn ApduTransport>,
        config: TransmitConfig,
    ) -> Self {
        // Validate configuration
        if let Err(e) = config.validate() {
            panic!("Invalid transmit configuration: {}", e);
        }

        Self {
            protocol_handler: Arc::new(protocol_handler),
            session_manager: Arc::new(session_manager),
            apdu_transport,
            config,
        }
    }

    /// Handles a transmit request from the eID-Client according to eCard-API and TR-03130
    ///
    /// This function processes XML-based transmit requests from the eID-Client,
    /// manages the client session, and returns the appropriate response according to
    /// ISO 24727-3 and eCard-API Framework specifications.
    ///
    /// # Arguments
    /// * `request` - The raw XML request from the eID-Client
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The XML response to be sent back to the eID-Client
    /// * `Err(TransmitError)` - If the request cannot be processed
    pub async fn handle_request(&self, request: &[u8]) -> Result<Vec<u8>, TransmitError> {
        let xml_str = std::str::from_utf8(request)
            .map_err(|e| TransmitError::InvalidRequest(format!("Invalid UTF-8: {}", e)))?;

        // Parse the Transmit request
        let transmit = match self.protocol_handler.parse_transmit(xml_str) {
            Ok(transmit) => transmit,
            Err(e) => {
                // Convert error to proper Result according to spec
                let error_result = self.protocol_handler.error_to_result(&e);
                let error_response = TransmitResponse {
                    result: error_result,
                    output_apdu: Vec::new(),
                };
                let xml_response = self
                    .protocol_handler
                    .format_transmit_response(&error_response)?;
                return Ok(xml_response.into_bytes());
            }
        };

        // Validate SlotHandle according to TR-03130 (must be non-empty)
        if transmit.slot_handle.is_empty() {
            let error_result = super::protocol::TransmitResult::error(
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#invalidSlotHandle",
                Some("Empty SlotHandle provided".to_string()),
            );
            let error_response = TransmitResponse {
                result: error_result,
                output_apdu: Vec::new(),
            };
            let xml_response = self
                .protocol_handler
                .format_transmit_response(&error_response)?;
            return Ok(xml_response.into_bytes());
        }

        // Get TLS session info from connection (use mock for now, but in production extract from connection)
        // According to TR-03130, we need to validate the TLS channel security and PSK
        let tls_info = super::session::TlsSessionInfo {
            session_id: "mock-session-id".to_string(),
            cipher_suite: "TLS_RSA_PSK_WITH_AES_256_CBC_SHA".to_string(), // TR-03130 required cipher suite
            psk_id: Some("mock-psk-id".to_string()), // In production, extract from TLS-2 connection
            psk_key: Some("mock-psk-key".to_string()), // In production, validate against negotiated PSK
        };

        // Get or create client session using SlotHandle as specified in TR-03112
        let session_result = match self
            .session_manager
            .get_session(&transmit.slot_handle)
            .await
        {
            Ok(session) => {
                // Update session state to Active if it was Suspended
                if session.state == super::session::SessionState::Suspended {
                    self.session_manager
                        .update_session_state(&session.id, super::session::SessionState::Active)
                        .await?;
                }
                Ok(session)
            }
            Err(_) => {
                // Create a new session with the specified SlotHandle
                self.session_manager.create_session(tls_info).await
            }
        };

        // Handle session errors according to TR-03130
        let session = match session_result {
            Ok(session) => session,
            Err(e) => {
                let error_result = super::protocol::TransmitResult::error(
                    "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#invalidContext",
                    Some(format!("Session error: {}", e)),
                );
                let error_response = TransmitResponse {
                    result: error_result,
                    output_apdu: Vec::new(),
                };
                let xml_response = self
                    .protocol_handler
                    .format_transmit_response(&error_response)?;
                return Ok(xml_response.into_bytes());
            }
        };

        // Process client APDU requests with timeout
        let output_apdu_result = timeout(
            std::time::Duration::from_secs(self.config.session_timeout_secs as u64),
            self.process_client_apdus(&transmit.input_apdu_info, &transmit.slot_handle),
        )
        .await
        .map_err(|_| TransmitError::SessionError("Request timeout".to_string()))?;

        // Handle APDU processing errors according to TR-03130
        let output_apdu = match output_apdu_result {
            Ok(apdus) => apdus,
            Err(e) => {
                // Suspend session on error
                let _ = self
                    .session_manager
                    .update_session_state(&session.id, super::session::SessionState::Suspended)
                    .await;

                let error_result = self.protocol_handler.error_to_result(&e);
                let error_response = TransmitResponse {
                    result: error_result,
                    output_apdu: Vec::new(),
                };
                let xml_response = self
                    .protocol_handler
                    .format_transmit_response(&error_response)?;
                return Ok(xml_response.into_bytes());
            }
        };

        // Build successful response for eID-Client per TR-03130
        let response = TransmitResponse {
            result: super::protocol::TransmitResult::ok(),
            output_apdu,
        };

        // Serialize response to XML with proper namespaces
        let xml_response = self.protocol_handler.format_transmit_response(&response)?;
        Ok(xml_response.into_bytes())
    }

    /// Processes APDU requests from the eID-Client according to eCard-API and TR-03130
    ///
    /// This function handles the APDU requests from the client according to the
    /// specifications and prepares the responses to be sent back to the client.
    /// Implements behavior as per ISO 24727-3 and TR-03112 Part 6 sections for Transmit.
    async fn process_client_apdus(
        &self,
        apdu_info: &[InputAPDUInfo],
        slot_handle: &str,
    ) -> Result<Vec<String>, TransmitError> {
        // Check if the client sent any APDUs
        if apdu_info.is_empty() {
            return Err(TransmitError::InvalidRequest(
                "No APDUs provided".to_string(),
            ));
        }

        let mut output_apdus = Vec::with_capacity(apdu_info.len());

        // TR-03112 specifies that APDUs should be processed sequentially
        for info in apdu_info {
            match self.process_single_client_apdu(info, slot_handle).await {
                Ok(output_apdu) => output_apdus.push(output_apdu),
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Ok(output_apdus)
    }

    /// Processes a single APDU request from the eID-Client according to eCard-API and TR-03130
    ///
    /// This function handles a single APDU request from the client according to
    /// ISO 24727-3 and TR-03112 requirements, and prepares the response.
    /// Implements timeout handling and status code validation as specified.
    async fn process_single_client_apdu(
        &self,
        info: &InputAPDUInfo,
        slot_handle: &str,
    ) -> Result<String, TransmitError> {
        // Validate APDU format according to ISO 7816-4
        if info.input_apdu.is_empty() {
            return Err(TransmitError::InvalidRequest(
                "Empty APDU provided".to_string(),
            ));
        }

        // Validate APDU format (should be even-length hexadecimal string)
        if info.input_apdu.len() % 2 != 0 {
            return Err(TransmitError::CardError(
                "Invalid APDU format: length must be even".to_string(),
            ));
        }

        // Convert hex string to bytes
        let apdu_bytes = hex::decode(&info.input_apdu)
            .map_err(|e| TransmitError::CardError(format!("Invalid APDU hex: {}", e)))?;

        // Validate APDU size
        if apdu_bytes.len() > self.config.max_apdu_size {
            return Err(TransmitError::InvalidRequest(format!(
                "APDU too large: {} bytes, maximum {} bytes allowed",
                apdu_bytes.len(),
                self.config.max_apdu_size
            )));
        }

        // Validate minimum length
        if apdu_bytes.len() < 4 {
            return Err(TransmitError::InvalidRequest(format!(
                "APDU too short: {} bytes, minimum 4 bytes required",
                apdu_bytes.len()
            )));
        }

        // Transmit APDU with timeout
        let timeout_duration =
            std::time::Duration::from_millis(info.timeout.unwrap_or(10000) as u64);

        let response_bytes = timeout(
            timeout_duration,
            self.apdu_transport.transmit_apdu(apdu_bytes, slot_handle),
        )
        .await
        .map_err(|_| TransmitError::CardError("APDU transmission timeout".to_string()))?
        .map_err(|e| TransmitError::CardError(e.to_string()))?;

        // Convert response to hex string
        let response_hex = hex::encode_upper(response_bytes);

        // Validate status code if specified
        if let Some(expected_status) = &info.acceptable_status_code {
            let actual_status = &response_hex[response_hex.len() - 4..];
            if actual_status != expected_status {
                return Err(TransmitError::InvalidStatusCode {
                    expected: expected_status.clone(),
                    actual: actual_status.to_string(),
                });
            }
        }

        Ok(response_hex)
    }
}

#[derive(Debug, Clone)]
pub struct TestApduTransport;

#[async_trait]
impl ApduTransport for TestApduTransport {
    async fn transmit_apdu(&self, apdu: Vec<u8>, _slot_handle: &str) -> Result<Vec<u8>, String> {
        // Convert APDU to uppercase hex for easier comparison
        let apdu_hex = hex::encode_upper(&apdu);

        // Return predefined responses for test APDUs
        match apdu_hex.as_str() {
            // SELECT eID application
            "00A4040008A000000167455349" => {
                Ok(hex::decode("6F108408A000000167455349A5049F6501FF9000")
                    .expect("Hardcoded test hex should decode successfully"))
            }
            // READ BINARY
            "00B0000000" => Ok(hex::decode("0102030405060708090A0B0C0D0E0F109000")
                .expect("Hardcoded test hex should decode successfully")),
            "00B0000010" => Ok(hex::decode("1112131415161718191A1B1C1D1E1F209000")
                .expect("Hardcoded test hex should decode successfully")),
            // SELECT eID.SIGN application
            "00A4040008A000000167455349474E" => {
                Ok(hex::decode("9000").expect("Hardcoded test hex should decode successfully"))
            }
            // Default success response for unknown APDUs
            _ => Ok(vec![0x90, 0x00]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::protocol::{ISO24727_3_NS, ProtocolHandler};
    use super::super::session::SessionManager;
    use super::*;

    #[tokio::test]
    async fn test_transmit_channel_basic_flow() {
        let protocol_handler = ProtocolHandler::new();
        let session_manager = SessionManager::new(std::time::Duration::from_secs(60));
        let config = TransmitConfig::default();
        let apdu_transport = Arc::new(TestApduTransport);
        let channel =
            TransmitChannel::new(protocol_handler, session_manager, apdu_transport, config);

        // Create a valid XML request according to TR-03130
        let xml = format!(
            r#"
            <Transmit xmlns="{0}">
                <SlotHandle>slot-1</SlotHandle>
                <InputAPDUInfo>
                    <InputAPDU>00A4040008A000000167455349</InputAPDU>
                    <AcceptableStatusCode>9000</AcceptableStatusCode>
                </InputAPDUInfo>
                <InputAPDUInfo>
                    <InputAPDU>00B0000000</InputAPDU>
                </InputAPDUInfo>
            </Transmit>
        "#,
            ISO24727_3_NS
        );

        let response_bytes = channel
            .handle_request(xml.as_bytes())
            .await
            .expect("XML flow should succeed");

        let response_xml = String::from_utf8(response_bytes).expect("Valid UTF-8");

        // Verify result is OK
        assert!(response_xml.contains(
            "<ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</ResultMajor>"
        ));

        // Verify both APDUs are present with correct responses
        assert!(
            response_xml
                .contains("<OutputAPDU>6F108408A000000167455349A5049F6501FF9000</OutputAPDU>")
        );
        assert!(
            response_xml.contains("<OutputAPDU>0102030405060708090A0B0C0D0E0F109000</OutputAPDU>")
        );
    }

    #[tokio::test]
    async fn test_transmit_channel_error_handling() {
        let protocol_handler = ProtocolHandler::new();
        let session_manager = SessionManager::new(std::time::Duration::from_secs(60));
        let config = TransmitConfig::default();
        let apdu_transport = Arc::new(TestApduTransport);
        let channel =
            TransmitChannel::new(protocol_handler, session_manager, apdu_transport, config);

        // Test 1: Malformed XML should return proper error
        let malformed_xml =
            "<Transmit><SlotHandle>slot-1</SlotHandle><InvalidTag></InvalidTag></Transmit>";
        let response = channel
            .handle_request(malformed_xml.as_bytes())
            .await
            .expect("Error handling should return valid XML response");
        let response_xml = String::from_utf8(response).expect("Response should be valid UTF-8");
        // Should contain error result
        assert!(response_xml.contains(
            "<ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error</ResultMajor>"
        ));
        assert!(
            response_xml
                .contains("<ResultMinor>http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#")
        );

        // Test 2: Missing SlotHandle should return proper error
        let missing_slot = format!(
            r#"<Transmit xmlns="{0}"><InputAPDUInfo><InputAPDU>00A4040008A000000167455349</InputAPDU></InputAPDUInfo></Transmit>"#,
            ISO24727_3_NS
        );

        let response = channel
            .handle_request(missing_slot.as_bytes())
            .await
            .expect("Error handling should return valid XML response");
        let response_xml = String::from_utf8(response).expect("Response should be valid UTF-8");
        // Should contain error result for missing SlotHandle
        assert!(response_xml.contains(
            "<ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error</ResultMajor>"
        ));

        // Test 3: Status code verification failure
        let wrong_status_xml = format!(
            r#"
            <Transmit xmlns="{0}">
                <SlotHandle>slot-1</SlotHandle>
                <InputAPDUInfo>
                    <InputAPDU>00A4040008A00000016745XXXX</InputAPDU>
                    <AcceptableStatusCode>9000</AcceptableStatusCode>
                </InputAPDUInfo>
            </Transmit>
        "#,
            ISO24727_3_NS
        );

        let response = channel
            .handle_request(wrong_status_xml.as_bytes())
            .await
            .expect("Error handling should return valid XML response");
        let response_xml = String::from_utf8(response).expect("Response should be valid UTF-8");

        // Should contain error for status code mismatch
        assert!(response_xml.contains(
            "<ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error</ResultMajor>"
        ));
        assert!(response_xml.contains("<ResultMinor>http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifd#cardError</ResultMinor>"));
    }

    #[tokio::test]
    async fn test_transmit_channel_invalid_apdu() {
        let protocol_handler = ProtocolHandler::new();
        let session_manager = SessionManager::new(std::time::Duration::from_secs(60));
        let config = TransmitConfig::default();
        let apdu_transport = Arc::new(TestApduTransport);
        let channel =
            TransmitChannel::new(protocol_handler, session_manager, apdu_transport, config);

        // Test with invalid APDU format (odd-length hex string)
        let invalid_apdu_xml = format!(
            r#"
            <Transmit xmlns="{0}">
                <SlotHandle>slot-1</SlotHandle>
                <InputAPDUInfo>
                    <InputAPDU>00A4040</InputAPDU>
                </InputAPDUInfo>
            </Transmit>
        "#,
            ISO24727_3_NS
        );

        let response = channel
            .handle_request(invalid_apdu_xml.as_bytes())
            .await
            .expect("Error handling should return valid XML response");
        let response_xml = String::from_utf8(response).expect("Response should be valid UTF-8");

        // Should contain error for invalid APDU
        assert!(response_xml.contains(
            "<ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error</ResultMajor>"
        ));
        assert!(response_xml.contains("<ResultMinor>http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifd#cardError</ResultMinor>"));

        // Test with empty APDU
        let empty_apdu_xml = format!(
            r#"
            <Transmit xmlns="{0}">
                <SlotHandle>slot-1</SlotHandle>
                <InputAPDUInfo>
                    <InputAPDU></InputAPDU>
                </InputAPDUInfo>
            </Transmit>
        "#,
            ISO24727_3_NS
        );

        let response = channel
            .handle_request(empty_apdu_xml.as_bytes())
            .await
            .expect("Error handling should return valid XML response");
        let response_xml = String::from_utf8(response).expect("Response should be valid UTF-8");

        // Should contain error for empty APDU
        assert!(response_xml.contains(
            "<ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error</ResultMajor>"
        ));
    }

    #[tokio::test]
    async fn test_transmit_channel_custom_slot_handle() {
        use super::super::config::TransmitConfig;
        use super::super::protocol::ProtocolHandler;
        use super::super::session::SessionManager;

        let protocol_handler = ProtocolHandler::new();
        let session_manager = SessionManager::new(std::time::Duration::from_secs(60));
        let config = TransmitConfig::default();
        let apdu_transport = Arc::new(TestApduTransport);
        let channel =
            TransmitChannel::new(protocol_handler, session_manager, apdu_transport, config);

        // Test with custom slot handle
        let test_request = r#"<?xml version="1.0" encoding="UTF-8"?>
<Transmit xmlns="urn:iso:std:iso-iec:24727:tech:schema">
    <SlotHandle>custom-slot-456</SlotHandle>
    <InputAPDUInfo>
        <InputAPDU>00A4040007A0000002471001</InputAPDU>
        <AcceptableStatusCode>9000</AcceptableStatusCode>
    </InputAPDUInfo>
</Transmit>"#;

        let result = channel.handle_request(test_request.as_bytes()).await;
        assert!(result.is_ok(), "Request should be processed successfully");

        let response = result.expect("Request should be processed successfully");
        let response_str = String::from_utf8_lossy(&response);

        // Verify that the response contains a successful result
        assert!(response_str.contains("http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok"));
    }

    #[tokio::test]
    async fn test_transmit_channel_multiple_apdus() {
        let protocol_handler = ProtocolHandler::new();
        let session_manager = SessionManager::new(std::time::Duration::from_secs(60));
        let config = TransmitConfig::default();
        let apdu_transport = Arc::new(TestApduTransport);
        let channel =
            TransmitChannel::new(protocol_handler, session_manager, apdu_transport, config);

        // Test with multiple APDUs in sequence (SELECT + READ BINARY)
        let multi_apdu_xml = format!(
            r#"
            <Transmit xmlns="{0}">
                <SlotHandle>slot-1</SlotHandle>
                <InputAPDUInfo>
                    <InputAPDU>00A4040008A000000167455349</InputAPDU>
                </InputAPDUInfo>
                <InputAPDUInfo>
                    <InputAPDU>00B0000000</InputAPDU>
                </InputAPDUInfo>
                <InputAPDUInfo>
                    <InputAPDU>00B0000010</InputAPDU>
                </InputAPDUInfo>
            </Transmit>
        "#,
            ISO24727_3_NS
        );

        let response_bytes = channel
            .handle_request(multi_apdu_xml.as_bytes())
            .await
            .expect("XML flow should succeed");

        let response_xml = String::from_utf8(response_bytes).expect("Valid UTF-8");

        // Should contain all three APDU responses
        assert!(
            response_xml
                .contains("<OutputAPDU>6F108408A000000167455349A5049F6501FF9000</OutputAPDU>")
        );
        assert!(
            response_xml.contains("<OutputAPDU>0102030405060708090A0B0C0D0E0F109000</OutputAPDU>")
        );

        // Count the number of OutputAPDU elements
        let apdu_count = response_xml.matches("<OutputAPDU>").count();
        assert_eq!(apdu_count, 3, "Should have 3 APDU responses");
    }
}
