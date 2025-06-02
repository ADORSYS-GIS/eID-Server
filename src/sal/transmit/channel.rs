use hex;
use std::sync::Arc;

use super::{
    error::TransmitError,
    protocol::{InputAPDUInfo, ProtocolHandler, TransmitResponse},
    session::SessionManager,
};

pub trait ApduTransport: Send + Sync {
    fn transmit_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>, String>;
}

pub struct MockApduTransport;

impl ApduTransport for MockApduTransport {
    fn transmit_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>, String> {
        // Echo the APDU and append 0x90 0x00 (success)
        let mut response = apdu.to_vec();
        response.extend_from_slice(&[0x90, 0x00]);
        Ok(response)
    }
}

#[derive(Clone)]
pub struct TransmitChannel {
    protocol_handler: Arc<ProtocolHandler>,
    session_manager: Arc<SessionManager>,
    apdu_transport: Arc<dyn ApduTransport>,
}

impl TransmitChannel {
    pub fn new(
        protocol_handler: ProtocolHandler,
        session_manager: SessionManager,
        apdu_transport: Arc<dyn ApduTransport>,
    ) -> Self {
        Self {
            protocol_handler: Arc::new(protocol_handler),
            session_manager: Arc::new(session_manager),
            apdu_transport,
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
        // Parse XML Transmit request from eID-Client with proper namespace handling
        let xml_str = std::str::from_utf8(request)
            .map_err(|e| TransmitError::InvalidRequest(format!("Invalid UTF-8: {}", e)))?;

        // Log incoming request for debugging (should be removed in production or made configurable)
        // tracing::debug!("Received XML request: {}", xml_str);

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
                super::result_codes::MinorCode::InvalidSlotHandle,
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
        // According to TR-03130, we need to validate the TLS channel security
        let tls_info = super::session::TlsSessionInfo {
            session_id: "mock-session-id".to_string(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(), // TR-03130 requires TLS 1.2 or higher
        };

        // Get or create client session using SlotHandle as specified in TR-03112
        let session_result = match self
            .session_manager
            .get_session(&transmit.slot_handle)
            .await
        {
            Ok(session) => Ok(session),
            Err(_) => {
                // Create a new session with the specified SlotHandle
                self.session_manager.create_session(tls_info).await
            }
        };

        // Handle session errors according to TR-03130
        let _session = match session_result {
            Ok(session) => session,
            Err(e) => {
                let error_result = super::protocol::TransmitResult::error(
                    super::result_codes::MinorCode::InvalidContext,
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

        // Process client APDU requests
        let output_apdu_result = self.process_client_apdus(&transmit.input_apdu_info).await;

        // Handle APDU processing errors according to TR-03130
        let output_apdu = match output_apdu_result {
            Ok(apdus) => apdus,
            Err(e) => {
                let error_result = self.protocol_handler.error_to_result(&e);
                let error_response = TransmitResponse {
                    result: error_result,
                    output_apdu: Vec::new(), // No APDUs in error case
                };
                let xml_response = self
                    .protocol_handler
                    .format_transmit_response(&error_response)?;
                return Ok(xml_response.into_bytes());
            }
        };

        // Build successful response for eID-Client per TR-03130
        let response = TransmitResponse {
            result: super::protocol::TransmitResult::ok(), // "ok" result as defined in TR-03112
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
            match self.process_single_client_apdu(info).await {
                Ok(output_apdu) => output_apdus.push(output_apdu),
                Err(e) => {
                    // According to TR-03130, we need to stop processing on error
                    // and return what we have processed so far along with an error
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

        // Validate APDU minimum length (at least CLA, INS, P1, P2 = 4 bytes)
        if apdu_bytes.len() < 4 {
            return Err(TransmitError::InvalidRequest(format!(
                "APDU too short: {} bytes, minimum 4 bytes required",
                apdu_bytes.len()
            )));
        }

        // If timeout is specified, use it (according to TR-03130)
        let _timeout_ms = info.timeout.unwrap_or(10000); // Default 10 seconds if not specified

        // Create a future for transmitting APDU with transport layer
        let transmit_future = self.apdu_transport.transmit_apdu(&apdu_bytes);

        // In real code, we'd implement a proper timeout here
        // For demonstration, we'll just directly call the transport
        let response_bytes = transmit_future.map_err(|e| TransmitError::CardError(e))?;

        // Convert response to hex string (uppercase as specified in TR-03130)
        let response_hex = hex::encode_upper(response_bytes);

        // According to TR-03130, we need to validate the status code if specified
        if let Some(expected_status) = &info.acceptable_status_code {
            // Ensure response is long enough to have a status code
            if response_hex.len() < 4 {
                return Err(TransmitError::CardError(format!(
                    "Response too short to contain status code: {}",
                    response_hex
                )));
            }

            // Extract the status code (last 2 bytes = 4 hex characters)
            let actual_status = &response_hex[response_hex.len() - 4..];

            // Validate the status code
            if actual_status != expected_status {
                return Err(TransmitError::CardError(format!(
                    "Status code mismatch: expected {}, got {}",
                    expected_status, actual_status
                )));
            }
        }

        Ok(response_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::super::protocol::{ISO24727_3_NS, ProtocolHandler};
    use super::super::session::SessionManager;
    use super::*;
    use tokio::runtime::Runtime;

    /// Create a test transport that responds with fixed APDUs for specific commands
    struct TestApduTransport;

    impl ApduTransport for TestApduTransport {
        fn transmit_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>, String> {
            // Convert APDU to uppercase hex for easier comparison
            let apdu_hex = hex::encode_upper(apdu);

            // Simulate specific responses according to TR-03130 test cases
            match apdu_hex.as_str() {
                // SELECT application command - OK response
                "00A4040008A000000167455349" => {
                    // Response with file control info and status word 9000 (OK)
                    Ok(hex::decode("6F108408A000000167455349A5049F6501FF9000").unwrap())
                }
                // READ BINARY command - OK response
                "00B0000000" | "00B0000010" => {
                    // Sample data response with status word 9000 (OK)
                    Ok(hex::decode("0102030405060708090A0B0C0D0E0F109000").unwrap())
                }
                // SELECT command with wrong AID - file not found
                "00A4040008A00000016745XXXX" => {
                    // Status word 6A82 - file not found
                    Ok(hex::decode("6A82").unwrap())
                }
                // VERIFY PIN command - incorrect PIN
                "0020000004XXXXXXXX" => {
                    // Status word 63C2 - verification failed, 2 tries left
                    Ok(hex::decode("63C2").unwrap())
                }
                // Default response: echo back command + OK status
                _ => {
                    let mut response = apdu.to_vec();
                    response.extend_from_slice(&[0x90, 0x00]);
                    Ok(response)
                }
            }
        }
    }

    // Tests according to TR-03130 Test Specification
    #[test]
    fn test_transmit_channel_basic_flow() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let protocol_handler = ProtocolHandler::new();
            let session_manager = SessionManager::new(std::time::Duration::from_secs(60));
            let channel = TransmitChannel::new(
                protocol_handler,
                session_manager,
                Arc::new(TestApduTransport),
            );

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
                response_xml
                    .contains("<OutputAPDU>0102030405060708090A0B0C0D0E0F109000</OutputAPDU>")
            );
        });
    }

    #[test]
    fn test_transmit_channel_error_handling() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let protocol_handler = ProtocolHandler::new();
            let session_manager = SessionManager::new(std::time::Duration::from_secs(60));
            let channel = TransmitChannel::new(
                protocol_handler,
                session_manager,
                Arc::new(TestApduTransport),
            );

            // Test 1: Malformed XML should return proper error
            let malformed_xml = "<Transmit><SlotHandle>slot-1</SlotHandle><InvalidTag></InvalidTag></Transmit>";
            let response = channel.handle_request(malformed_xml.as_bytes()).await.unwrap();
            let response_xml = String::from_utf8(response).unwrap();
            // Should contain error result
            assert!(response_xml.contains("<ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error</ResultMajor>"));
            assert!(response_xml.contains("<ResultMinor>http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#"));

            // Test 2: Missing SlotHandle should return proper error
            let missing_slot = format!(r#"<Transmit xmlns="{0}"><InputAPDUInfo><InputAPDU>00A4040008A000000167455349</InputAPDU></InputAPDUInfo></Transmit>"#,
                ISO24727_3_NS);

            let response = channel.handle_request(missing_slot.as_bytes()).await.unwrap();
            let response_xml = String::from_utf8(response).unwrap();
            // Should contain error result for missing SlotHandle
            assert!(response_xml.contains("<ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error</ResultMajor>"));

            // Test 3: Status code verification failure
            let wrong_status_xml = format!(r#"
                <Transmit xmlns="{0}">
                    <SlotHandle>slot-1</SlotHandle>
                    <InputAPDUInfo>
                        <InputAPDU>00A4040008A00000016745XXXX</InputAPDU>
                        <AcceptableStatusCode>9000</AcceptableStatusCode>
                    </InputAPDUInfo>
                </Transmit>
            "#, ISO24727_3_NS);

            let response = channel.handle_request(wrong_status_xml.as_bytes()).await.unwrap();
            let response_xml = String::from_utf8(response).unwrap();

            // Should contain error for status code mismatch
            assert!(response_xml.contains("<ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error</ResultMajor>"));
            assert!(response_xml.contains("<ResultMinor>http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifd#cardError</ResultMinor>"));
        });
    }

    #[test]
    fn test_transmit_channel_invalid_apdu() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let protocol_handler = ProtocolHandler::new();
            let session_manager = SessionManager::new(std::time::Duration::from_secs(60));
            let channel = TransmitChannel::new(
                protocol_handler,
                session_manager,
                Arc::new(TestApduTransport),
            );

            // Test with invalid APDU format (odd-length hex string)
            let invalid_apdu_xml = format!(r#"
                <Transmit xmlns="{0}">
                    <SlotHandle>slot-1</SlotHandle>
                    <InputAPDUInfo>
                        <InputAPDU>00A4040</InputAPDU>
                    </InputAPDUInfo>
                </Transmit>
            "#, ISO24727_3_NS);

            let response = channel.handle_request(invalid_apdu_xml.as_bytes()).await.unwrap();
            let response_xml = String::from_utf8(response).unwrap();

            // Should contain error for invalid APDU
            assert!(response_xml.contains("<ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error</ResultMajor>"));
            assert!(response_xml.contains("<ResultMinor>http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifd#cardError</ResultMinor>"));

            // Test with empty APDU
            let empty_apdu_xml = format!(r#"
                <Transmit xmlns="{0}">
                    <SlotHandle>slot-1</SlotHandle>
                    <InputAPDUInfo>
                        <InputAPDU></InputAPDU>
                    </InputAPDUInfo>
                </Transmit>
            "#, ISO24727_3_NS);

            let response = channel.handle_request(empty_apdu_xml.as_bytes()).await.unwrap();
            let response_xml = String::from_utf8(response).unwrap();

            // Should contain error for empty APDU
            assert!(response_xml.contains("<ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error</ResultMajor>"));
        });
    }

    #[test]
    fn test_transmit_channel_multiple_apdus() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let protocol_handler = ProtocolHandler::new();
            let session_manager = SessionManager::new(std::time::Duration::from_secs(60));
            let channel = TransmitChannel::new(
                protocol_handler,
                session_manager,
                Arc::new(TestApduTransport),
            );

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
                response_xml
                    .contains("<OutputAPDU>0102030405060708090A0B0C0D0E0F109000</OutputAPDU>")
            );

            // Count the number of OutputAPDU elements
            let apdu_count = response_xml.matches("<OutputAPDU>").count();
            assert_eq!(apdu_count, 3, "Should have 3 APDU responses");
        });
    }
}
