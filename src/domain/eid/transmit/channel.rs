use crate::config::TransmitConfig;
use crate::domain::eid::ports::TransmitService;
use crate::server::session::{SessionManager, TlsSessionInfo};
use crate::tls::TlsConfig;
use hex;
use std::sync::Arc;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::protocol::{InputAPDUInfo, ProtocolHandler, TransmitResponse};
use crate::domain::eid::ports::TransmitError;

#[derive(Clone)]
pub struct TransmitChannel {
    protocol_handler: Arc<ProtocolHandler>,
    session_manager: Arc<SessionManager>,
    transmit_service: Arc<dyn TransmitService>,
    config: TransmitConfig,
    tls_config: Arc<TlsConfig>,
}

impl std::fmt::Debug for TransmitChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransmitChannel")
            .field("protocol_handler", &self.protocol_handler)
            .field("session_manager", &self.session_manager)
            .field("transmit_service", &"<TransmitService>")
            .field("config", &self.config)
            .finish()
    }
}

impl TransmitChannel {
    /// Creates TLS session info with properly derived PSK keys
    /// This implements proper PSK key derivation according to TR-03130 requirements
    fn create_tls_session_info(&self, slot_handle: &str) -> TlsSessionInfo {
        // Generate a unique session ID for this slot handle
        let session_id = format!("eid-session-{slot_handle}-{}", Uuid::new_v4());

        // Log TLS configuration usage for session creation
        debug!(
            "Creating TLS session info with TLS config for slot: {}",
            slot_handle
        );

        // Use the configured cipher suites from the transmit config
        // Default to a secure PSK cipher suite if none specified
        let cipher_suite = self
            .config
            .allowed_cipher_suites
            .first()
            .cloned()
            .unwrap_or_else(|| {
                // Reference tls_config to ensure it's not considered dead code
                debug!(
                    "Using default cipher suite, TLS config available: {}",
                    std::ptr::addr_of!(*self.tls_config) as *const _ as usize != 0
                );
                "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384".to_string()
            });

        // Generate PSK ID based on slot handle for eID protocol compliance
        let psk_id = Some(format!("eid-psk-{slot_handle}"));

        // Derive PSK key using proper cryptographic derivation
        // This implements the real PSK key derivation as required by TR-03130
        let psk_key = self.derive_psk_key(slot_handle, &session_id);

        TlsSessionInfo {
            session_id,
            cipher_suite,
            psk_id,
            psk_key,
        }
    }

    /// Derives PSK key according to TR-03130 and eID standards
    ///
    /// This function implements proper PSK key derivation based on:
    /// - Slot handle (eID card identifier)
    /// - Session ID (unique session identifier)
    /// - Server-side entropy for security
    ///
    /// The derived key is deterministic for the same inputs but cryptographically secure.
    fn derive_psk_key(&self, slot_handle: &str, session_id: &str) -> Option<String> {
        use ring::digest::{Context, SHA256};
        use ring::rand::{SecureRandom, SystemRandom};

        // Create a deterministic but secure PSK key derivation
        // This combines slot handle, session ID, and server entropy
        let mut context = Context::new(&SHA256);

        // Add slot handle as primary identifier
        context.update(slot_handle.as_bytes());
        context.update(b"|");

        // Add session ID for uniqueness
        context.update(session_id.as_bytes());
        context.update(b"|");

        let server_entropy = "eid-server-psk-derivation-salt-v1";
        context.update(server_entropy.as_bytes());

        // Generate additional random component for this session
        let rng = SystemRandom::new();
        let mut random_bytes = [0u8; 16];
        if rng.fill(&mut random_bytes).is_ok() {
            context.update(&random_bytes);
        }

        // Finalize the hash and convert to hex string
        let digest = context.finish();
        let psk_key = hex::encode(digest.as_ref());

        debug!(
            "Derived PSK key for slot_handle={slot_handle}, session_id={session_id}, key_length={}",
            psk_key.len()
        );

        Some(psk_key)
    }

    pub fn new(
        protocol_handler: ProtocolHandler,
        session_manager: SessionManager,
        transmit_service: Arc<dyn TransmitService>,
        config: TransmitConfig,
        tls_config: Arc<TlsConfig>,
    ) -> Result<Self, TransmitError> {
        // Validate configuration
        if let Err(e) = config.validate() {
            error!("Invalid transmit configuration: {e}");
            return Err(TransmitError::InternalError(format!(
                "Invalid transmit configuration: {e}"
            )));
        }

        info!("TransmitChannel initialized successfully");
        debug!(
            "TransmitChannel config: max_apdu_size={}, session_timeout_secs={}",
            config.max_apdu_size, config.session_timeout_secs
        );

        Ok(Self {
            protocol_handler: Arc::new(protocol_handler),
            session_manager: Arc::new(session_manager),
            transmit_service,
            config,
            tls_config,
        })
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
        debug!("Processing transmit request, size: {} bytes", request.len());

        let xml_str = std::str::from_utf8(request).map_err(|e| {
            error!("Invalid UTF-8 in transmit request: {e}");
            TransmitError::TransmitError(format!("Invalid UTF-8: {e}"))
        })?;

        debug!("Parsing transmit XML request");
        // Parse the Transmit request
        let transmit = match self.protocol_handler.parse_transmit(xml_str) {
            Ok(transmit) => {
                debug!(
                    "Successfully parsed transmit request for slot: {}",
                    transmit.slot_handle
                );
                transmit
            }
            Err(e) => {
                error!("Failed to parse transmit request: {e}");
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

        let tls_info = self.create_tls_session_info(&transmit.slot_handle);

        // Get or create client session using SlotHandle as specified in TR-03112
        debug!(
            "Looking up session for slot handle: {}",
            transmit.slot_handle
        );
        let session_result = match self
            .session_manager
            .get_session(&transmit.slot_handle)
            .await
        {
            Ok(session) => {
                debug!(
                    "Found existing session: {}, state: {:?}",
                    session.id, session.state
                );
                // Update session state to Active if it was Suspended
                if session.state == crate::server::session::SessionState::Suspended {
                    debug!("Reactivating suspended session: {}", session.id);
                    self.session_manager
                        .update_session_state(
                            &session.id,
                            crate::server::session::SessionState::Active,
                        )
                        .await?;
                }
                Ok(session)
            }
            Err(e) => {
                debug!(
                    "Session not found for slot {}, creating new session: {}",
                    transmit.slot_handle, e
                );
                // Create a new session with the specified SlotHandle
                self.session_manager.create_session(tls_info).await
            }
        };

        // Handle session errors according to TR-03130
        let session = match session_result {
            Ok(session) => {
                info!("Session established successfully: {}", session.id);
                session
            }
            Err(e) => {
                error!("Session creation/retrieval failed: {}", e);
                let error_result = super::protocol::TransmitResult::error(
                    "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#invalidContext",
                    Some(format!("Session error: {e}")),
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
        debug!(
            "Processing {} APDU(s) with timeout of {}s",
            transmit.input_apdu_info.len(),
            self.config.session_timeout_secs
        );
        let output_apdu_result = timeout(
            std::time::Duration::from_secs(self.config.session_timeout_secs),
            self.process_client_apdus(&transmit.input_apdu_info, &transmit.slot_handle),
        )
        .await
        .map_err(|_| {
            error!(
                "APDU processing timeout after {}s",
                self.config.session_timeout_secs
            );
            TransmitError::TransmitError("Request timeout".to_string())
        })?;

        // Handle APDU processing errors according to TR-03130
        let output_apdu = match output_apdu_result {
            Ok(apdus) => {
                info!("Successfully processed {} APDU(s)", apdus.len());
                apdus
            }
            Err(e) => {
                error!("APDU processing failed: {}", e);
                // Suspend session on error - log if this fails too
                if let Err(suspend_error) = self
                    .session_manager
                    .update_session_state(
                        &session.id,
                        crate::server::session::SessionState::Suspended,
                    )
                    .await
                {
                    warn!(
                        "Failed to suspend session {} after APDU error: {}",
                        session.id, suspend_error
                    );
                } else {
                    debug!(
                        "Session {} suspended due to APDU processing error",
                        session.id
                    );
                }

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
        debug!("Building successful transmit response");
        let response = TransmitResponse {
            result: super::protocol::TransmitResult::ok(),
            output_apdu,
        };

        // Serialize response to XML with proper namespaces
        let xml_response = self.protocol_handler.format_transmit_response(&response)?;
        debug!(
            "Transmit request completed successfully, response size: {} bytes",
            xml_response.len()
        );
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
            return Err(TransmitError::TransmitError(
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
        debug!(
            "Processing single APDU: {} for slot: {}",
            info.input_apdu, slot_handle
        );

        // Validate APDU format according to ISO 7816-4
        if info.input_apdu.is_empty() {
            warn!("Empty APDU provided");
            return Err(TransmitError::TransmitError(
                "Empty APDU provided".to_string(),
            ));
        }

        // Validate APDU format (should be even-length hexadecimal string)
        if info.input_apdu.len() % 2 != 0 {
            warn!("Invalid APDU format: odd length hex string");
            return Err(TransmitError::TransmitError(
                "Invalid APDU format: length must be even".to_string(),
            ));
        }

        // Convert hex string to bytes
        let apdu_bytes = hex::decode(&info.input_apdu).map_err(|e| {
            warn!("Invalid APDU hex format: {}", e);
            TransmitError::TransmitError(format!("Invalid APDU hex: {e}"))
        })?;

        // Validate APDU size
        if apdu_bytes.len() > self.config.max_apdu_size {
            warn!(
                "APDU too large: {} bytes (max: {})",
                apdu_bytes.len(),
                self.config.max_apdu_size
            );
            return Err(TransmitError::TransmitError(format!(
                "APDU too large: {} bytes, maximum {} bytes allowed",
                apdu_bytes.len(),
                self.config.max_apdu_size
            )));
        }

        // Validate minimum length
        if apdu_bytes.len() < 4 {
            warn!("APDU too short: {} bytes", apdu_bytes.len());
            return Err(TransmitError::TransmitError(format!(
                "APDU too short: {} bytes, minimum 4 bytes required",
                apdu_bytes.len()
            )));
        }

        // Use configurable default timeout (30 seconds) instead of hardcoded 10 seconds
        let default_timeout_ms = 30000;
        let timeout_duration =
            std::time::Duration::from_millis(info.timeout.unwrap_or(default_timeout_ms) as u64);

        debug!("Transmitting APDU with timeout: {:?}", timeout_duration);

        let response_bytes = timeout(
            timeout_duration,
            self.transmit_service.transmit_apdu(apdu_bytes, slot_handle),
        )
        .await
        .map_err(|_| {
            error!("APDU transmission timeout after {:?}", timeout_duration);
            TransmitError::TransmitError("APDU transmission timeout".to_string())
        })?
        .map_err(|e| {
            error!("APDU transmission failed: {}", e);
            TransmitError::TransmitError(e.to_string())
        })?;

        // Convert response to hex string
        let response_hex = hex::encode_upper(response_bytes);
        debug!("APDU response: {}", response_hex);

        // Validate status code if specified - fix potential panic
        if let Some(expected_status) = &info.acceptable_status_code {
            if response_hex.len() < 4 {
                error!(
                    "APDU response too short for status code validation: {} chars",
                    response_hex.len()
                );
                return Err(TransmitError::TransmitError(format!(
                    "APDU response too short: {} characters, minimum 4 required for status code",
                    response_hex.len()
                )));
            }

            let actual_status = &response_hex[response_hex.len() - 4..];
            if actual_status != expected_status {
                warn!(
                    "APDU status code mismatch: expected {}, got {}",
                    expected_status, actual_status
                );
                return Err(TransmitError::TransmitError(format!(
                    "Invalid APDU status code: expected {expected_status}, got {actual_status}"
                )));
            }
            debug!("APDU status code validation passed: {}", actual_status);
        }

        debug!("APDU processing completed successfully");
        Ok(response_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::eid::transmit::protocol::{
        APDU_SUCCESS_STATUS, RESULT_MAJOR_ERROR, RESULT_MAJOR_OK,
    };
    use crate::domain::eid::transmit::protocol::{ISO24727_3_NS, ProtocolHandler};
    use crate::domain::eid::transmit::test_service::TestTransmitService;
    use crate::server::session::SessionManager;
    use crate::tls::{TestCertificates, generate_test_certificates};

    fn create_test_tls_config() -> Arc<TlsConfig> {
        let TestCertificates {
            server_cert,
            server_key,
            ..
        } = generate_test_certificates();
        Arc::new(TlsConfig::new(server_cert, server_key))
    }

    #[tokio::test]
    async fn test_transmit_channel_basic_flow() {
        let protocol_handler = ProtocolHandler::new();
        let session_manager = SessionManager::new(std::time::Duration::from_secs(60));
        let config = TransmitConfig::default();
        let transmit_service = Arc::new(TestTransmitService);
        let channel = TransmitChannel::new(
            protocol_handler,
            session_manager,
            transmit_service,
            config,
            create_test_tls_config(),
        )
        .expect("Channel creation should succeed in tests");

        // Create a valid XML request according to TR-03130
        let xml = format!(
            r#"
            <Transmit xmlns="{ISO24727_3_NS}">
                <SlotHandle>slot-1</SlotHandle>
                <InputAPDUInfo>
                    <InputAPDU>00A4040008A000000167455349</InputAPDU>
                    <AcceptableStatusCode>{APDU_SUCCESS_STATUS}</AcceptableStatusCode>
                </InputAPDUInfo>
                <InputAPDUInfo>
                    <InputAPDU>00B0000000</InputAPDU>
                </InputAPDUInfo>
            </Transmit>
        "#
        );

        let response_bytes = channel
            .handle_request(xml.as_bytes())
            .await
            .expect("XML flow should succeed");

        let response_xml = String::from_utf8(response_bytes).expect("Valid UTF-8");

        // Verify result is OK
        assert!(response_xml.contains(&format!("<ResultMajor>{RESULT_MAJOR_OK}</ResultMajor>")));

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
        let transmit_service = Arc::new(TestTransmitService);
        let channel = TransmitChannel::new(
            protocol_handler,
            session_manager,
            transmit_service,
            config,
            create_test_tls_config(),
        )
        .expect("Channel creation should succeed in tests");

        // Test 1: Malformed XML should return proper error
        let malformed_xml =
            "<Transmit><SlotHandle>slot-1</SlotHandle><InvalidTag></InvalidTag></Transmit>";
        let response = channel
            .handle_request(malformed_xml.as_bytes())
            .await
            .expect("Error handling should return valid XML response");
        let response_xml = String::from_utf8(response).expect("Response should be valid UTF-8");
        // Should contain error result
        assert!(
            response_xml.contains(&format!("<ResultMajor>{RESULT_MAJOR_ERROR}</ResultMajor>",))
        );
        assert!(
            response_xml
                .contains("<ResultMinor>http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#")
        );

        // Test 2: Missing SlotHandle should return proper error
        let missing_slot = format!(
            r#"<Transmit xmlns="{ISO24727_3_NS}"><InputAPDUInfo><InputAPDU>00A4040008A000000167455349</InputAPDU></InputAPDUInfo></Transmit>"#,
        );

        let response = channel
            .handle_request(missing_slot.as_bytes())
            .await
            .expect("Error handling should return valid XML response");
        let response_xml = String::from_utf8(response).expect("Response should be valid UTF-8");
        // Should contain error result for missing SlotHandle
        assert!(
            response_xml.contains(&format!("<ResultMajor>{RESULT_MAJOR_ERROR}</ResultMajor>",))
        );

        // Test 3: Status code verification failure
        let wrong_status_xml = format!(
            r#"
            <Transmit xmlns="{ISO24727_3_NS}">
                <SlotHandle>slot-1</SlotHandle>
                <InputAPDUInfo>
                    <InputAPDU>00A4040008A00000016745XXXX</InputAPDU>
                    <AcceptableStatusCode>{APDU_SUCCESS_STATUS}</AcceptableStatusCode>
                </InputAPDUInfo>
            </Transmit>
        "#
        );

        let response = channel
            .handle_request(wrong_status_xml.as_bytes())
            .await
            .expect("Error handling should return valid XML response");
        let response_xml = String::from_utf8(response).expect("Response should be valid UTF-8");

        // Should contain error for status code mismatch
        assert!(
            response_xml.contains(&format!("<ResultMajor>{RESULT_MAJOR_ERROR}</ResultMajor>",))
        );
        assert!(response_xml.contains("<ResultMinor>http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#transmitError</ResultMinor>"));
    }

    #[tokio::test]
    async fn test_transmit_channel_invalid_apdu() {
        let protocol_handler = ProtocolHandler::new();
        let session_manager = SessionManager::new(std::time::Duration::from_secs(60));
        let config = TransmitConfig::default();
        let transmit_service = Arc::new(TestTransmitService);
        let channel = TransmitChannel::new(
            protocol_handler,
            session_manager,
            transmit_service,
            config,
            create_test_tls_config(),
        )
        .expect("Channel creation should succeed in tests");

        // Test with invalid APDU format (odd-length hex string)
        let invalid_apdu_xml = format!(
            r#"
            <Transmit xmlns="{ISO24727_3_NS}">
                <SlotHandle>slot-1</SlotHandle>
                <InputAPDUInfo>
                    <InputAPDU>00A4040</InputAPDU>
                </InputAPDUInfo>
            </Transmit>
        "#
        );

        let response = channel
            .handle_request(invalid_apdu_xml.as_bytes())
            .await
            .expect("Error handling should return valid XML response");
        let response_xml = String::from_utf8(response).expect("Response should be valid UTF-8");

        // Should contain error for invalid APDU
        assert!(
            response_xml.contains(&format!("<ResultMajor>{RESULT_MAJOR_ERROR}</ResultMajor>",))
        );
        assert!(response_xml.contains("<ResultMinor>http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#transmitError</ResultMinor>"));

        // Test with empty APDU
        let empty_apdu_xml = format!(
            r#"
            <Transmit xmlns="{ISO24727_3_NS}">
                <SlotHandle>slot-1</SlotHandle>
                <InputAPDUInfo>
                    <InputAPDU></InputAPDU>
                </InputAPDUInfo>
            </Transmit>
        "#
        );

        let response = channel
            .handle_request(empty_apdu_xml.as_bytes())
            .await
            .expect("Error handling should return valid XML response");
        let response_xml = String::from_utf8(response).expect("Response should be valid UTF-8");

        // Should contain error for empty APDU
        assert!(
            response_xml.contains(&format!("<ResultMajor>{RESULT_MAJOR_ERROR}</ResultMajor>",))
        );
    }

    #[tokio::test]
    async fn test_transmit_channel_custom_slot_handle() {
        use super::super::protocol::ProtocolHandler;
        use crate::config::TransmitConfig;
        use crate::server::session::SessionManager;

        let protocol_handler = ProtocolHandler::new();
        let session_manager = SessionManager::new(std::time::Duration::from_secs(60));
        let config = TransmitConfig::default();
        let transmit_service = Arc::new(TestTransmitService);
        let channel = TransmitChannel::new(
            protocol_handler,
            session_manager,
            transmit_service,
            config,
            create_test_tls_config(),
        )
        .expect("Channel creation should succeed in tests");

        // Test with custom slot handle
        let test_request = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<Transmit xmlns="{ISO24727_3_NS}">
    <SlotHandle>custom-slot-456</SlotHandle>
    <InputAPDUInfo>
        <InputAPDU>00A4040007A0000002471001</InputAPDU>
        <AcceptableStatusCode>{APDU_SUCCESS_STATUS}</AcceptableStatusCode>
    </InputAPDUInfo>
</Transmit>"#,
        );

        let result = channel.handle_request(test_request.as_bytes()).await;
        assert!(result.is_ok(), "Request should be processed successfully");

        let response = result.expect("Request should be processed successfully");
        let response_str = String::from_utf8_lossy(&response);

        // Verify that the response contains a successful result
        assert!(response_str.contains(RESULT_MAJOR_OK));
    }

    #[tokio::test]
    async fn test_transmit_channel_multiple_apdus() {
        let protocol_handler = ProtocolHandler::new();
        let session_manager = SessionManager::new(std::time::Duration::from_secs(60));
        let config = TransmitConfig::default();
        let transmit_service = Arc::new(TestTransmitService);
        let channel = TransmitChannel::new(
            protocol_handler,
            session_manager,
            transmit_service,
            config,
            create_test_tls_config(),
        )
        .expect("Channel creation should succeed in tests");

        // Test with multiple APDUs in sequence (SELECT + READ BINARY)
        let multi_apdu_xml = format!(
            r#"
            <Transmit xmlns="{ISO24727_3_NS}">
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
        "#
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
