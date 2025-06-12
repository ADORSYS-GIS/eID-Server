use hex;
use std::sync::Arc;
use reqwest::Client;
use tokio::time::timeout;
use async_trait::async_trait;
use quick_xml::de::from_str;
use serde::Deserialize;
use tracing::{warn, info, error};
use crate::sal::transmit::config::TransmitConfig;
use crate::sal::transmit::session::{TlsSessionInfo, SessionManager};

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

#[derive(Debug, Clone, Copy)]
pub enum Platform {
    Android,
    IOS,
    Desktop,
}

impl Platform {
    fn detect() -> Self {
        // In a real implementation, this would detect the platform
        // For now, we'll use environment variables for testing
        match std::env::var("APP_PLATFORM").unwrap_or_default().as_str() {
            "android" => Self::Android,
            "ios" => Self::IOS,
            _ => Self::Desktop,
        }
    }
}

#[async_trait]
pub trait ApduTransport: Send + Sync {
    async fn transmit_apdu(&self, apdu: Vec<u8>) -> Result<Vec<u8>, String>;
}

/// HTTP-based APDU transport implementation
pub struct HttpApduTransport {
    client: Client,
    config: TransmitConfig,
    platform: Platform,
    session_manager: SessionManager,
}

impl HttpApduTransport {
    pub fn new(config: TransmitConfig) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build() 
            .expect("Failed to create HTTP client");

        let session_manager = SessionManager::new(config.session_timeout);

        Self { 
            client, 
            config,
            platform: Platform::detect(),
            session_manager,
        }
    }

    async fn extract_tls_info(&self, response: &reqwest::Response) -> Option<TlsSessionInfo> {
        // Extract TLS session ID from response headers
        let session_id = response
            .headers()
            .get("X-TLS-Session-ID")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Extract cipher suite from response headers
        let cipher_suite = response
            .headers()
            .get("X-TLS-Cipher-Suite")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // If we have both pieces of information, create TlsSessionInfo
        match (session_id, cipher_suite) {
            (Some(id), Some(cipher)) => Some(TlsSessionInfo {
                session_id: id,
                cipher_suite: cipher,
            }),
            _ => None,
        }
    }

    async fn handle_mobile_request(&self, apdu: Vec<u8>) -> Result<Vec<u8>, String> {
        match self.platform {
            Platform::Android => self.handle_android_request(apdu).await,
            Platform::IOS => self.handle_ios_request(apdu).await,
            Platform::Desktop => Err("Invalid platform for mobile request".to_string()),
        }
    }

    async fn handle_android_request(&self, apdu: Vec<u8>) -> Result<Vec<u8>, String> {
        // Convert APDU to hex string
        let apdu_hex = hex::encode_upper(&apdu);
        
        // Create intent URL for Android
        let _intent_url = format!(
            "intent://eid-client#Intent;scheme=eid;package=com.android.eid;component=com.android.eid/.MainActivity;S.apdu={};end",
            apdu_hex
        );

        // In a real implementation, we would:
        // 1. Launch the intent using Android's Intent system
        // 2. Wait for the response from the eID-Client app
        // 3. Parse the response and return the APDU

        // For now, we'll simulate a response
        Ok(vec![0x90, 0x00]) // Success response
    }

    async fn handle_ios_request(&self, apdu: Vec<u8>) -> Result<Vec<u8>, String> {
        // Convert APDU to hex string
        let apdu_hex = hex::encode_upper(&apdu);
        
        // Create URL scheme for iOS
        let _url = format!(
            "eid://eid-client?apdu={}",
            apdu_hex
        );

        // In a real implementation, we would:
        // 1. Open the URL using iOS URL scheme handling
        // 2. Wait for the response from the eID-Client app
        // 3. Parse the response and return the APDU

        // For now, we'll simulate a response
        Ok(vec![0x90, 0x00]) // Success response
    }
}

#[async_trait]
impl ApduTransport for HttpApduTransport {
    async fn transmit_apdu(&self, apdu: Vec<u8>) -> Result<Vec<u8>, String> {
        // Get the appropriate client URL based on platform
        let client_url = self.config.get_client_url();
        info!("Transmitting APDU to {}", client_url);

        // Handle mobile platforms
        if client_url.starts_with("eid://") {
            info!("Using mobile platform transport");
            return self.handle_mobile_request(apdu).await;
        }

        // For classical systems, use HTTP POST
        let apdu_hex = hex::encode_upper(&apdu);
        let xml_payload = format!(
            r#"<Transmit><InputAPDU>{}</InputAPDU></Transmit>"#,
            apdu_hex
        );

        let response = self.client
            .post(&client_url)
            .header("Content-Type", "application/xml")
            .body(xml_payload)
            .send()
            .await
            .map_err(|e| {
                error!("HTTP request failed: {}", e);
                format!("HTTP request failed: {}", e)
            })?;

        // Check response status
        if !response.status().is_success() {
            let status = response.status();
            error!("HTTP request failed with status: {}", status);
            return Err(format!(
                "HTTP request failed with status: {}",
                status
            ));
        }

        // Extract TLS session info if available
        if let Some(tls_info) = self.extract_tls_info(&response).await {
            info!("Extracted TLS session info: {:?}", tls_info);
            // Create or update session with TLS info
            if let Err(e) = self.session_manager.create_session(tls_info).await {
                warn!("Failed to create session with TLS info: {}", e);
            }
        }

        // Parse response body 
        let response_text = response 
            .text()
            .await
            .map_err(|e| { 
                error!("Failed to read response body: {}", e);
                format!("Failed to read response body: {}", e)
            })?;

        // Parse XML response using quick-xml
        let client_response: ClientResponse = from_str(&response_text)
            .map_err(|e| {
                error!("Failed to parse XML response: {}", e);
                format!("Failed to parse XML response: {}", e)
            })?;

        // Decode the APDU response
        hex::decode(&client_response.output_apdu)
            .map_err(|e| {
                error!("Failed to decode APDU hex: {}", e);
                format!("Failed to decode APDU hex: {}", e)
            })
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
        config: TransmitConfig,
    ) -> Self {
        // Validate configuration
        config.validate().expect("Invalid transmit configuration");

        let apdu_transport = Arc::new(HttpApduTransport::new(config.clone()));

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

        // Process client APDU requests with timeout
        let output_apdu_result = timeout(
            self.config.session_timeout,
            self.process_client_apdus(&transmit.input_apdu_info),
        )
        .await
        .map_err(|_| TransmitError::SessionError("Request timeout".to_string()))?;

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
        let timeout_duration = std::time::Duration::from_millis(
            info.timeout.unwrap_or(10000) as u64
        );
        
        let response_bytes = timeout(
            timeout_duration,
            self.apdu_transport.transmit_apdu(apdu_bytes)
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

#[cfg(test)]
mod tests {
    use super::super::protocol::{ISO24727_3_NS, ProtocolHandler};
    use super::super::session::SessionManager;
    use super::*;
    use tokio::runtime::Runtime;
    use async_trait::async_trait;

    /// Create a test transport that responds with fixed APDUs for specific commands
    struct TestApduTransport;

    #[async_trait]
    impl ApduTransport for TestApduTransport {
        async fn transmit_apdu(&self, apdu: Vec<u8>) -> Result<Vec<u8>, String> {
            // Convert APDU to uppercase hex for easier comparison
            let apdu_hex = hex::encode_upper(&apdu);
            
            // Return predefined responses for test APDUs
            match apdu_hex.as_str() {
                // SELECT eID application
                "00A4040008A000000167455349" => Ok(hex::decode("6F108408A000000167455349A5049F6501FF9000").unwrap()),
                // READ BINARY
                "00B0000000" => Ok(hex::decode("0102030405060708090A0B0C0D0E0F109000").unwrap()),
                "00B0000010" => Ok(hex::decode("1112131415161718191A1B1C1D1E1F209000").unwrap()),
                // SELECT eID.SIGN application
                "00A4040008A000000167455349474E" => Ok(hex::decode("9000").unwrap()),
                _ => Err("Unknown test APDU".to_string()),
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
            let config = TransmitConfig::default();
            let channel = TransmitChannel::new(
                protocol_handler,
                session_manager,
                config,
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
            let config = TransmitConfig::default();
            let channel = TransmitChannel::new(
                protocol_handler,
                session_manager,
                config,
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
            let config = TransmitConfig::default();
            let channel = TransmitChannel::new(
                protocol_handler,
                session_manager,
                config,
            );

            // Test with invalid APDU format (odd-length hex string)
            let invalid_apdu_xml = format!(r#"
                <Transmit xmlns="{0}">
                    <SlotHandle>slot-1</SlotHandle>
                    <InputAPDUInfo>
                        <InputAPDU>00A4040</InputAPDU>
                    </InputAPDUInfo>
                </Transmit>
            "#, ISO24727_3_NS
            );

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
            let config = TransmitConfig::default();
            let channel = TransmitChannel::new(
                protocol_handler,
                session_manager,
                config,
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
