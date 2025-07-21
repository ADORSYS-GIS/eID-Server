use base64::Engine;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use color_eyre::Result;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::default::Default;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use super::certificate::{CardCommunicator, CertificateStore, CryptoProvider};
use super::models::{
    AuthError, ClientResponse, DIDAuthenticateRequest, DIDAuthenticateResponse,
    ResponseProtocolData, ServerInfo,
};
use super::ports::{
    DIDAuthenticate, EIDService, EidService, TransmitError, TransmitResult, TransmitService,
};
use super::session_manager::{InMemorySessionManager, RedisSessionManager, SessionManager};
use super::transmit::protocol::{APDU_SUCCESS_STATUS, ProtocolHandler};
use crate::config::TransmitConfig;
use crate::eid::common::models::{
    AttributeRequester, OperationsRequester, ResultCode, ResultMajor, SessionResponse,
};
use crate::eid::use_id::model::{Psk, UseIDRequest, UseIDResponse};
use async_trait::async_trait;
use hex;
use quick_xml::de::from_str;
use reqwest::Client;

// Configuration for the eID Service
#[derive(Clone, Debug)]
pub struct EIDServiceConfig {
    /// Maximum number of concurrent sessions
    pub max_sessions: usize,
    /// Session timeout in minutes
    pub session_timeout_minutes: i64,
    /// Optional eCard server address to return in responses
    pub ecard_server_address: Option<String>,
    /// Redis connection URL (optional, if using Redis backend)
    pub redis_url: Option<String>,
}

impl Default for EIDServiceConfig {
    fn default() -> Self {
        Self {
            max_sessions: 1000,
            session_timeout_minutes: 5,
            ecard_server_address: Some("https://localhost:3000".to_string()),
            redis_url: None,
        }
    }
}

/// Session information stored by the server
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub expiry: DateTime<Utc>,
    pub psk: String,
    pub operations: Vec<String>,
}

impl SessionInfo {
    pub fn new(id: String, psk: String, operations: Vec<String>, timeout_minutes: i64) -> Self {
        SessionInfo {
            id,
            expiry: Utc::now() + ChronoDuration::minutes(timeout_minutes),
            psk,
            operations,
        }
    }
}

/// Main service for handling useID requests
#[derive(Clone, Debug)]
pub struct UseidService {
    pub config: EIDServiceConfig,
    pub session_manager: Arc<dyn SessionManager>,
}

impl UseidService {
    pub fn new(config: EIDServiceConfig) -> Self {
        let session_manager: Arc<dyn SessionManager> = if let Some(redis_url) = &config.redis_url {
            Arc::new(
                RedisSessionManager::new(redis_url, config.session_timeout_minutes)
                    .expect("Failed to initialize RedisSessionManager"),
            )
        } else {
            Arc::new(InMemorySessionManager::new())
        };

        Self {
            config,
            session_manager,
        }
    }

    /// Generate a random PSK for secure communication
    pub fn generate_psk(&self) -> String {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Helper function to extract required operations from OperationsRequester
    pub fn get_required_operations(ops: &OperationsRequester) -> Vec<String> {
        let mut required = Vec::new();
        if ops.document_type == AttributeRequester::REQUIRED {
            required.push("DocumentType".to_string());
        }
        if ops.issuing_state == AttributeRequester::REQUIRED {
            required.push("IssuingState".to_string());
        }
        if ops.date_of_expiry == AttributeRequester::REQUIRED {
            required.push("DateOfExpiry".to_string());
        }
        if ops.given_names == AttributeRequester::REQUIRED {
            required.push("GivenNames".to_string());
        }
        if ops.family_names == AttributeRequester::REQUIRED {
            required.push("FamilyNames".to_string());
        }
        if ops.artistic_name == AttributeRequester::REQUIRED {
            required.push("ArtisticName".to_string());
        }
        if ops.academic_title == AttributeRequester::REQUIRED {
            required.push("AcademicTitle".to_string());
        }
        if ops.date_of_birth == AttributeRequester::REQUIRED {
            required.push("DateOfBirth".to_string());
        }
        if ops.place_of_birth == AttributeRequester::REQUIRED {
            required.push("PlaceOfBirth".to_string());
        }
        if ops.nationality == AttributeRequester::REQUIRED {
            required.push("Nationality".to_string());
        }
        if ops.birth_name == AttributeRequester::REQUIRED {
            required.push("BirthName".to_string());
        }
        if ops.place_of_residence == AttributeRequester::REQUIRED {
            required.push("PlaceOfResidence".to_string());
        }
        if let Some(community_id) = &ops.community_id
            && *community_id == AttributeRequester::REQUIRED
        {
            required.push("CommunityID".to_string());
        }
        if let Some(residence_permit_id) = &ops.residence_permit_id
            && *residence_permit_id == AttributeRequester::REQUIRED
        {
            required.push("ResidencePermitID".to_string());
        }
        if ops.restricted_id == AttributeRequester::REQUIRED {
            required.push("RestrictedID".to_string());
        }
        if ops.age_verification == AttributeRequester::REQUIRED {
            required.push("AgeVerification".to_string());
        }
        if ops.place_verification == AttributeRequester::REQUIRED {
            required.push("PlaceVerification".to_string());
        }
        required
    }
}

// Implement the EIDService trait for UseidService
#[async_trait]
impl EIDService for UseidService {
    async fn handle_use_id(&self, request: UseIDRequest) -> Result<UseIDResponse> {
        // Validate the request: Check if any operations are REQUIRED
        let required_operations = Self::get_required_operations(&request._use_operations);
        debug!("Required operations: {:?}", required_operations);

        // Check if we've reached the maximum number of sessions
        if self.session_manager.session_count().await? >= self.config.max_sessions {
            return Err(color_eyre::eyre::eyre!("Maximum session limit reached"));
        }

        // Generate session ID
        let session_id = self.session_manager.generate_session_id().await?;
        if session_id.is_empty() {
            error!("Generated empty session ID");
            return Err(color_eyre::eyre::eyre!("Failed to generate session ID"));
        }
        debug!("Generated session_id: {}", session_id);

        // Generate or use provided PSK
        let psk = match &request._psk {
            Some(psk) => {
                // Check if PSK ID matches an existing session
                if self.session_manager.get_session(&psk.id).await?.is_some() {
                    error!("Attempted to reuse session ID: {}", psk.id);
                    return Err(color_eyre::eyre::eyre!("Session ID reuse detected"));
                }
                psk.key.clone()
            }
            None => self.generate_psk(),
        };
        if psk.is_empty() {
            error!("Generated empty PSK");
            return Err(color_eyre::eyre::eyre!("Failed to generate PSK"));
        }
        debug!("Generated PSK: {}", psk);

        // Store session with PSK
        let session_info = SessionInfo::new(
            session_id.clone(),
            psk.clone(),
            required_operations.clone(),
            self.config.session_timeout_minutes,
        );

        // Store the session
        self.session_manager
            .store_session(session_info.clone())
            .await?;
        info!(
            "Created new session: {}, expires: {}, operations: {:?}",
            session_id, session_info.expiry, session_info.operations
        );

        // Construct TcTokenURL
        let tc_token_url = self.config.ecard_server_address.clone().map(|addr| {
            format!(
                "{}?sessionId={}&binding=urn:liberty:paos:2006-08",
                addr.trim_end_matches('/'),
                session_id
            )
        });
        debug!(
            "Config ecard_server_address: {:?}",
            self.config.ecard_server_address
        );
        debug!("Constructed tc_token_url: {:?}", tc_token_url);

        // Validate TcTokenURL
        let tc_token_url = tc_token_url.ok_or_else(|| {
            error!("eCard server address not configured");
            color_eyre::eyre::eyre!("eCard server address not configured")
        })?;
        // Remove XML escaping since CDATA will handle raw characters
        debug!("Raw tc_token_url: {}", tc_token_url);

        if !tc_token_url.starts_with("https://") {
            warn!("TcTokenURL is not HTTPS: {}", tc_token_url);
        }

        // Build response
        let response = UseIDResponse {
            result: ResultMajor {
                result_major: ResultCode::Ok.to_string(),
            },
            session: SessionResponse {
                id: session_id.clone(),
            },
            ecard_server_address: Some(tc_token_url),
            psk: Psk {
                id: session_id,
                key: psk,
            },
        };
        debug!("Response before return: {:?}", response);

        // Validate response
        if response.session.id.is_empty() {
            error!("Response contains empty session ID");
            return Err(color_eyre::eyre::eyre!(
                "Response contains empty session ID"
            ));
        }
        if response.psk.id.is_empty() || response.psk.key.is_empty() {
            error!("Response contains empty PSK fields");
            return Err(color_eyre::eyre::eyre!(
                "Response contains empty PSK fields"
            ));
        }

        Ok(response)
    }
}

// Implement the EidService trait for UseidService
impl EidService for UseidService {
    fn get_server_info(&self) -> ServerInfo {
        ServerInfo::default()
    }
}

#[derive(Debug, Clone)]
pub struct DIDAuthenticateService {
    certificate_store: CertificateStore,
    crypto_provider: CryptoProvider,
    card_communicator: CardCommunicator,
    session_manager: Arc<dyn SessionManager>,
}

impl DIDAuthenticateService {
    pub fn new(
        certificate_store: CertificateStore,
        crypto_provider: CryptoProvider,
        card_communicator: CardCommunicator,
        session_manager: Arc<dyn SessionManager>,
    ) -> Self {
        Self {
            certificate_store,
            crypto_provider,
            card_communicator,
            session_manager,
        }
    }

    pub async fn new_with_defaults(session_manager: Arc<dyn SessionManager>) -> Self {
        dotenvy::dotenv().expect("Failed to load .env file");
        let certificate_store = CertificateStore::new();

        // Load CVCA as trusted root
        let cvca_path = std::env::var("CVCA_PATH").expect("CVCA_PATH not set in .env");
        let cvca_data = fs::read(&cvca_path).expect("Failed to read CVCA certificate");
        if let Err(e) = certificate_store.add_trusted_root(cvca_data).await {
            tracing::error!("Failed to add trusted root certificate: {:?}", e);
            panic!("Cannot proceed without trusted CVCA certificate");
        }

        let ausweisapp2_endpoint =
            std::env::var("AUSWEISAPP2_ENDPOINT").expect("AUSWEISAPP2_ENDPOINT not set in .env");

        Self {
            certificate_store: certificate_store.clone(),
            crypto_provider: CryptoProvider::default(),
            card_communicator: CardCommunicator::new(&ausweisapp2_endpoint, certificate_store),
            session_manager,
        }
    }

    pub async fn authenticate(&self, request: DIDAuthenticateRequest) -> DIDAuthenticateResponse {
        info!(
            "Starting DID authentication process for request: {:?}",
            request
        );

        match self
            .authenticate_internal(request, self.session_manager.clone())
            .await
        {
            Ok(response_data) => {
                info!("DID authentication completed successfully");
                DIDAuthenticateResponse::success(response_data)
            }
            Err(e) => {
                error!("DID authentication failed: {:?}", e);
                DIDAuthenticateResponse::error(&e)
            }
        }
    }

    async fn authenticate_internal(
        &self,
        request: DIDAuthenticateRequest,
        session_manager: Arc<dyn SessionManager>,
    ) -> Result<ResponseProtocolData, AuthError> {
        request.validate()?;
        debug!("Request validation passed");

        // Validate session
        let session_id = request
            .connection_handle
            .channel_handle
            .as_ref()
            .ok_or_else(|| AuthError::invalid_connection("Missing channel handle"))?;

        let session_info = session_manager
            .get_session(session_id)
            .await
            .map_err(|e| AuthError::internal_error(format!("Failed to acquire session: {e}")))?;

        let session_info = session_info.ok_or_else(|| {
            error!("Session {} not found", session_id);
            AuthError::invalid_connection("Invalid or expired session")
        })?;

        if session_info.expiry < Utc::now() {
            error!("Session {} expired at {}", session_id, session_info.expiry);
            return Err(AuthError::timeout_error("Session validation"));
        }

        let certificate_der = base64::engine::general_purpose::STANDARD
            .decode(&request.authentication_protocol_data.certificate_description)
            .map_err(|e| {
                AuthError::invalid_certificate(format!("Failed to decode certificate: {e}"))
            })?;

        let is_valid = self
            .certificate_store
            .validate_certificate_chain(certificate_der)
            .await?;
        if !is_valid {
            return Err(AuthError::invalid_certificate(
                "Certificate chain validation failed",
            ));
        }

        let personal_data = self
            .card_communicator
            .send_did_authenticate(
                &request.connection_handle,
                &request.did_name,
                &request.authentication_protocol_data,
            )
            .await?;

        // Generate authentication token
        let auth_token = self
            .crypto_provider
            .generate_challenge()
            .await?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        Ok(ResponseProtocolData {
            challenge: None,
            certificate: Some(
                request
                    .authentication_protocol_data
                    .certificate_description
                    .clone(),
            ),
            personal_data: Some(personal_data),
            authentication_token: Some(auth_token),
        })
    }
}

#[async_trait]
impl DIDAuthenticate for UseidService {
    async fn handle_did_authenticate(
        &self,
        request: DIDAuthenticateRequest,
    ) -> Result<DIDAuthenticateResponse, AuthError> {
        if let Err(e) = request.validate() {
            return Ok(DIDAuthenticateResponse {
                result_major: String::from(
                    "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error",
                ),
                result_minor: Some(format!(
                    "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError: {e}"
                )),
                authentication_protocol_data: ResponseProtocolData::default(),
                timestamp: Utc::now().timestamp() as u64,
            });
        }

        let did_service =
            DIDAuthenticateService::new_with_defaults(self.session_manager.clone()).await;
        Ok(did_service.authenticate(request).await)
    }
}

/// HTTP-based transmit service implementation
/// This service handles the business logic for APDU transmission including
/// HTTP client management, retry logic, XML serialization, and error handling
pub struct HttpTransmitService {
    client: Client,
    config: TransmitConfig,
}

impl HttpTransmitService {
    /// Creates a new HTTP transmit service
    pub fn new(config: TransmitConfig) -> TransmitResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.session_timeout_secs))
            .tls_built_in_root_certs(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .build()
            .map_err(|e| {
                TransmitError::InternalError(format!("Failed to create HTTP client: {e}"))
            })?;

        Ok(Self { client, config })
    }

    /// Serializes the APDU request to XML format
    fn serialize_request(&self, apdu: &[u8], slot_handle: &str) -> TransmitResult<String> {
        let apdu_hex = hex::encode_upper(apdu);
        let protocol_handler = ProtocolHandler::new();

        // Create a single APDU transmit request using the protocol handler
        let transmit_request = ProtocolHandler::create_single_apdu_request(
            slot_handle,
            &apdu_hex,
            Some(APDU_SUCCESS_STATUS),
        );

        // Serialize using the protocol handler
        protocol_handler.serialize_transmit_request(&transmit_request)
    }

    /// Parses the XML response from the eID-Client
    fn parse_response(&self, response_text: &str) -> TransmitResult<Vec<u8>> {
        let client_response: ClientResponse = from_str(response_text).map_err(|e| {
            TransmitError::TransmitError(format!("Failed to parse XML response: {e}"))
        })?;

        hex::decode(&client_response.output_apdu)
            .map_err(|e| TransmitError::TransmitError(format!("Failed to decode APDU hex: {e}")))
    }

    /// Sends a single HTTP request to the eID-Client
    async fn send_request(&self, xml_payload: &str) -> TransmitResult<String> {
        let response = self
            .client
            .post(&self.config.client_url)
            .header("Content-Type", "application/xml")
            .body(xml_payload.to_string())
            .send()
            .await
            .map_err(|e| TransmitError::TransmitError(format!("HTTP request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(TransmitError::TransmitError(format!(
                "HTTP request failed with status: {status}"
            )));
        }

        response
            .text()
            .await
            .map_err(|e| TransmitError::TransmitError(format!("Failed to read response body: {e}")))
    }
}

#[async_trait]
impl TransmitService for HttpTransmitService {
    async fn transmit_apdu(&self, apdu: Vec<u8>, slot_handle: &str) -> TransmitResult<Vec<u8>> {
        // Serialize the request
        let xml_payload = self.serialize_request(&apdu, slot_handle)?;

        // Send request with retries
        let mut retries = 0;
        let mut last_error = None;

        while retries < self.config.max_retries {
            match self.send_request(&xml_payload).await {
                Ok(response_text) => {
                    // Parse and return the response
                    return self.parse_response(&response_text);
                }
                Err(e) => {
                    error!("APDU transmission attempt {} failed: {}", retries + 1, e);
                    last_error = Some(e);
                    retries += 1;
                }
            }
        }

        // All retries failed
        Err(last_error
            .unwrap_or_else(|| TransmitError::TransmitError("All retries failed".to_string())))
    }
}

#[cfg(test)]
mod transmit_tests {
    use super::*;

    #[test]
    fn test_transmit_config_usage() {
        let transmit_config = TransmitConfig {
            client_url: "http://test.example.com".to_string(),
            session_timeout_secs: 60,
            max_apdu_size: 4096,
            max_retries: 3,
            allowed_cipher_suites: vec!["TLS_AES_128_GCM_SHA256".to_string()],
            max_requests_per_minute: 60,
            require_client_certificate: true,
            min_tls_version: "TLSv1.2".to_string(),
        };

        // Test that we can create a service directly with TransmitConfig
        let service = HttpTransmitService::new(transmit_config.clone())
            .expect("Service creation should succeed");
        assert_eq!(service.config.client_url, "http://test.example.com");
        assert_eq!(service.config.session_timeout_secs, 60);
        assert_eq!(service.config.max_retries, 3);
    }

    #[test]
    fn test_serialize_request() {
        let config = TransmitConfig {
            client_url: "http://test.example.com".to_string(),
            session_timeout_secs: 30,
            max_apdu_size: 4096,
            max_retries: 3,
            allowed_cipher_suites: vec!["TLS_AES_128_GCM_SHA256".to_string()],
            max_requests_per_minute: 60,
            require_client_certificate: true,
            min_tls_version: "TLSv1.2".to_string(),
        };

        let service = HttpTransmitService::new(config).expect("Service creation should succeed");
        let apdu = vec![0x00, 0xA4, 0x04, 0x00];
        let slot_handle = "test-slot";

        let xml = service
            .serialize_request(&apdu, slot_handle)
            .expect("Serialization should succeed");

        assert!(xml.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("<SlotHandle>test-slot</SlotHandle>"));
        assert!(xml.contains("<InputAPDU>00A40400</InputAPDU>"));
    }

    #[test]
    fn test_parse_response() {
        let config = TransmitConfig {
            client_url: "http://test.example.com".to_string(),
            session_timeout_secs: 30,
            max_apdu_size: 4096,
            max_retries: 3,
            allowed_cipher_suites: vec!["TLS_AES_128_GCM_SHA256".to_string()],
            max_requests_per_minute: 60,
            require_client_certificate: true,
            min_tls_version: "TLSv1.2".to_string(),
        };

        let service = HttpTransmitService::new(config).expect("Service creation should succeed");
        let response_xml = r#"<TransmitResponse><OutputAPDU>9000</OutputAPDU></TransmitResponse>"#;

        let result = service
            .parse_response(response_xml)
            .expect("Parsing should succeed");
        assert_eq!(result, vec![0x90, 0x00]);
    }
}
