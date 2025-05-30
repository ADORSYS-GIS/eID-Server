//! Service layer that provides the business logic of the domain.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use color_eyre::Result;
use rand::Rng;
use tracing::{debug, info, instrument, warn, error};
use std::default::Default;

use super::certificate::{CardCommunicator, CertificateStore, CryptoProvider};
use super::models::{AuthError, ConnectionHandle, DIDAuthenticateRequest, DIDAuthenticateResponse, ResponseProtocolData, ServerInfo};
use super::ports::{DIDAuthenticate, EIDService, EidService};
use crate::eid::common::models::{
    AttributeRequester, OperationsRequester, ResultCode, ResultMajor, SessionResponse,
};
use crate::eid::use_id::model::{Psk, UseIDRequest, UseIDResponse};

// Configuration for the eID Service
#[derive(Clone, Debug)]
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
    pub expiry: DateTime<Utc>,
    pub psk: Option<String>,
    pub operations: Vec<String>,
}

/// Main service for handling useID requests
#[derive(Clone, Debug)]
pub struct UseidService {
    pub config: EIDServiceConfig,
    pub sessions: Arc<RwLock<Vec<SessionInfo>>>,
}

#[derive(Clone, Debug)]
pub struct DIDAuthenticateService {
    certificate_store: CertificateStore,
    crypto_provider: CryptoProvider,
    card_communicator: CardCommunicator,
    max_retry_attempts: u32,
}

impl UseidService {
    pub fn new(config: EIDServiceConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Generate a random PSK for secure communication
    pub fn generate_psk(&self) -> String {
        // Generate a 32-character random PSK
        rand::rng()
            .sample_iter(&rand::distr::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
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
        if let Some(community_id) = &ops.community_id {
            if *community_id == AttributeRequester::REQUIRED {
                required.push("CommunityID".to_string());
            }
        }
        if let Some(residence_permit_id) = &ops.residence_permit_id {
            if *residence_permit_id == AttributeRequester::REQUIRED {
                required.push("ResidencePermitID".to_string());
            }
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
impl EIDService for UseidService {
    fn handle_use_id(&self, request: UseIDRequest) -> Result<UseIDResponse> {
        // Validate the request: Check if any operations are REQUIRED
        let required_operations = Self::get_required_operations(&request._use_operations);
        if required_operations.is_empty() {
            return Ok(UseIDResponse {
                result: ResultMajor {
                    result_major: "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok".to_string(),
                },
                ..Default::default()
            });
        }

        // Check if we've reached the maximum number of sessions
        if self.sessions.read().unwrap().len() >= self.config.max_sessions {
            return Ok(UseIDResponse {
                ..Default::default()
            });
        }

        fn generate_session_id() -> String {
            let timestamp = Utc::now()
                .timestamp_nanos_opt()
                .expect("System time out of range for timestamp_nanos_opt()");

            let random_part: String = rand::rng()
                .sample_iter(&rand::distr::Alphanumeric)
                .take(16)
                .map(char::from)
                .collect();

            format!("{timestamp}-{random_part}")
        }

        let session_id = generate_session_id();

        // Generate or use provided PSK
        let psk = match &request._psk {
            Some(psk) => psk.key.clone(),
            None => self.generate_psk(),
        };

        // Calculate session expiry time
        let expiry = Utc::now() + chrono::Duration::minutes(self.config.session_timeout_minutes);

        // Create session info
        let session_info = SessionInfo {
            id: session_id.clone(),
            expiry,
            psk: Some(psk.clone()),
            operations: required_operations,
        };

        // Store the session
        {
            let mut sessions = self.sessions.write().unwrap();

            // Remove expired sessions first
            let now = Utc::now();
            sessions.retain(|session| session.expiry > now);

            // Add new session
            sessions.push(session_info.clone());

            tracing::info!(
                "Created new session: {}, expires: {}, operations: {:?}",
                session_id,
                expiry,
                session_info.operations
            );
        }

        // Build response
        Ok(UseIDResponse {
            result: ResultMajor {
                result_major: ResultCode::Ok.to_string(),
            },
            session: SessionResponse {
                id: session_id.clone(),
            },
            ecard_server_address: self.config.ecard_server_address.clone(),
            psk: Psk {
                id: session_id,
                key: psk,
            },
        })
    }
}

// Implement the EidService trait for UseidService
impl EidService for UseidService {
    fn get_server_info(&self) -> ServerInfo {
        // Return default ServerInfo which contains the basic implementation details
        ServerInfo::default()
    }
}

impl DIDAuthenticateService {
    /// Creates a new DIDAuthenticateService with the provided components
    pub fn new(
        certificate_store: CertificateStore,
        crypto_provider: CryptoProvider,
        card_communicator: CardCommunicator,
    ) -> Self {
        Self {
            certificate_store,
            crypto_provider,
            card_communicator,
            max_retry_attempts: 3,
        }
    }
    
    /// Creates a service with default components for testing/development
    pub fn new_with_defaults() -> Self {
        Self::new(
            CertificateStore::default(),
            CryptoProvider::default(),
            CardCommunicator::default(),
        )
    }
    
    /// Main entry point for DID authentication
    #[instrument(skip(self), fields(did_name = %request.did_name))]
    pub async fn authenticate(&self, request: DIDAuthenticateRequest) -> DIDAuthenticateResponse {
        info!("Starting DID authentication process");
        
        match self.authenticate_internal(request).await {
            Ok(response_data) => {
                info!("DID authentication completed successfully");
                DIDAuthenticateResponse::success(response_data)
            }
            Err(error) => {
                error!("DID authentication failed: {}", error);
                DIDAuthenticateResponse::error(&error)
            }
        }
    }
    
    /// Internal authentication logic with proper error handling
    async fn authenticate_internal(&self, request: DIDAuthenticateRequest) -> Result<ResponseProtocolData, AuthError> {
        // 1. Validate the request
        request.validate()?;
        debug!("Request validation passed");
        
        // 2. Validate connection to card
        self.validate_connection(&request.connection_handle).await?;
        debug!("Connection validation passed");
        
        // 3. Perform Terminal Authentication
        let terminal_auth_result = self.perform_terminal_authentication(&request).await?;
        debug!("Terminal authentication completed");

        // 4. Read identity data
        let identity_data = self.read_identity_data(&request).await?;
        debug!("Identity data retrieved");
        
        // 5. Build response
        Ok(ResponseProtocolData::new()
            .with_personal_data(identity_data)
            .with_certificate(terminal_auth_result)
            .with_authentication_token("auth_token_12345".to_string()))
    }
    
    /// Validates the connection to the smart card
    #[instrument(skip(self))]
    async fn validate_connection(&self, handle: &ConnectionHandle) -> Result<(), AuthError> {
        debug!("Validating connection handle");
        
        if !handle.is_valid() {
            return Err(AuthError::InvalidConnection {
                reason: "Connection handle validation failed".to_string(),
            });
        }
        
        // Test communication with the card
        match self.card_communicator.send_apdu(handle, &[0x00, 0xA4, 0x04, 0x00]).await {
            Ok(response) => {
                if response.len() < 2 {
                    return Err(AuthError::CardCommunicationError {
                        reason: "Unexpected card response length".to_string(),
                    });
                }
                debug!("Card communication test successful");
                Ok(())
            }
            Err(e) => {
                warn!("Card communication test failed: {}", e);
                Err(e)
            }
        }
    }
    
    /// Performs Terminal Authentication (TA) phase
    #[instrument(skip(self))]
    async fn perform_terminal_authentication(&self, request: &DIDAuthenticateRequest) -> Result<String, AuthError> {
        info!("Starting Terminal Authentication");
        
        let certificate = &request.authentication_protocol_data.certificate_description;
        
        // 1. Validate our certificate chain - convert String to Vec<u8>
        let certificate_der = certificate.as_bytes().to_vec();
        let is_valid = self.certificate_store.validate_certificate_chain(certificate_der).await?;
        if !is_valid {
            return Err(AuthError::InvalidCertificate {
                details: "Certificate chain validation failed".to_string(),
            });
        }
        
        // 2. Get certificate permissions - convert String to &[u8]
        let certificate_bytes = certificate.as_bytes();
        let permissions = self.certificate_store.get_certificate_permissions(certificate_bytes).await?;
        debug!("Certificate permissions: {:?}", permissions);
        
        // 3. Generate challenge for card verification
        let challenge = self.crypto_provider.generate_challenge().await?;
        
        // 4. Send certificate and challenge to card
        let mut apdu = vec![0x00, 0x87]; // MSE:Set AT command
        apdu.extend_from_slice(&challenge);
        
        let response = self.card_communicator.send_apdu(&request.connection_handle, &apdu).await?;
        
        if response.len() < 2 || response[response.len()-2..] != [0x90, 0x00] {
            return Err(AuthError::AuthenticationFailed {
                reason: "Terminal authentication rejected by card".to_string(),
            });
        }
        
        info!("Terminal Authentication completed successfully");
        Ok(certificate.clone())
    }
    
    /// Establishes secure channel via Chip Authentication (CA)
    #[instrument(skip(self))]
    async fn establish_secure_channel(&self, request: &DIDAuthenticateRequest) -> Result<(Vec<u8>, Vec<u8>), AuthError> {
        info!("Starting Chip Authentication");
        
        // 1. Get card's public key
        let get_challenge = vec![0x00, 0x84, 0x00, 0x00, 0x08];
        let card_pubkey_response = self.card_communicator.send_apdu(&request.connection_handle, &get_challenge).await?;
        
        if card_pubkey_response.len() < 10 {
            return Err(AuthError::CryptoError {
                operation: "Failed to retrieve card public key".to_string(),
            });
        }
        
        let card_pubkey = &card_pubkey_response[..card_pubkey_response.len()-2];
        
        // 2. Generate our ephemeral key pair (mock)
        let our_private_key = vec![0x12, 0x34, 0x56, 0x78]; // Mock private key
        let our_public_key = vec![0x87, 0x65, 0x43, 0x21]; // Mock public key
        
        // 3. Send our public key to card
        let mut send_pubkey = vec![0x00, 0x86, 0x00, 0x00];
        send_pubkey.push(our_public_key.len() as u8);
        send_pubkey.extend_from_slice(&our_public_key);
        
        let pubkey_response = self.card_communicator.send_apdu(&request.connection_handle, &send_pubkey).await?;
        
        if pubkey_response.len() < 2 || pubkey_response[pubkey_response.len()-2..] != [0x90, 0x00] {
            return Err(AuthError::CryptoError {
                operation: "Card rejected our public key".to_string(),
            });
        }
        
        // 4. Perform ECDH key exchange
        let shared_secret = self.crypto_provider.perform_ecdh(&our_private_key, card_pubkey).await?;
        
        // 5. Derive session keys
        let (enc_key, mac_key) = self.crypto_provider.derive_session_keys(&shared_secret).await?;
        
        info!("Chip Authentication completed successfully");
        Ok((enc_key, mac_key))
    }
    
    /// Reads identity data from the card
    #[instrument(skip(self))]
    async fn read_identity_data(&self, request: &DIDAuthenticateRequest) -> Result<String, AuthError> {
        info!("Reading identity data from card");
        
        // Extract required permissions from request
        let required_permissions = vec![request.authentication_protocol_data.required_chat.clone()];
        
        let mut all_permissions = required_permissions;
        if let Some(optional) = &request.authentication_protocol_data.optional_chat {
            all_permissions.push(optional.clone());
        }
        
        // Read data with retry logic
        for attempt in 1..=self.max_retry_attempts {
            match self.card_communicator.read_identity_data(&request.connection_handle, &all_permissions).await {
                Ok(data) => {
                    info!("Successfully read identity data on attempt {}", attempt);
                    return Ok(data);
                }
                Err(e) if attempt < self.max_retry_attempts => {
                    warn!("Attempt {} failed, retrying: {}", attempt, e);
                    tokio::time::sleep(Duration::from_millis(100 * attempt as u64)).await;
                }
                Err(e) => {
                    error!("Failed to read identity data after {} attempts: {}", self.max_retry_attempts, e);
                    return Err(e);
                }
            }
        }
        
        unreachable!()
    }
}
impl DIDAuthenticate for UseidService {
    fn handle_did_authenticate(&self, request: DIDAuthenticateRequest) -> Result<DIDAuthenticateResponse, AuthError> {
        // Validate the request first
        if let Err(e) = request.validate() {
            return Ok(DIDAuthenticateResponse {
                result_major: "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error".to_string(),
                result_minor: Some(format!("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError: {}", e)),
                authentication_protocol_data: ResponseProtocolData::default(),
                timestamp: Utc::now().timestamp() as u64,
            });
        }

        // Create DIDAuthenticateService with default components for processing
        let did_service = DIDAuthenticateService::new_with_defaults();
        
        // Since we need to handle this synchronously but the actual authentication is async,
        // we'll use a runtime to block on the async operation
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                error!("Failed to create async runtime: {}", e);
                return Ok(DIDAuthenticateResponse {
                    result_major: "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error".to_string(),
                    result_minor: Some("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#internalError".to_string()),
                    authentication_protocol_data: ResponseProtocolData::default(),
                    timestamp: Utc::now().timestamp() as u64,
                });
            }
        };

        // Execute the authentication process
        let response = rt.block_on(did_service.authenticate(request));
        
        // The DIDAuthenticateService.authenticate method already returns a properly formatted response
        Ok(response)
    }
}
