//! Service layer that provides the business logic of the domain.

use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use color_eyre::Result;
use rand::Rng;

use super::models::{AuthError, ConnectionHandle, DIDAuthenticateRequest, DIDAuthenticateResponse, ResponseProtocolData, ServerInfo};
use super::ports::{EIDService, DIDAuthenticate, EidService};
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

// Add placeholder types for DIDAuthenticate implementation
// You'll need to replace these with your actual types
#[derive(Clone, Debug)]
pub struct CertificateStore;

#[derive(Clone, Debug)]
pub struct CryptoProvider;

#[derive(Clone, Debug)]
pub struct CardCommunicator;

#[derive(Clone, Debug)]
pub struct DIDAuthenticateService {
    certificate_store: CertificateStore,
    crypto_provider: CryptoProvider,
    card_communicator: CardCommunicator,
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
    pub fn new(
        certificate_store: CertificateStore,
        crypto_provider: CryptoProvider,
        card_communicator: CardCommunicator,
    ) -> Self {
        DIDAuthenticateService {
            certificate_store,
            crypto_provider,
            card_communicator,
        }
    }

    async fn validate_connection(&self, handle: &ConnectionHandle) -> Result<(), AuthError> {
        // Implement connection validation
        Ok(())
    }

    async fn perform_terminal_auth(&self, request: &DIDAuthenticateRequest) -> Result<(), AuthError> {
        // Implement terminal authentication (certificate validation, challenge signing)
        Ok(())
    }

    async fn establish_secure_channel(&self, request: &DIDAuthenticateRequest) -> Result<(), AuthError> {
        // Implement chip authentication (ECDH key exchange)
        Ok(())
    }

    async fn read_identity_data(&self, request: &DIDAuthenticateRequest) -> Result<ResponseProtocolData, AuthError> {
        // Implement data retrieval
        Ok(ResponseProtocolData {
            challenge: None,
            certificate: Some("mock_certificate".to_string()),
            personal_data: Some("mock_personal_data".to_string()),
        })
    }
}

impl DIDAuthenticate for UseidService {
    fn handle_did_authenticate(&self, request: DIDAuthenticateRequest) -> Result<DIDAuthenticateResponse, AuthError> {
        // Note: This is a synchronous implementation. If you need async, you'll need to modify the trait
        // For now, we'll create a mock implementation
        let identity_data = ResponseProtocolData {
            challenge: None,
            certificate: Some("mock_certificate".to_string()),
            personal_data: Some("mock_personal_data".to_string()),
        };

        Ok(DIDAuthenticateResponse {
            result_major: "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok".to_string(),
            result_minor: None,
            authentication_protocol_data: identity_data,
        })
    }
}