//! Service layer that provides the business logic of the domain.

use std::fs;

use base64::Engine;
use chrono::Utc;
use color_eyre::Result;
use color_eyre::eyre::eyre;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::certificate::{CardCommunicator, CertificateStore, CryptoProvider};
use super::models::{
    AuthError, DIDAuthenticateRequest, DIDAuthenticateResponse, ResponseProtocolData, ServerInfo,
};
use super::ports::{DIDAuthenticate, EIDService, EidService};
use crate::eid::common::models::{
    AttributeRequester, OperationsRequester, ResultCode, ResultMajor, SessionResponse,
};
use crate::eid::use_id::model::{Psk, UseIDRequest, UseIDResponse};
use crate::session::{SessionManager, SessionStore};
use crate::tls::{PskStore, PskStoreError};
use async_trait::async_trait;

// Configuration for the eID Service
#[derive(Clone, Debug)]
pub struct EIDServiceConfig {
    /// Optional eCard server address to return in responses
    pub ecard_server_address: Option<String>,
}

impl Default for EIDServiceConfig {
    fn default() -> Self {
        Self {
            ecard_server_address: Some("https://localhost:3000".to_string()),
        }
    }
}

/// Session information stored by the server
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub psk: String,
    pub operations: Vec<String>,
    pub connection_handles: Vec<ConnectionHandle>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionHandle {
    pub connection_handle: String,
}

impl SessionInfo {
    pub fn new(id: String, psk: String, operations: Vec<String>) -> Self {
        SessionInfo {
            id,
            psk,
            operations,
            connection_handles: Vec::new(),
        }
    }
}

/// Main service for handling useID requests
#[derive(Clone, Debug)]
pub struct UseidService<S: SessionStore + Clone> {
    pub config: EIDServiceConfig,
    pub session_manager: SessionManager<S>,
}

impl<S: SessionStore + Clone> UseidService<S> {
    pub fn new(config: EIDServiceConfig, session_manager: SessionManager<S>) -> Self {
        Self {
            config,
            session_manager,
        }
    }

    /// Generate a random PSK for secure communication
    pub fn generate_psk(&self) -> String {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
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
impl<S: SessionStore + Clone + 'static> EIDService for UseidService<S> {
    async fn handle_use_id(&self, request: UseIDRequest) -> Result<UseIDResponse> {
        // Validate the request: Check if any operations are REQUIRED
        let required_operations = Self::get_required_operations(&request._use_operations);
        debug!("Required operations: {:?}", required_operations);

        // Generate session ID
        let session_id = Uuid::new_v4().simple().to_string();

        // Generate or use provided PSK
        let psk = match &request._psk {
            Some(psk) => {
                // Check if PSK ID matches an existing session
                if self
                    .session_manager
                    .get::<SessionInfo>(&psk.id)
                    .await?
                    .is_some()
                {
                    error!("Attempted to reuse session ID: {}", psk.id);
                    return Err(color_eyre::eyre::eyre!("Session ID reuse detected"));
                }
                psk.key.clone()
            }
            None => self.generate_psk(),
        };

        if psk.is_empty() {
            error!("Generated empty PSK");
            return Err(eyre!("Failed to generate PSK"));
        }
        debug!("Generated PSK: {psk}");

        let session_info =
            SessionInfo::new(session_id.clone(), psk.clone(), required_operations.clone());

        // Store session with PSK
        self.session_manager
            .insert(&session_id, session_info.clone())
            .await?;
        info!(
            "Created new session: {}, operations: {:?}",
            session_id, session_info.operations
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
impl<S: SessionStore + Clone + 'static> EidService for UseidService<S> {
    fn get_server_info(&self) -> ServerInfo {
        ServerInfo::default()
    }
}

#[derive(Debug, Clone)]
pub struct DIDAuthenticateService<S: SessionStore + Clone> {
    certificate_store: CertificateStore,
    crypto_provider: CryptoProvider,
    card_communicator: CardCommunicator,
    session_manager: SessionManager<S>,
}

impl<S: SessionStore + Clone + 'static> DIDAuthenticateService<S> {
    pub fn new(
        certificate_store: CertificateStore,
        crypto_provider: CryptoProvider,
        card_communicator: CardCommunicator,
        session_manager: SessionManager<S>,
    ) -> Self {
        Self {
            certificate_store,
            crypto_provider,
            card_communicator,
            session_manager,
        }
    }

    pub async fn new_with_defaults(session_manager: SessionManager<S>) -> Self {
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
        session_manager: SessionManager<S>,
    ) -> Result<ResponseProtocolData, AuthError> {
        request.validate()?;
        debug!("Request validation passed");

        // Validate session
        let session_id = request
            .connection_handle
            .channel_handle
            .as_ref()
            .ok_or_else(|| AuthError::invalid_connection("Missing channel handle"))?;

        if !session_manager
            .exists(session_id)
            .await
            .map_err(|e| AuthError::internal_error(format!("Failed to acquire session: {e}")))?
        {
            return Err(AuthError::invalid_connection(
                "Invalid or expired session: {session_id}",
            ));
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
impl<S: SessionStore + Clone + 'static> DIDAuthenticate for UseidService<S> {
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

#[derive(Debug, Clone)]
pub struct PskStoreAdapter<S: SessionStore + Clone>(SessionManager<S>);

impl<S: SessionStore + Clone> PskStoreAdapter<S> {
    pub fn new(session_manager: SessionManager<S>) -> Self {
        Self(session_manager)
    }
}

#[async_trait]
impl<S: SessionStore + Clone + 'static> PskStore for PskStoreAdapter<S> {
    async fn get_psk(&self, identity: &[u8]) -> Result<Option<Vec<u8>>, PskStoreError> {
        let result: Option<SessionInfo> = self
            .0
            .get(identity)
            .await
            .map_err(|e| PskStoreError::msg(format!("Session lookup failed: {e}")))?;

        match result {
            Some(s) => hex::decode(&s.psk)
                .map(Some)
                .map_err(|e| PskStoreError::msg(format!("Invalid PSK hex format: {e}"))),
            None => Ok(None),
        }
    }
}
