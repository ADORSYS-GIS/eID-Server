use std::fs;
use std::sync::{Arc, RwLock};

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use color_eyre::Result;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::default::Default;
use tracing::{debug, error, info, warn};

use super::certificate::{CardCommunicator, CertificateStore, CryptoProvider};
use super::models::{
    AuthError, DIDAuthenticateRequest, DIDAuthenticateResponse, ResponseProtocolData, ServerInfo,
};
use super::ports::{DIDAuthenticate, EIDService, EidService};
use super::session_manager::{InMemorySessionManager, RedisSessionManager, SessionManager};
use crate::eid::common::models::{
    AttributeRequester, OperationsRequester, ResultCode, ResultMajor, SessionResponse,
};
use crate::eid::get_result::error::GetResultError;
use crate::eid::get_result::model::GetResultResponse;
use crate::eid::use_id::model::{Psk, UseIDRequest, UseIDResponse};
use async_trait::async_trait;

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
    pub request_counter: u8,
    pub authentication_completed: bool,
    pub authentication_data: Option<String>,
}

impl SessionInfo {
    pub fn new(id: String, psk: String, operations: Vec<String>, timeout_minutes: i64) -> Self {
        SessionInfo {
            id,
            expiry: Utc::now() + Duration::minutes(timeout_minutes),
            psk,
            operations,
            request_counter: 0,
            authentication_completed: false,
            authentication_data: None,
        }
    }
}

/// Main service for handling useID requests
#[derive(Clone, Debug)]
pub struct UseidService {
    pub sessions: Arc<RwLock<Vec<SessionInfo>>>,
    pub config: EIDServiceConfig,
    pub session_manager: Arc<dyn SessionManager>,
}

/// Structure to hold personal data from XML
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PersonalData {
    document_type: Option<String>,
    issuing_state: Option<String>,
    date_of_expiry: Option<String>,
    given_names: Option<String>,
    family_names: Option<String>,
    artistic_name: Option<String>,
    academic_title: Option<String>,
    #[serde(rename = "DateOfBirth")]
    date_of_birth_string: Option<String>,
    #[serde(skip)]
    date_of_birth_value: Option<String>,
    place_of_birth: Option<String>,
    nationality: Option<String>,
    birth_name: Option<String>,
    #[serde(rename = "Street")]
    residence_street: Option<String>,
    #[serde(rename = "City")]
    residence_city: Option<String>,
    #[serde(rename = "Country")]
    residence_country: Option<String>,
    #[serde(rename = "ZipCode")]
    residence_zipcode: Option<String>,
    #[serde(rename = "CommunityID")]
    community_id: Option<String>,
    #[serde(rename = "ResidencePermitID")]
    residence_permit_id: Option<String>,
    restricted_id: Option<String>,
    restricted_id2: Option<String>,
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
            sessions: Arc::new(RwLock::new(Vec::new())),
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
            required.push("RestrictedId".to_string());
        }
        if ops.age_verification == AttributeRequester::REQUIRED {
            required.push("AgeVerification".to_string());
        }
        if ops.place_verification == AttributeRequester::REQUIRED {
            required.push("PlaceVerification".to_string());
        }
        required
    }

    /// Parse personal data from XML authentication data
    fn parse_personal_data_xml(&self, xml_data: &str) -> Result<PersonalData, GetResultError> {
        use quick_xml::de::from_str;

        let mut parsed_data: PersonalData = from_str(xml_data)
            .map_err(|e| GetResultError::GenericError(format!("XML parsing error: {e}")))?;

        // Process date_of_birth_value if date_of_birth_string is available
        if let Some(ref date_string) = parsed_data.date_of_birth_string {
            if date_string.len() == 8 {
                if let (Ok(year), Ok(month), Ok(day)) = (
                    date_string[0..4].parse::<u32>(),
                    date_string[4..6].parse::<u32>(),
                    date_string[6..8].parse::<u32>(),
                ) {
                    parsed_data.date_of_birth_value =
                        Some(format!("{year:04}-{month:02}-{day:02}"));
                }
            }
        }

        Ok(parsed_data)
    }

    /// Create a GetResultResponse
    /// This method parses authentication data retrieved from the eID card
    pub fn create_get_result_response(
        &self,
        authentication_data: &str,
    ) -> Result<GetResultResponse, GetResultError> {
        use crate::eid::common::models::{
            AttributeResponder, EIDTypeResponse, GeneralDateType, GeneralPlaceType,
            LevelOfAssurance, OperationsResponder, PersonalData, PlaceType, RestrictedID,
            ResultMajor, TransactionAttestationResponse,
        };
        use crate::eid::get_result::model::FulfilsRequest;

        // Parse XML authentication data to extract personal data
        let parsed_data = self.parse_personal_data_xml(authentication_data)?;

        Ok(GetResultResponse {
            personal_data: PersonalData {
                document_type: parsed_data
                    .document_type
                    .unwrap_or_else(|| "ID".to_string()),
                issuing_state: parsed_data.issuing_state.unwrap_or_else(|| "D".to_string()),
                date_of_expiry: parsed_data
                    .date_of_expiry
                    .unwrap_or_else(|| "2029-10-31".to_string()),
                given_names: parsed_data.given_names.unwrap_or_else(|| "".to_string()),
                family_names: parsed_data.family_names.unwrap_or_else(|| "".to_string()),
                artistic_name: parsed_data.artistic_name.unwrap_or_else(|| "".to_string()),
                academic_title: parsed_data.academic_title.unwrap_or_else(|| "".to_string()),
                date_of_birth: GeneralDateType {
                    date_string: parsed_data
                        .date_of_birth_string
                        .unwrap_or_else(|| "".to_string()),
                    date_value: parsed_data.date_of_birth_value,
                },
                place_of_birth: GeneralPlaceType {
                    structured_place: None,
                    freetextplace: parsed_data.place_of_birth,
                    noplaceinfo: None,
                },
                nationality: parsed_data.nationality.unwrap_or_else(|| "".to_string()),
                birth_name: parsed_data.birth_name.unwrap_or_else(|| "".to_string()),
                place_of_residence: GeneralPlaceType {
                    structured_place: if parsed_data.residence_street.is_some()
                        || parsed_data.residence_city.is_some()
                    {
                        Some(PlaceType {
                            street: parsed_data
                                .residence_street
                                .unwrap_or_else(|| "".to_string()),
                            city: parsed_data.residence_city.unwrap_or_else(|| "".to_string()),
                            state: "".to_string(),
                            country: parsed_data
                                .residence_country
                                .unwrap_or_else(|| "D".to_string()),
                            zipcode: parsed_data
                                .residence_zipcode
                                .unwrap_or_else(|| "".to_string()),
                        })
                    } else {
                        None
                    },
                    freetextplace: None,
                    noplaceinfo: None,
                },
                community_id: parsed_data.community_id.unwrap_or_else(|| "".to_string()),
                residence_permit_id: parsed_data
                    .residence_permit_id
                    .unwrap_or_else(|| "".to_string()),
                restricted_id: RestrictedID {
                    id: parsed_data.restricted_id.unwrap_or_else(|| "".to_string()),
                    id2: parsed_data.restricted_id2.unwrap_or_else(|| "".to_string()),
                },
            },
            fulfils_age_verification: FulfilsRequest {
                fulfils_request: true,
            },
            fulfils_place_verification: FulfilsRequest {
                fulfils_request: true,
            },
            operations_allowed_by_user: OperationsResponder {
                document_type: AttributeResponder::ALLOWED,
                issuing_state: AttributeResponder::ALLOWED,
                date_of_expiry: AttributeResponder::ALLOWED,
                given_names: AttributeResponder::ALLOWED,
                family_names: AttributeResponder::ALLOWED,
                artistic_name: None,
                academic_title: None,
                date_of_birth: AttributeResponder::ALLOWED,
                place_of_birth: AttributeResponder::ALLOWED,
                nationality: AttributeResponder::ALLOWED,
                birth_name: AttributeResponder::PROHIBITED,
                place_of_residence: AttributeResponder::ALLOWED,
                community_id: AttributeResponder::ALLOWED,
                residence_permit_id: AttributeResponder::ALLOWED,
                restricted_id: AttributeResponder::ALLOWED,
                age_verification: AttributeResponder::ALLOWED,
                place_verification: AttributeResponder::ALLOWED,
            },
            transaction_attestation_response: TransactionAttestationResponse {
                transaction_attestation_format: "http://bsi.bund.de/eID/ExampleAttestationFormat"
                    .to_string(),
                transaction_attestation_data: authentication_data.to_string(),
            },
            level_of_assurance: LevelOfAssurance::Hoch.to_string(),
            eid_type_response: EIDTypeResponse {
                card_certified: "USED".to_string(),
                hw_keystore: "".to_string(),
                se_certified: "".to_string(),
                se_endorsed: "".to_string(),
            },
            result: ResultMajor {
                result_major: "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok".to_string(),
            },
        })
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

    fn get_sessions(&self) -> &Arc<RwLock<Vec<SessionInfo>>> {
        &self.sessions
    }

    fn create_get_result_response_from_data(
        &self,
        authentication_data: &str,
    ) -> Result<GetResultResponse, GetResultError> {
        self.create_get_result_response(authentication_data)
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

        // Store the authentication data in the session
        if let Some(mut session_info) = session_manager
            .get_session(session_id)
            .await
            .map_err(|e| AuthError::internal_error(format!("Failed to get session: {e}")))?
        {
            session_info.authentication_completed = true;
            session_info.authentication_data = Some(personal_data.clone());
            session_manager
                .store_session(session_info)
                .await
                .map_err(|e| AuthError::internal_error(format!("Failed to update session: {e}")))?;
            info!("Stored authentication data for session: {}", session_id);
        }

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
