use std::fs;
use std::sync::{Arc, RwLock};

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use color_eyre::Result;
use quick_xml::{Reader, events::Event};
use rand::distr::Alphanumeric;
use rand::{Rng, RngCore};
use std::default::Default;
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
use crate::eid::get_result::error::GetResultError;
use crate::eid::get_result::model::{GetResultRequest, GetResultResponse};
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
}

impl Default for EIDServiceConfig {
    fn default() -> Self {
        Self {
            max_sessions: 1000,
            session_timeout_minutes: 5,
            ecard_server_address: Some("https://localhost:3000".to_string()),
        }
    }
}

/// Session information stored by the server
#[derive(Clone, Debug)]
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
    pub config: EIDServiceConfig,
    pub sessions: Arc<RwLock<Vec<SessionInfo>>>,
}

/// Structure to hold parsed personal data from XML
#[derive(Debug, Default)]
struct ParsedPersonalData {
    document_type: Option<String>,
    issuing_state: Option<String>,
    date_of_expiry: Option<String>,
    given_names: Option<String>,
    family_names: Option<String>,
    artistic_name: Option<String>,
    academic_title: Option<String>,
    date_of_birth_string: Option<String>,
    date_of_birth_value: Option<String>,
    place_of_birth: Option<String>,
    nationality: Option<String>,
    birth_name: Option<String>,
    residence_street: Option<String>,
    residence_city: Option<String>,
    residence_country: Option<String>,
    residence_zipcode: Option<String>,
    community_id: Option<String>,
    residence_permit_id: Option<String>,
    restricted_id: Option<String>,
    restricted_id2: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DIDAuthenticateService {
    certificate_store: CertificateStore,
    crypto_provider: CryptoProvider,
    card_communicator: CardCommunicator,
    sessions: Arc<RwLock<Vec<SessionInfo>>>,
}

impl UseidService {
    pub fn new(config: EIDServiceConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Generate a random session ID
    pub fn generate_session_id(&self) -> String {
        let timestamp = Utc::now()
            .timestamp_nanos_opt()
            .expect("System time out of range for timestamp_nanos_opt()");
        let _random_part: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();
        format!("{timestamp}-{}", Uuid::new_v4())
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

    /// Parse personal data from XML authentication data
    fn parse_personal_data_xml(
        &self,
        xml_data: &str,
    ) -> Result<ParsedPersonalData, GetResultError> {
        let mut reader = Reader::from_str(xml_data);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut parsed_data = ParsedPersonalData::default();
        let mut current_element = String::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    current_element = String::from_utf8_lossy(e.name().as_ref()).to_string();
                }
                Ok(Event::Text(e)) => {
                    let text = e
                        .unescape()
                        .map_err(|_| {
                            GetResultError::GenericError("Failed to unescape XML text".to_string())
                        })?
                        .to_string();

                    match current_element.as_str() {
                        "DocumentType" => parsed_data.document_type = Some(text),
                        "IssuingState" => parsed_data.issuing_state = Some(text),
                        "DateOfExpiry" => parsed_data.date_of_expiry = Some(text),
                        "GivenNames" => parsed_data.given_names = Some(text),
                        "FamilyNames" => parsed_data.family_names = Some(text),
                        "ArtisticName" => parsed_data.artistic_name = Some(text),
                        "AcademicTitle" => parsed_data.academic_title = Some(text),
                        "DateOfBirth" => {
                            parsed_data.date_of_birth_string = Some(text.clone());

                            if text.len() == 8 {
                                if let (Ok(year), Ok(month), Ok(day)) = (
                                    text[0..4].parse::<u32>(),
                                    text[4..6].parse::<u32>(),
                                    text[6..8].parse::<u32>(),
                                ) {
                                    parsed_data.date_of_birth_value =
                                        Some(format!("{year:04}-{month:02}-{day:02}"));
                                }
                            }
                        }
                        "PlaceOfBirth" => parsed_data.place_of_birth = Some(text),
                        "Nationality" => parsed_data.nationality = Some(text),
                        "BirthName" => parsed_data.birth_name = Some(text),
                        "Street" => parsed_data.residence_street = Some(text),
                        "City" => parsed_data.residence_city = Some(text),
                        "Country" => parsed_data.residence_country = Some(text),
                        "ZipCode" => parsed_data.residence_zipcode = Some(text),
                        "CommunityID" => parsed_data.community_id = Some(text),
                        "ResidencePermitID" => parsed_data.residence_permit_id = Some(text),
                        "RestrictedID" => parsed_data.restricted_id = Some(text),
                        "RestrictedID2" => parsed_data.restricted_id2 = Some(text),
                        _ => {} // Ignore unknown elements
                    }
                }
                Ok(Event::End(_)) => {
                    current_element.clear();
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(GetResultError::GenericError(format!(
                        "XML parsing error: {e}",
                    )));
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(parsed_data)
    }

    /// Create a GetResultResponse
    /// This method parses the actual authentication data retrieved from the eID card
    fn create_get_result_response(
        &self,
        authentication_data: &str,
    ) -> Result<GetResultResponse, GetResultError> {
        use crate::eid::common::models::{
            AttributeResponder, EIDTypeResponse, GeneralDateType, GeneralPlaceType,
            LevelOfAssurance, OperationsResponder, PersonalData, PlaceType, RestrictedID,
            ResultMajor, TransactionAttestationResponse,
        };
        use crate::eid::get_result::model::FulfilsRequest;

        // Parse the XML authentication data to extract real personal data
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
impl EIDService for UseidService {
    fn handle_use_id(&self, request: UseIDRequest) -> Result<UseIDResponse> {
        // Validate the request: Check if any operations are REQUIRED
        let required_operations = Self::get_required_operations(&request._use_operations);
        debug!("Required operations: {:?}", required_operations);

        // Check if we've reached the maximum number of sessions
        let sessions_count = self
            .sessions
            .read()
            .map_err(|e| color_eyre::eyre::eyre!("Failed to acquire session lock: {}", e))?
            .len();
        if sessions_count >= self.config.max_sessions {
            return Err(color_eyre::eyre::eyre!("Maximum session limit reached"));
        }

        // Generate session ID
        let session_id = self.generate_session_id();
        if session_id.is_empty() {
            error!("Generated empty session ID");
            return Err(color_eyre::eyre::eyre!("Failed to generate session ID"));
        }
        debug!("Generated session_id: {}", session_id);

        // Generate or use provided PSK
        let psk = match &request._psk {
            Some(psk) => psk.key.clone(),
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
            30,
        );

        // Store the session
        {
            let mut sessions = self.sessions.write().map_err(|e| {
                color_eyre::eyre::eyre!("Failed to acquire session write lock: {}", e)
            })?;
            let now = Utc::now();
            sessions.retain(|session| session.expiry > now);
            sessions.push(session_info.clone());
            info!(
                "Created new session: {}, expires: {}, operations: {:?}",
                session_id, session_info.expiry, session_info.operations
            );
        }

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

    fn handle_get_result(
        &self,
        request: GetResultRequest,
    ) -> Result<GetResultResponse, GetResultError> {
        debug!(
            "Handling get_result request for session: {}",
            request.session.id
        );

        // Find and validate session
        let mut sessions = self.sessions.write().map_err(|e| {
            GetResultError::GenericError(format!("Failed to acquire session write lock: {e}"))
        })?;
        let now = Utc::now();

        // Clean up expired sessions
        sessions.retain(|session| session.expiry > now);

        // Find the session
        let session_index = sessions
            .iter()
            .position(|s| s.id == request.session.id)
            .ok_or(GetResultError::InvalidSession)?;

        let session = &mut sessions[session_index];

        // Validate request counter
        let expected_counter = session.request_counter + 1;
        if request.request_counter != expected_counter {
            return Err(GetResultError::InvalidRequestCounter);
        }

        // Update request counter
        session.request_counter = request.request_counter;

        // Check if authentication is completed
        if !session.authentication_completed {
            return Err(GetResultError::NoResultYet);
        }

        // Create response
        let authentication_data =
            session
                .authentication_data
                .as_ref()
                .ok_or(GetResultError::GenericError(
                    "No authentication data available".to_string(),
                ))?;

        let response = self.create_get_result_response(authentication_data)?;

        // Session becomes invalid after successful response (as per specification)
        // "Upon success, the session becomes invalid and the server MUST delete the data"
        sessions.remove(session_index);

        Ok(response)
    }
}

// Implement the EidService trait for UseidService
impl EidService for UseidService {
    fn get_server_info(&self) -> ServerInfo {
        ServerInfo::default()
    }
}

impl DIDAuthenticateService {
    pub fn new(
        certificate_store: CertificateStore,
        crypto_provider: CryptoProvider,
        card_communicator: CardCommunicator,
        sessions: Arc<RwLock<Vec<SessionInfo>>>,
    ) -> Self {
        Self {
            certificate_store,
            crypto_provider,
            card_communicator,
            sessions,
        }
    }

    pub async fn new_with_defaults(sessions: Arc<RwLock<Vec<SessionInfo>>>) -> Self {
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
            sessions,
        }
    }

    pub async fn authenticate(&self, request: DIDAuthenticateRequest) -> DIDAuthenticateResponse {
        info!(
            "Starting DID authentication process for request: {:?}",
            request
        );

        match self
            .authenticate_internal(request, self.sessions.clone())
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
        sessions: Arc<RwLock<Vec<SessionInfo>>>,
    ) -> Result<ResponseProtocolData, AuthError> {
        request.validate()?;
        debug!("Request validation passed");

        // Validate session
        let session_id = request
            .connection_handle
            .channel_handle
            .as_ref()
            .ok_or_else(|| AuthError::invalid_connection("Missing channel handle"))?;

        let _session_info = {
            let sessions = sessions.read().map_err(|e| {
                AuthError::internal_error(format!("Failed to acquire sessions lock: {e}"))
            })?;
            debug!(
                "Available sessions: {:?}",
                sessions.iter().map(|s| &s.id).collect::<Vec<_>>()
            );
            let session = sessions
                .iter()
                .find(|s| s.id == *session_id)
                .ok_or_else(|| {
                    error!("Session {} not found", session_id);
                    AuthError::invalid_connection("Invalid or expired session")
                })?;
            if session.expiry < Utc::now() {
                error!("Session {} expired at {}", session_id, session.expiry);
                return Err(AuthError::timeout_error("Session validation"));
            }
            session.clone()
        };

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
        {
            let mut sessions = sessions.write().map_err(|e| {
                AuthError::internal_error(format!("Failed to acquire sessions write lock: {e}"))
            })?;

            if let Some(session) = sessions.iter_mut().find(|s| s.id == *session_id) {
                session.authentication_completed = true;
                session.authentication_data = Some(personal_data.clone());
                info!("Stored authentication data for session: {}", session_id);
            }
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

        let did_service = DIDAuthenticateService::new_with_defaults(self.sessions.clone()).await;
        Ok(did_service.authenticate(request).await)
    }
}
