//! Service layer that provides the business logic of the domain.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use chrono::{DateTime, Utc};
use color_eyre::Result;
use rand::Rng;
use rand::distr::Alphanumeric;

use super::models::ServerInfo;
use super::ports::{EIDService, EidService};
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
    pub connection_handles: Vec<ConnectionHandle>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionHandle {
    pub connection_handle: String,
}

#[derive(Clone, Debug)]
pub struct SessionManager {
    sessions: HashMap<String, SessionInfo>,
}

impl SessionManager {
    /// Creates a new SessionManager
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Adds a session to the manager
    pub fn add_session(&mut self, session: SessionInfo) {
        self.sessions.insert(session.id.clone(), session);
    }

    /// Retrieves a session by ID if it exists and hasn't expired
    pub fn get_session(&self, session_id: &str) -> Option<SessionInfo> {
        self.sessions.get(session_id).cloned()
    }

    /// Removes expired sessions
    pub fn cleanup_expired(&mut self) {
        let now = Utc::now();
        self.sessions.retain(|_, session| session.expiry > now);
    }

    /// Checks if session exists and is valid
    pub fn is_valid_session(&self, session_id: &str) -> bool {
        if let Some(session) = self.sessions.get(session_id) {
            session.expiry > Utc::now()
        } else {
            false
        }
    }

    /// Returns current session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Retrieves a mutable reference to a session by ID if it exists
    pub fn get_session_mut(&mut self, session_id: &str) -> Option<&mut SessionInfo> {
        self.sessions.get_mut(session_id)
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Main service for handling useID requests
#[derive(Clone, Debug)]
pub struct UseidService {
    pub config: EIDServiceConfig,
    pub session_manager: Arc<RwLock<SessionManager>>,
}

impl UseidService {
    pub fn new(config: EIDServiceConfig) -> Self {
        let session_manager = Arc::new(RwLock::new(SessionManager::new()));

        // Clone Arc for the cleanup thread
        let cleanup_manager = session_manager.clone();

        // Spawn background thread for periodic session cleanup
        thread::spawn(move || {
            loop {
                // Cleanup every 60 seconds
                thread::sleep(Duration::from_secs(60));

                // Cleanup expired sessions
                if let Ok(mut mgr) = cleanup_manager.write() {
                    mgr.cleanup_expired();
                }
            }
        });

        Self {
            config,
            session_manager,
        }
    }

    /// Generate a random PSK for secure communication
    pub fn generate_psk(&self) -> String {
        // Generate a 32-character random PSK
        rand::rng()
            .sample_iter(Alphanumeric)
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

    /// Generates a unique session ID
    fn generate_session_id() -> String {
        let timestamp = Utc::now()
            .timestamp_nanos_opt()
            .expect("System time out of range for timestamp_nanos_opt()");

        let random_part: String = rand::rng()
            .sample_iter(Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();

        format!("{timestamp}-{random_part}")
    }
}

// Implement the EIDService trait for UseidService
impl EIDService for UseidService {
    fn update_session_connection_handles(
        &self,
        session_id: &str,
        connection_handles: Vec<String>,
    ) -> Result<()> {
        let mut manager = self
            .session_manager
            .write()
            .map_err(|e| color_eyre::eyre::eyre!("Session manager lock poisoned: {}", e))?;

        if let Some(session) = manager.get_session_mut(session_id) {
            for handle in connection_handles {
                session.connection_handles.push(ConnectionHandle {
                    connection_handle: handle,
                });
            }
            tracing::debug!(
                "Updated session {} with {} connection handles",
                session_id,
                session.connection_handles.len()
            );
            Ok(())
        } else {
            Err(color_eyre::eyre::eyre!("Session not found"))
        }
    }

    /// Check if a session is valid by its ID
    fn is_session_valid(&self, session_id: &str) -> Result<bool> {
        match self.session_manager.read() {
            Ok(mgr) => Ok(mgr.is_valid_session(session_id)),
            Err(e) => Err(color_eyre::eyre::eyre!(
                "Session manager lock poisoned: {}",
                e
            )),
        }
    }

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

        // Generate session ID and PSK
        let session_id = Self::generate_session_id();
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
            connection_handles: Vec::new(),
        };

        // Store the session
        {
            let mut manager = self
                .session_manager
                .write()
                .map_err(|e| color_eyre::eyre::eyre!("Session manager lock poisoned: {}", e))?;

            // Cleanup expired sessions before adding new one
            manager.cleanup_expired();

            // Check session limit
            if manager.session_count() >= self.config.max_sessions {
                return Ok(UseIDResponse {
                    result: ResultMajor {
                        // FIX: Use correct error result code
                        result_major: "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error"
                            .to_string(),
                    },
                    ..Default::default()
                });
            }

            manager.add_session(session_info);
        }

        tracing::info!("Created new session: {}, expires: {}", session_id, expiry);

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
