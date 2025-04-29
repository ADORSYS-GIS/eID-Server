use chrono::{Duration, Utc};
use rand::{distributions::Alphanumeric, Rng};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;

use super::models::{Session, UseIDRequest, UseIDResponse, PSK};

/// Configuration for the eID Service
#[derive(Clone)]
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
    pub expiry: chrono::DateTime<Utc>,
    pub psk: Option<String>,
    pub operations: Vec<String>,
}

/// Main service for handling useID requests
#[derive(Clone)]
pub struct EIDService {
    config: EIDServiceConfig,
    sessions: Arc<RwLock<Vec<SessionInfo>>>,
}

impl EIDService {
    pub fn new(config: EIDServiceConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Handle a useID request according to TR-03130
    pub async fn handle_use_id(&self, request: UseIDRequest) -> anyhow::Result<UseIDResponse> {
        // Validate the request
        if request.use_operations.use_operations.is_empty() {
            return Ok(UseIDResponse {
                result: Result::error(
                    "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/parameterError",
                    Some("UseOperations must contain at least one operation"),
                ),
                session: Session {
                    session_identifier: "".to_string(),
                    timeout: "0".to_string(),
                },
                ecard_server_address: None,
                psk: None,
            });
        }

        // Check if we've reached the maximum number of sessions
        if self.sessions.read().await.len() >= self.config.max_sessions {
            return Ok(UseIDResponse {
                result: Result::error(
                    "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/tooManySessions",
                    Some("Maximum number of sessions reached"),
                ),
                session: Session {
                    session_identifier: "".to_string(),
                    timeout: "0".to_string(),
                },
                ecard_server_address: None,
                psk: None,
            });
        }

        // Generate a session ID
        let session_id = Uuid::new_v4().to_string();
        
        // Generate or use provided PSK
        let psk = match &request.psk {
            Some(psk) => psk.value.clone(),
            None => self.generate_psk(),
        };

        // Calculate session expiry time
        let expiry = Utc::now() + Duration::minutes(self.config.session_timeout_minutes);
        
        // Create session info
        let session_info = SessionInfo {
            id: session_id.clone(),
            expiry,
            psk: Some(psk.clone()),
            operations: request
                .use_operations
                .use_operations
                .iter()
                .map(|op| op.id.clone())
                .collect(),
        };

        // Store the session
        {
            let mut sessions = self.sessions.write().await;
            
            // Remove expired sessions first
            let now = Utc::now();
            sessions.retain(|session| session.expiry > now);
            
            // Add new session
            sessions.push(session_info.clone());
            
            info!(
                "Created new session: {}, expires: {}, operations: {:?}",
                session_id, expiry, session_info.operations
            );
        }

        // Build response
        Ok(UseIDResponse {
            result: Result::success(),
            session: Session {
                session_identifier: session_id,
                timeout: expiry.to_rfc3339(),
            },
            ecard_server_address: self.config.ecard_server_address.clone(),
            psk: Some(PSK { value: psk }),
        })
    }

    /// Generate a random PSK for secure communication
    fn generate_psk(&self) -> String {
        // Generate a 32-character random PSK
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }

    /// Clean up expired sessions (can be called periodically)
    pub async fn cleanup_expired_sessions(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let before_count = sessions.len();
        let now = Utc::now();
        sessions.retain(|session| session.expiry > now);
        let removed = before_count - sessions.len();
        
        if removed > 0 {
            info!("Removed {} expired sessions", removed);
        }
        
        removed
    }

    /// Get a session by ID
    pub async fn get_session(&self, session_id: &str) -> Option<SessionInfo> {
        let sessions = self.sessions.read().await;
        let now = Utc::now();
        
        sessions
            .iter()
            .find(|s| s.id == session_id && s.expiry > now)
            .cloned()
    }
}