use crate::domain::eid::ports::TransmitError;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info};

#[derive(Debug, Clone)]
pub struct TlsSessionInfo {
    pub session_id: String,
    pub cipher_suite: String,
    pub psk_id: Option<String>,
    pub psk_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    Created,
    Active,
    Suspended,
    Terminated,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub state: SessionState,
    pub security_context: Option<TlsSessionInfo>,
}

impl Session {
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn can_transition_to(&self, new_state: &SessionState) -> bool {
        matches!(
            (&self.state, new_state),
            (SessionState::Created, SessionState::Active)
                | (SessionState::Active, SessionState::Suspended)
                | (SessionState::Suspended, SessionState::Active)
                | (_, SessionState::Terminated)
        )
    }
}

/// Session manager using DashMap for robust concurrent session management
/// This provides better security, maintenance, and follows best practices
#[derive(Debug, Clone)]
pub struct SessionManager {
    sessions: Arc<DashMap<String, Session>>,
    session_timeout: Duration,
}

impl SessionManager {
    pub fn new(session_timeout: Duration) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            session_timeout,
        }
    }

    /// Validates PSK according to TR-03130 requirements
    /// The eID-Server MUST verify that each SessionIdentifier of a PSK used by an eID-Client
    /// matches a PSK ID previously negotiated at the eID-Interface for one specific session
    pub async fn validate_psk(
        &self,
        psk_id: &str,
        session_id: &str,
    ) -> Result<bool, TransmitError> {
        // Find session by ID and validate PSK
        if let Some(session) = self.sessions.get(session_id) {
            if let Some(security_context) = &session.security_context {
                if let Some(stored_psk_id) = &security_context.psk_id {
                    return Ok(stored_psk_id == psk_id);
                }
            }
        }

        // PSK validation failed - return error as per TR-03130
        Err(TransmitError::TransmitError(
            "Invalid PSK or session not found".to_string(),
        ))
    }

    pub async fn create_session(&self, tls_info: TlsSessionInfo) -> Result<Session, TransmitError> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let session = Session {
            id: session_id.clone(),
            created_at: Instant::now(),
            last_activity: Instant::now(),
            state: SessionState::Created,
            security_context: Some(tls_info),
        };
        self.sessions.insert(session_id, session.clone());
        info!("Created new session: {}", session.id);
        Ok(session)
    }

    pub async fn get_session(&self, session_id: &str) -> Result<Session, TransmitError> {
        match self.sessions.get(session_id) {
            Some(session) => {
                if session.is_expired(self.session_timeout) {
                    error!("Session {} expired", session_id);
                    // Remove expired session
                    self.sessions.remove(session_id);
                    Err(TransmitError::TransmitError("Session expired".to_string()))
                } else {
                    Ok(session.clone())
                }
            }
            None => {
                error!("Session {} not found", session_id);
                Err(TransmitError::TransmitError(
                    "Session not found".to_string(),
                ))
            }
        }
    }

    pub async fn update_session_state(
        &self,
        session_id: &str,
        new_state: SessionState,
    ) -> Result<(), TransmitError> {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            if session.can_transition_to(&new_state) {
                debug!(
                    "Updating session {} state from {:?} to {:?}",
                    session_id, session.state, new_state
                );
                session.state = new_state;
                session.update_activity();
                Ok(())
            } else {
                error!(
                    "Invalid state transition for session {}: {:?} -> {:?}",
                    session_id, session.state, new_state
                );
                Err(TransmitError::TransmitError(
                    "Invalid state transition".to_string(),
                ))
            }
        } else {
            error!("Session {} not found", session_id);
            Err(TransmitError::TransmitError(
                "Session not found".to_string(),
            ))
        }
    }

    pub async fn cleanup_expired_sessions(&self) {
        let expired_count = self.sessions.len();
        self.sessions.retain(|id, session| {
            let is_expired = session.is_expired(self.session_timeout);
            if is_expired {
                debug!("Cleaning up expired session: {}", id);
            }
            !is_expired
        });
        let remaining_count = self.sessions.len();
        if expired_count != remaining_count {
            info!(
                "Cleaned up {} expired sessions, {} remaining",
                expired_count - remaining_count,
                remaining_count
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_session_lifecycle() {
        let manager = SessionManager::new(Duration::from_secs(1));
        let tls_info = TlsSessionInfo {
            session_id: "test-session".to_string(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            psk_id: Some("test-psk-id".to_string()),
            psk_key: Some("test-psk-key".to_string()),
        };

        // Create session
        let session = manager
            .create_session(tls_info)
            .await
            .expect("Session creation should succeed");
        assert_eq!(session.state, SessionState::Created);

        // Get session
        let retrieved = manager
            .get_session(&session.id)
            .await
            .expect("Session retrieval should succeed");
        assert_eq!(retrieved.id, session.id);

        // Update state
        manager
            .update_session_state(&session.id, SessionState::Active)
            .await
            .expect("State update should succeed");
        let updated = manager
            .get_session(&session.id)
            .await
            .expect("Session retrieval should succeed");
        assert_eq!(updated.state, SessionState::Active);

        // Test expiration
        sleep(Duration::from_secs(2)).await;
        manager.cleanup_expired_sessions().await;
        assert!(manager.get_session(&session.id).await.is_err());
    }

    #[tokio::test]
    async fn test_invalid_state_transition() {
        let manager = SessionManager::new(Duration::from_secs(1));
        let tls_info = TlsSessionInfo {
            session_id: "test-session".to_string(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            psk_id: Some("test-psk-id".to_string()),
            psk_key: Some("test-psk-key".to_string()),
        };

        let session = manager
            .create_session(tls_info)
            .await
            .expect("Session creation should succeed");

        // Try invalid transition
        assert!(
            manager
                .update_session_state(&session.id, SessionState::Suspended)
                .await
                .is_err()
        );
    }
}
