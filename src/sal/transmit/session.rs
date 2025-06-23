use crate::sal::transmit::error::TransmitError;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

#[derive(Debug, Clone)]
pub struct TlsSessionInfo {
    pub session_id: String,
    pub cipher_suite: String,
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

#[derive(Debug, Clone)]
pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    session_timeout: Duration,
}

impl SessionManager {
    pub fn new(session_timeout: Duration) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            session_timeout,
        }
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
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id, session.clone());
        info!("Created new session: {}", session.id);
        Ok(session)
    }

    pub async fn get_session(&self, session_id: &str) -> Result<Session, TransmitError> {
        let sessions = self.sessions.read().await;
        match sessions.get(session_id) {
            Some(session) => {
                if session.is_expired(self.session_timeout) {
                    error!("Session {} expired", session_id);
                    Err(TransmitError::SessionError("Session expired".to_string()))
                } else {
                    Ok(session.clone())
                }
            }
            None => {
                error!("Session {} not found", session_id);
                Err(TransmitError::SessionError("Session not found".to_string()))
            }
        }
    }

    pub async fn update_session_state(
        &self,
        session_id: &str,
        new_state: SessionState,
    ) -> Result<(), TransmitError> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
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
                Err(TransmitError::SessionError(
                    "Invalid state transition".to_string(),
                ))
            }
        } else {
            error!("Session {} not found", session_id);
            Err(TransmitError::SessionError("Session not found".to_string()))
        }
    }

    pub async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        let expired_count = sessions.len();
        sessions.retain(|id, session| {
            let is_expired = session.is_expired(self.session_timeout);
            if is_expired {
                debug!("Cleaning up expired session: {}", id);
            }
            !is_expired
        });
        let remaining_count = sessions.len();
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
        };

        // Create session
        let session = manager.create_session(tls_info).await.unwrap();
        assert_eq!(session.state, SessionState::Created);

        // Get session
        let retrieved = manager.get_session(&session.id).await.unwrap();
        assert_eq!(retrieved.id, session.id);

        // Update state
        manager
            .update_session_state(&session.id, SessionState::Active)
            .await
            .unwrap();
        let updated = manager.get_session(&session.id).await.unwrap();
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
        };

        let session = manager.create_session(tls_info).await.unwrap();

        // Try invalid transition
        assert!(
            manager
                .update_session_state(&session.id, SessionState::Suspended)
                .await
                .is_err()
        );
    }
}
