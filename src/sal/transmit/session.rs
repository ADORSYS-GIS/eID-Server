use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use super::error::TransmitError;

#[derive(Debug, Clone)]
pub struct TlsSessionInfo {
    pub session_id: String,
    pub cipher_suite: String,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub state: SessionState,
    pub security_context: Option<TlsSessionInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Created,
    Active,
    Processing,
    Expired,
    Terminated,
}

impl Session {
    pub fn new(id: String) -> Self {
        Self {
            id,
            created_at: Instant::now(),
            last_activity: Instant::now(),
            state: SessionState::Created,
            security_context: None,
        }
    }

    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}

#[derive(Clone, Debug)]
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
        Ok(session)
    }

    pub async fn get_session(&self, session_id: &str) -> Result<Session, TransmitError> {
        let sessions = self.sessions.read().await;
        sessions
            .get(session_id)
            .cloned()
            .ok_or_else(|| TransmitError::SessionError("Session not found".to_string()))
    }

    pub async fn update_session_state(
        &self,
        session_id: &str,
        state: SessionState,
    ) -> Result<(), TransmitError> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.state = state;
            session.update_activity();
            Ok(())
        } else {
            Err(TransmitError::SessionError("Session not found".to_string()))
        }
    }

    pub async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, session| !session.is_expired(self.session_timeout));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_session_expiration_and_cleanup() {
        let manager = SessionManager::new(Duration::from_millis(10));
        let tls_info = TlsSessionInfo {
            session_id: "test-session".to_string(),
            cipher_suite: "TLS_TEST".to_string(),
        };
        let session = manager.create_session(tls_info.clone()).await.unwrap();
        assert!(manager.get_session(&session.id).await.is_ok());
        // Wait for session to expire
        tokio::time::sleep(Duration::from_millis(20)).await;
        manager.cleanup_expired_sessions().await;
        assert!(manager.get_session(&session.id).await.is_err());
    }

    #[tokio::test]
    async fn test_concurrent_session_access() {
        let manager = SessionManager::new(Duration::from_secs(1));
        let tls_info = TlsSessionInfo {
            session_id: "concurrent-session".to_string(),
            cipher_suite: "TLS_TEST".to_string(),
        };
        let mut handles = vec![];
        for _ in 0..10 {
            let manager = manager.clone();
            let tls_info = tls_info.clone();
            handles.push(tokio::spawn(async move {
                let session = manager.create_session(tls_info).await.unwrap();
                manager.get_session(&session.id).await.unwrap();
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
    }
}
