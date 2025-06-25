use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};

#[derive(Clone, Debug)]
pub struct TransmitSession {
    pub session_id: String,
    pub last_activity: DateTime<Utc>,
    // Add more fields as needed (e.g., APDU state, timeouts)
}

impl TransmitSession {
    pub fn new(session_id: String) -> Self {
        TransmitSession {
            session_id,
            last_activity: Utc::now(),
        }
    }
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }
}

#[derive(Clone, Default)]
pub struct TransmitSessionStore {
    sessions: Arc<Mutex<HashMap<String, TransmitSession>>>,
}

impl TransmitSessionStore {
    pub fn new() -> Self {
        TransmitSessionStore {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    pub fn create_session(&self, session_id: String) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session_id.clone(), TransmitSession::new(session_id));
    }
    pub fn get_session(&self, session_id: &str) -> Option<TransmitSession> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_id) {
            session.touch();
            Some(session.clone())
        } else {
            None
        }
    }
    pub fn remove_session(&self, session_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(session_id);
    }
    pub fn cleanup_expired(&self, timeout_secs: i64) {
        let mut sessions = self.sessions.lock().unwrap();
        let now = Utc::now();
        sessions.retain(|_, session| (now - session.last_activity).num_seconds() < timeout_secs);
    }
} 