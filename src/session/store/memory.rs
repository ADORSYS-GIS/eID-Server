use crate::session::{
    Session,
    store::{Result, SessionStore},
};
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;
use time::UtcDateTime;

/// An in-memory session store.
///
/// Useful for testing and development.
#[derive(Debug, Default, Clone)]
pub struct MemoryStore {
    sessions: Arc<DashMap<Vec<u8>, Vec<u8>>>,
}

#[async_trait]
impl SessionStore for MemoryStore {
    async fn save(&self, session_id: &[u8], data: &[u8]) -> Result<()> {
        self.sessions.insert(session_id.to_vec(), data.to_vec());
        Ok(())
    }

    async fn load(&self, session_id: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(session_bytes) = self.sessions.get(session_id) {
            let session: Session = serde_json::from_slice(session_bytes.value())?;
            if is_active(session.expiry_date) {
                return Ok(Some(session_bytes.value().to_vec()));
            }
            self.sessions.remove(session_id);
        }
        Ok(None)
    }

    async fn delete(&self, session_id: &[u8]) -> Result<()> {
        self.sessions.remove(session_id);
        Ok(())
    }

    async fn count(&self) -> Result<usize> {
        Ok(self.sessions.len())
    }
}

fn is_active(expiry_date: UtcDateTime) -> bool {
    expiry_date > UtcDateTime::now()
}
