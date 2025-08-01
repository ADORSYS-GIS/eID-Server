use crate::session::store::{Result, SessionStore};
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;
use time::{Duration, UtcDateTime};

#[derive(Debug)]
struct SessionData {
    data: Vec<u8>,
    expiry: Option<UtcDateTime>,
}

/// An in-memory session store
///
/// Useful for testing and development
#[derive(Debug, Default, Clone)]
pub struct MemoryStore {
    sessions: Arc<DashMap<Vec<u8>, SessionData>>,
}

impl MemoryStore {
    /// Creates a new in-memory session store
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
        }
    }
}

#[async_trait]
impl SessionStore for MemoryStore {
    async fn save(&self, session_id: &[u8], data: &[u8], ttl: Option<u64>) -> Result<()> {
        let expiry =
            ttl.map(|secs| UtcDateTime::now().saturating_add(Duration::seconds(secs as i64)));
        let session_data = SessionData {
            data: data.to_vec(),
            expiry,
        };
        self.sessions.insert(session_id.to_vec(), session_data);
        Ok(())
    }

    async fn load(&self, session_id: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(entry) = self.sessions.get(session_id) {
            let session_data = entry.value();
            match session_data.expiry {
                Some(expiry) if expiry <= UtcDateTime::now() => {
                    drop(entry);
                    self.sessions.remove(session_id);
                    Ok(None)
                }
                _ => Ok(Some(session_data.data.clone())),
            }
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, session_id: &[u8]) -> Result<()> {
        self.sessions.remove(session_id);
        Ok(())
    }

    async fn count(&self) -> Result<usize> {
        Ok(self.sessions.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_store_flow() {
        let store = MemoryStore::new();
        let session_id = b"test-session";
        let session_data = b"test-data".to_vec();

        store
            .save(session_id, &session_data, Some(3600))
            .await
            .unwrap();

        let loaded = store.load(session_id).await.unwrap().unwrap();
        assert_eq!(loaded, session_data);

        store.delete(session_id).await.unwrap();
        assert!(store.load(session_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_memory_store_count() {
        let store = MemoryStore::new();
        let session_id = b"test-session";
        let session_data = b"test-data".to_vec();

        store
            .save(session_id, &session_data, Some(3600))
            .await
            .unwrap();
        assert_eq!(store.count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_memory_store_expiry() {
        let store = MemoryStore::new();
        let session_id = b"expiring-session";
        let session_data = b"test-data".to_vec();

        store
            .save(session_id, &session_data, Some(1))
            .await
            .unwrap();
        assert!(store.load(session_id).await.unwrap().is_some());

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        assert!(store.load(session_id).await.unwrap().is_none());
    }
}
