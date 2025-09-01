use async_trait::async_trait;
use color_eyre::Report;
use dashmap::DashMap;
use std::{collections::HashMap, error::Error as StdError, fmt, sync::Arc};

use crate::session::{SessionData, SessionError, SessionManager, SessionStore};

/// Abstract interface for a PSK store.
#[async_trait]
pub trait PskStore: Send + Sync {
    /// Returns the PSK for the given identity.
    async fn get_psk(&self, identity: &[u8]) -> Result<Option<Vec<u8>>, PskStoreError>;
}

#[async_trait]
impl<S: SessionStore> PskStore for SessionManager<S> {
    async fn get_psk(&self, identity: &[u8]) -> Result<Option<Vec<u8>>, PskStoreError> {
        let result: Option<SessionData> = self.get(identity).await?;

        Ok(result.map(|session| session.psk))
    }
}

/// Error type for PSK store operations.
pub struct PskStoreError(Report);

impl PskStoreError {
    pub fn new<T>(error: T) -> Self
    where
        T: StdError + Send + Sync + 'static,
    {
        Self(Report::new(error))
    }

    pub fn msg<T>(message: T) -> Self
    where
        T: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        Self(Report::msg(message))
    }
}

impl StdError for PskStoreError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.0.source()
    }
}

impl fmt::Display for PskStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for PskStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<SessionError> for PskStoreError {
    fn from(error: SessionError) -> Self {
        Self::new(error)
    }
}

#[async_trait]
impl PskStore for DashMap<String, Vec<u8>> {
    async fn get_psk(&self, identity: &[u8]) -> Result<Option<Vec<u8>>, PskStoreError> {
        let identity = std::str::from_utf8(identity).map_err(PskStoreError::new)?;
        Ok(self.get(identity).map(|entry| entry.value().clone()))
    }
}

#[async_trait]
impl PskStore for Arc<DashMap<String, Vec<u8>>> {
    async fn get_psk(&self, identity: &[u8]) -> Result<Option<Vec<u8>>, PskStoreError> {
        let identity = std::str::from_utf8(identity).map_err(PskStoreError::new)?;
        Ok(self.get(identity).map(|entry| entry.value().clone()))
    }
}

#[async_trait]
impl PskStore for HashMap<String, Vec<u8>> {
    async fn get_psk(&self, identity: &[u8]) -> Result<Option<Vec<u8>>, PskStoreError> {
        let identity = std::str::from_utf8(identity).map_err(PskStoreError::new)?;
        Ok(self.get(identity).cloned())
    }
}

#[async_trait]
impl PskStore for Arc<HashMap<String, Vec<u8>>> {
    async fn get_psk(&self, identity: &[u8]) -> Result<Option<Vec<u8>>, PskStoreError> {
        let identity = std::str::from_utf8(identity).map_err(PskStoreError::new)?;
        Ok(self.get(identity).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_psk_store() {
        let psk_store = DashMap::new();
        psk_store.insert("test".to_string(), vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(
            psk_store.get_psk(b"test").await.unwrap(),
            Some(vec![0x01, 0x02, 0x03, 0x04])
        );

        let mut psk_store = HashMap::new();
        psk_store.insert("test".to_string(), vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(
            psk_store.get_psk(b"test").await.unwrap(),
            Some(vec![0x01, 0x02, 0x03, 0x04])
        );
    }
}
