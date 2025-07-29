mod errors;
pub mod store;

pub use errors::SessionError;
pub use store::{ExpiredDeletion, SessionStore, SessionStoreError};

use std::{result, sync::Arc};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use time::{Duration, UtcDateTime};

pub(crate) const DEFAULT_DURATION: Duration = Duration::minutes(15);
pub(crate) const DEFAULT_MAX_SESSIONS: usize = 100_000;

type Result<T> = result::Result<T, SessionError>;

/// ID type for sessions
///
/// Wraps a vector of bytes
#[derive(Clone, Debug, Deserialize, Serialize, Eq, Hash, PartialEq)]
pub struct SessionId(Vec<u8>);

impl SessionId {
    /// Creates a new session ID from a byte slice.
    pub fn new<T: AsRef<[u8]>>(value: T) -> Self {
        Self(value.as_ref().to_vec())
    }
}

impl From<&[u8]> for SessionId {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl From<Vec<u8>> for SessionId {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for SessionId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Session {
    pub data: Value,
    pub expiry_date: UtcDateTime,
}

/// A session manager
#[derive(Debug, Clone)]
pub struct SessionManager<Store: SessionStore> {
    store: Arc<Store>,
    expiry: Duration,
    max_sessions: usize,
}

impl<Store: SessionStore> SessionManager<Store> {
    /// Creates a new session manager with the provided store.
    ///
    /// The default expiry duration is 15 minutes and the default maximum number of sessions is 100,000.
    /// These values can be overridden using the `with_expiry` and `with_max_sessions` chainable methods.
    pub fn new(store: Store) -> Self {
        Self {
            store: Arc::new(store),
            expiry: DEFAULT_DURATION,
            max_sessions: DEFAULT_MAX_SESSIONS,
        }
    }

    /// Configures the default expiry duration for all sessions.
    #[must_use]
    pub fn with_expiry(mut self, duration: Duration) -> Self {
        self.expiry = duration;
        self
    }

    /// Configures the maximum allowed number of sessions to handle at the same time.
    ///
    /// When this limit is reached, the session manager will reject new sessions
    /// until some sessions are deleted.
    #[must_use]
    pub fn with_max_sessions(mut self, max_sessions: usize) -> Self {
        self.max_sessions = max_sessions;
        self
    }

    /// Inserts a session value into the store.
    pub async fn insert(&self, key: SessionId, value: impl Serialize) -> Result<()> {
        if self.store.count().await? >= self.max_sessions {
            return Err(SessionError::MaxSessions);
        }

        let session = Session {
            data: serde_json::to_value(value)?,
            expiry_date: UtcDateTime::now().saturating_add(self.expiry),
        };

        let session_bytes = serde_json::to_vec(&session)?;
        self.store.save(key.as_ref(), &session_bytes).await?;
        Ok(())
    }

    /// Gets a session value from the store.
    pub async fn get<T: DeserializeOwned>(&self, key: SessionId) -> Result<Option<T>> {
        if let Some(session_data) = self.store.load(key.as_ref()).await? {
            let session: Session = serde_json::from_slice(&session_data)?;
            return Ok(serde_json::from_value(session.data)?);
        }
        Ok(None)
    }

    /// Removes a session from the store.
    pub async fn remove(&self, key: SessionId) -> Result<()> {
        self.store.delete(key.as_ref()).await?;
        Ok(())
    }

    /// Sets the expiry for a specific session if it exists.
    pub async fn set_expiry(&self, key: SessionId, duration: Duration) -> Result<()> {
        if let Some(session_data) = self.store.load(key.as_ref()).await? {
            let mut session: Session = serde_json::from_slice(&session_data)?;
            session.expiry_date = UtcDateTime::now().saturating_add(duration);
            let updated_session_bytes = serde_json::to_vec(&session)?;
            self.store
                .save(key.as_ref(), &updated_session_bytes)
                .await?;
        }
        Ok(())
    }

    /// Gets the expiry as `OffsetDateTime` for a specific session if it exists.
    pub async fn get_expiry_date(&self, key: SessionId) -> Result<Option<UtcDateTime>> {
        if let Some(session_data) = self.store.load(key.as_ref()).await? {
            let session: Session = serde_json::from_slice(&session_data)?;
            return Ok(Some(session.expiry_date));
        }
        Ok(None)
    }
}
