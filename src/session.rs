mod errors;
#[cfg(test)]
mod tests;

pub mod store;

use color_eyre::eyre::eyre;
pub use errors::SessionError;
pub use store::{ExpiredDeletion, SessionStore, SessionStoreError};

use std::{array::TryFromSliceError, result, sync::Arc};

use bincode::config::standard;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use time::{Duration, UtcDateTime};

pub(crate) const DEFAULT_DURATION: Duration = Duration::minutes(15);
pub(crate) const DEFAULT_MAX_SESSIONS: usize = 100_000;
pub(crate) const TIMESTAMP_BYTES: usize = 16;

type Result<T> = result::Result<T, SessionError>;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SessionEntry {
    pub data: Vec<u8>,
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
    /// By default sessions expire after 15 minutes with a maximum of 100,000 allowed active sessions.
    /// These values can be overridden using the [with_expiry][we] and [with_max_sessions][wms] chainable methods.
    ///
    /// [we]: Self::with_expiry
    /// [wms]: Self::with_max_sessions
    ///
    /// # Examples
    ///
    /// ```
    /// # use eid_server::session::SessionManager;
    /// # use eid_server::session::store::MemoryStore;
    /// use time::Duration;
    ///
    /// let store = MemoryStore::new();
    /// let manager = SessionManager::new(store)
    ///     .with_expiry(Duration::minutes(30))
    ///     .with_max_sessions(50_000);
    /// ```
    pub fn new(store: Store) -> Self {
        Self {
            store: Arc::new(store),
            expiry: DEFAULT_DURATION,
            max_sessions: DEFAULT_MAX_SESSIONS,
        }
    }

    /// Configures the default expiry duration for all sessions.
    pub fn with_expiry(mut self, duration: Duration) -> Self {
        self.expiry = duration;
        self
    }

    /// Configures the maximum allowed number of sessions to handle at the same time.
    ///
    /// When this limit is reached, the session manager will reject new sessions
    /// until some sessions are deleted.
    pub fn with_max_sessions(mut self, max_sessions: usize) -> Self {
        self.max_sessions = max_sessions;
        self
    }

    /// Inserts a session value into the store.
    pub async fn insert(&self, key: Id, value: impl Serialize) -> Result<()> {
        if self.store.count().await? >= self.max_sessions {
            return Err(SessionError::MaxSessions);
        }

        let expiry_date = UtcDateTime::now().saturating_add(self.expiry);
        let expiry_bytes = expiry_date.unix_timestamp_nanos().to_le_bytes();
        let data_bytes = bincode::serde::encode_to_vec(value, standard())?;
        let ttl = self.expiry.whole_seconds().max(0) as u64;

        let mut payload = Vec::with_capacity(TIMESTAMP_BYTES + data_bytes.len());
        payload.extend_from_slice(&expiry_bytes);
        payload.extend_from_slice(&data_bytes);

        self.store.save(key.as_ref(), &payload, Some(ttl)).await?;
        Ok(())
    }

    /// Gets a session value from the store.
    pub async fn get<T: DeserializeOwned>(&self, key: Id) -> Result<Option<T>> {
        let Some(session_data) = self.store.load(key.as_ref()).await? else {
            return Ok(None);
        };

        validate_session_data(&session_data)?;
        let (data, _) =
            bincode::serde::decode_from_slice(&session_data[TIMESTAMP_BYTES..], standard())?;
        Ok(Some(data))
    }

    /// Removes a session from the store.
    pub async fn remove(&self, key: Id) -> Result<()> {
        self.store.delete(key.as_ref()).await?;
        Ok(())
    }

    /// Sets the expiry for a specific session if it exists.
    pub async fn set_expiry(&self, key: Id, duration: Duration) -> Result<()> {
        let Some(mut session_data) = self.store.load(key.as_ref()).await? else {
            return Ok(());
        };

        validate_session_data(&session_data)?;
        let new_expiry_date = UtcDateTime::now().saturating_add(duration);
        let new_expiry_bytes = new_expiry_date.unix_timestamp_nanos().to_le_bytes();
        let ttl = duration.whole_seconds().max(0) as u64;
        session_data[..TIMESTAMP_BYTES].copy_from_slice(&new_expiry_bytes);

        self.store
            .save(key.as_ref(), &session_data, Some(ttl))
            .await?;
        Ok(())
    }

    /// Gets the expiry as `UtcDateTime` for a specific session if it exists.
    pub async fn get_expiry_date(&self, key: Id) -> Result<Option<UtcDateTime>> {
        let Some(session_data) = self.store.load(key.as_ref()).await? else {
            return Ok(None);
        };

        validate_session_data(&session_data)?;
        let expiry_bytes: [u8; TIMESTAMP_BYTES] = session_data[..TIMESTAMP_BYTES]
            .try_into()
            .map_err(|e: TryFromSliceError| SessionError::Other(e.into()))?;
        let timestamp = i128::from_le_bytes(expiry_bytes);

        let expiry_date = UtcDateTime::from_unix_timestamp_nanos(timestamp)
            .map_err(|e| SessionError::Other(e.into()))?;

        Ok(Some(expiry_date))
    }
}

fn validate_session_data(session_data: &[u8]) -> Result<()> {
    if session_data.len() < TIMESTAMP_BYTES {
        return Err(SessionError::Other(eyre!(
            "Invalid session data. Expected at least {} bytes, found {}",
            TIMESTAMP_BYTES,
            session_data.len()
        )));
    }
    Ok(())
}

/// ID type for sessions
///
/// Wraps a vector of bytes
#[derive(Clone, Debug, Deserialize, Serialize, Eq, Hash, PartialEq)]
pub struct Id(Vec<u8>);

impl Id {
    /// Creates a new session ID.
    pub fn new<T: AsRef<[u8]>>(value: T) -> Self {
        let bytes = value.as_ref();
        let mut vec = Vec::with_capacity(bytes.len());
        vec.extend_from_slice(bytes);
        Self(vec)
    }

    /// Creates an ID from a string slice
    pub fn from_str(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }

    /// Get the inner bytes without
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for Id {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl From<Vec<u8>> for Id {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&str> for Id {
    fn from(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }
}

impl From<String> for Id {
    fn from(value: String) -> Self {
        Self(value.as_bytes().to_vec())
    }
}

impl AsRef<[u8]> for Id {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
