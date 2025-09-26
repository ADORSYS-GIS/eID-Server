mod data;
mod errors;
mod store;
#[cfg(test)]
mod tests;

// Re-export public types
pub use data::*;
pub use errors::SessionError;
pub use store::*;

use std::{array::TryFromSliceError, fmt, result, sync::Arc};

use bincode::{
    config::standard,
    serde::{decode_from_slice as bincode_decode, encode_to_vec as bincode_encode},
};
use color_eyre::eyre::eyre;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use time::{Duration, UtcDateTime};

pub(crate) const DEFAULT_DURATION: Duration = Duration::minutes(15);
pub(crate) const DEFAULT_MAX_SESSIONS: usize = 1000;
pub(crate) const TIMESTAMP_BYTES: usize = 16;

type Result<T> = result::Result<T, SessionError>;

/// A session manager used to manage the lifecycle of sessions.
///
/// `SessionManager` provides a high-level API to interact with a configurable
/// backend session store. It handles expiry time management and session limits
/// automatically.
///
/// # Defaults
/// By default, sessions expire after **15 minutes** with a maximum of **1,000**
/// allowed active sessions. These values can be overridden using the
/// [`with_expiry`][we] and [`with_max_sessions`][wms] methods.
///
/// # Backend Stores
/// The manager is generic over the [`SessionStore`] trait, allowing it to work
/// with different backends like in-memory stores, Redis, or other custom stores.
/// It provides out-of-the-box implementations for both [`MemoryStore`] and
/// [`RedisStore`].
///
/// [we]: Self::with_expiry
/// [wms]: Self::with_max_sessions
#[derive(Clone)]
pub struct SessionManager {
    store: Arc<dyn SessionStore>,
    expiry: Duration,
    max_sessions: usize,
}

impl SessionManager {
    /// Creates a new session manager with the provided store.
    ///
    /// # Examples
    ///
    /// ```
    /// # use eid_server::session::SessionManager;
    /// # use eid_server::session::MemoryStore;
    /// use time::Duration;
    ///
    /// let store = MemoryStore::new();
    /// let manager = SessionManager::new(store);
    /// ```
    pub fn new(store: Arc<dyn SessionStore>) -> Self {
        Self {
            store,
            expiry: DEFAULT_DURATION,
            max_sessions: DEFAULT_MAX_SESSIONS,
        }
    }

    /// Overrides the default expiry duration for all sessions.
    ///
    /// Default expiry is 15 minutes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use eid_server::session::SessionManager;
    /// # use eid_server::session::MemoryStore;
    /// use time::Duration;
    ///
    /// let store = MemoryStore::new();
    /// let manager = SessionManager::new(store)
    ///     .with_expiry(Duration::minutes(30));
    /// ```
    pub fn with_expiry(mut self, duration: Duration) -> Self {
        self.expiry = duration;
        self
    }

    /// Configures the maximum allowed number of sessions to handle at the same time.
    ///
    /// When this limit is reached, the session manager will reject new sessions
    /// until some sessions are deleted.
    ///
    /// # Examples
    ///
    /// ```
    /// # use eid_server::session::SessionManager;
    /// # use eid_server::session::MemoryStore;
    ///
    /// let store = MemoryStore::new();
    /// let manager = SessionManager::new(store)
    ///     .with_max_sessions(100);
    /// ```
    pub fn with_max_sessions(mut self, max_sessions: usize) -> Self {
        self.max_sessions = max_sessions;
        self
    }

    /// Inserts a session value into the store.
    ///
    /// # Examples
    ///
    /// ```
    /// # pollster::block_on(async {
    /// # use eid_server::session::SessionManager;
    /// # use eid_server::session::MemoryStore;
    ///
    /// let store = MemoryStore::new();
    /// let manager = SessionManager::new(store);
    ///
    /// let key = "session_id";
    /// let value = "session_value";
    /// manager.insert(key, value).await.unwrap();
    /// # })
    /// ```
    pub async fn insert(&self, key: impl Into<Id>, value: impl Serialize) -> Result<()> {
        if self.store.count().await? >= self.max_sessions {
            return Err(SessionError::MaxSessions);
        }

        let expiry_date = UtcDateTime::now().saturating_add(self.expiry);
        let expiry_bytes = expiry_date.unix_timestamp_nanos().to_le_bytes();
        let data_bytes = bincode_encode(value, standard())?;
        let ttl = self.expiry.whole_seconds().max(0) as u64;

        let mut session_bytes = Vec::with_capacity(TIMESTAMP_BYTES + data_bytes.len());
        session_bytes.extend_from_slice(&expiry_bytes);
        session_bytes.extend_from_slice(&data_bytes);

        self.store
            .save(key.into().as_ref(), &session_bytes, Some(ttl))
            .await?;
        Ok(())
    }

    /// Gets a session value from the store.
    ///
    /// # Examples
    ///
    /// ```
    /// # pollster::block_on(async {
    /// # use eid_server::session::SessionManager;
    /// # use eid_server::session::MemoryStore;
    ///
    /// let store = MemoryStore::new();
    /// let manager = SessionManager::new(store);
    ///
    /// let key = "session_id";
    /// let value = "session_value";
    /// manager.insert(key, value).await.unwrap();
    ///
    /// let value = manager.get::<String>(key).await.unwrap();
    /// assert_eq!(value, Some("session_value".to_string()));
    /// # })
    /// ```
    pub async fn get<T: DeserializeOwned>(&self, key: impl Into<Id>) -> Result<Option<T>> {
        let Some(session_bytes) = self.store.load(key.into().as_ref()).await? else {
            return Ok(None);
        };

        validate_session_data(&session_bytes)?;
        let (data, _) = bincode_decode(&session_bytes[TIMESTAMP_BYTES..], standard())?;
        Ok(Some(data))
    }

    /// Checks if a session exists in the store.
    ///
    /// # Examples
    ///
    /// ```
    /// # pollster::block_on(async {
    /// # use eid_server::session::SessionManager;
    /// # use eid_server::session::MemoryStore;
    ///
    /// let store = MemoryStore::new();
    /// let manager = SessionManager::new(store);
    ///
    /// let key = "session_id";
    /// let value = "session_value";
    /// manager.insert(key, value).await.unwrap();
    ///
    /// let exists = manager.exists(key).await.unwrap();
    /// assert!(exists);
    /// assert!(!manager.exists("nonexistent_key").await.unwrap());
    /// # })
    /// ```
    pub async fn exists(&self, key: impl Into<Id>) -> Result<bool> {
        self.store
            .exists(key.into().as_ref())
            .await
            .map_err(Into::into)
    }

    /// Removes a session from the store.
    ///
    /// # Examples
    ///
    /// ```
    /// # pollster::block_on(async {
    /// # use eid_server::session::SessionManager;
    /// # use eid_server::session::MemoryStore;
    ///
    /// let store = MemoryStore::new();
    /// let manager = SessionManager::new(store);
    ///
    /// let key = "session_id";
    /// let value = "session_value";
    /// manager.insert(key, value).await.unwrap();
    ///
    /// manager.remove(key).await.unwrap();
    /// assert!(manager.get::<String>(key).await.unwrap().is_none());
    /// # })
    /// ```
    pub async fn remove(&self, key: impl Into<Id>) -> Result<()> {
        self.store.delete(key.into().as_ref()).await?;
        Ok(())
    }

    /// Sets the expiry for a specific session if it exists.
    ///
    /// # Examples
    ///
    /// ```
    /// # pollster::block_on(async {
    /// # use eid_server::session::SessionManager;
    /// # use eid_server::session::MemoryStore;
    /// use time::Duration;
    ///
    /// let store = MemoryStore::new();
    /// let manager = SessionManager::new(store);
    ///
    /// let key = "session_id";
    /// let value = "session_value";
    /// manager.insert(key, value).await.unwrap();
    ///
    /// let res = manager.set_expiry(key, Duration::minutes(30)).await;
    /// assert!(res.is_ok());
    /// # })
    /// ```
    pub async fn set_expiry(&self, key: impl Into<Id>, duration: Duration) -> Result<()> {
        let key = key.into();
        let Some(mut session_bytes) = self.store.load(key.as_ref()).await? else {
            return Ok(());
        };

        validate_session_data(&session_bytes)?;
        let new_expiry_date = UtcDateTime::now().saturating_add(duration);
        let new_expiry_bytes = new_expiry_date.unix_timestamp_nanos().to_le_bytes();
        let ttl = duration.whole_seconds().max(0) as u64;
        session_bytes[..TIMESTAMP_BYTES].copy_from_slice(&new_expiry_bytes);

        self.store
            .save(key.as_ref(), &session_bytes, Some(ttl))
            .await?;
        Ok(())
    }

    /// Gets the expiry as `UtcDateTime` for a specific session if it exists.
    ///
    /// # Examples
    ///
    /// ```
    /// # pollster::block_on(async {
    /// # use eid_server::session::SessionManager;
    /// # use eid_server::session::MemoryStore;
    /// use time::Duration;
    ///
    /// let store = MemoryStore::new();
    /// let manager = SessionManager::new(store);
    ///
    /// let key = "session_id";
    /// let value = "session_value";
    /// manager.insert(key, value).await.unwrap();
    ///
    /// let res = manager.set_expiry(key, Duration::minutes(30)).await;
    /// assert!(res.is_ok());
    ///
    /// let expiry_date = manager.get_expiry_date(key).await.unwrap();
    /// assert!(expiry_date.is_some());
    /// # })
    /// ```
    pub async fn get_expiry_date(&self, key: impl Into<Id>) -> Result<Option<UtcDateTime>> {
        let Some(session_bytes) = self.store.load(key.into().as_ref()).await? else {
            return Ok(None);
        };

        validate_session_data(&session_bytes)?;
        let expiry_bytes: [u8; TIMESTAMP_BYTES] = session_bytes[..TIMESTAMP_BYTES]
            .try_into()
            .map_err(|e: TryFromSliceError| SessionError::Other(e.into()))?;
        let timestamp = i128::from_le_bytes(expiry_bytes);

        let expiry_date = UtcDateTime::from_unix_timestamp_nanos(timestamp)
            .map_err(|e| SessionError::Other(e.into()))?;

        Ok(Some(expiry_date))
    }
}

impl fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionManager")
            .field("expiry", &self.expiry)
            .field("max_sessions", &self.max_sessions)
            .finish()
    }
}

fn validate_session_data(session_bytes: &[u8]) -> Result<()> {
    if session_bytes.len() < TIMESTAMP_BYTES {
        return Err(SessionError::Other(eyre!(
            "Invalid session data. Expected at least {} bytes, found {}",
            TIMESTAMP_BYTES,
            session_bytes.len()
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

    /// Get the inner bytes of the ID
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

impl AsRef<[u8]> for Id {
    fn as_ref(&self) -> &[u8] {
        &self.0
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
