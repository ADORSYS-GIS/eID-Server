use ::redis::RedisError;
use async_trait::async_trait;
use color_eyre::Report;
use std::error::Error as StdError;
use std::fmt;

mod memory;
mod redis;

pub use memory::MemoryStore;
pub use redis::RedisStore;

type Result<T> = std::result::Result<T, SessionStoreError>;

/// Error type for session store operations.
#[derive(Debug)]
pub struct SessionStoreError {
    error: Report,
}

impl SessionStoreError {
    pub fn new<T>(error: T) -> Self
    where
        T: StdError + Send + Sync + 'static,
    {
        Self {
            error: Report::new(error),
        }
    }

    pub fn msg<T>(message: T) -> Self
    where
        T: fmt::Debug + fmt::Display + Send + Sync + 'static,
    {
        Self {
            error: Report::msg(message),
        }
    }
}

impl StdError for SessionStoreError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.error.source()
    }
}

impl fmt::Display for SessionStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl From<RedisError> for SessionStoreError {
    fn from(error: RedisError) -> Self {
        Self {
            error: Report::new(error),
        }
    }
}

impl From<serde_json::Error> for SessionStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self {
            error: Report::new(error),
        }
    }
}

/// Abstract interface for session storage backends.
#[async_trait]
pub trait SessionStore: Send + Sync + Clone + 'static {
    /// Saves the provided session data to the store.
    ///
    /// An optional TTL can be provided to specify the time-to-live for the session.
    async fn save(&self, session_id: &[u8], data: &[u8], ttl: Option<u64>) -> Result<()>;

    /// Loads an existing session data from the store using the provided ID.
    async fn load(&self, session_id: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Checks if the session with the provided ID exists in the store.
    async fn exists(&self, session_id: &[u8]) -> Result<bool>;

    /// Deletes a session record from the store using the provided ID.
    async fn delete(&self, session_id: &[u8]) -> Result<()>;

    /// Returns the number of active sessions in the store.
    async fn count(&self) -> Result<usize>;
}

/// Provides a method for deleting expired sessions.
#[async_trait]
pub trait ExpiredDeletion: SessionStore
where
    Self: Sized,
{
    /// A method for deleting expired sessions from the store.
    async fn delete_expired(&self) -> Result<()>;

    /// This function will keep running indefinitely, deleting expired sessions
    /// and then waiting for the specified period before deleting again.
    async fn delete_expired_sessions(self, period: tokio::time::Duration) -> Result<()> {
        let mut interval = tokio::time::interval(period);
        interval.tick().await;
        loop {
            interval.tick().await;
            self.delete_expired().await?;
        }
    }
}
