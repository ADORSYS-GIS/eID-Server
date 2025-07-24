// session.rs - Session store traits and implementations

use async_trait::async_trait;
use dashmap::DashMap;
use redis::RedisError;
use redis::aio::ConnectionManager;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SessionStoreError {
    #[error("Redis error: {0}")]
    RedisError(#[from] RedisError),
}

/// Abstract interface for TLS session storage backends
///
/// It could be used to implement a shared TLS session cache across multiple instances of the server.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Store a new session or update an existing one
    async fn store_session(
        &self,
        session_id: &[u8],
        session_data: &[u8],
    ) -> Result<(), SessionStoreError>;

    /// Retrieve a session by ID
    async fn get_session(&self, session_id: &[u8]) -> Result<Option<Vec<u8>>, SessionStoreError>;

    /// Remove a session by ID
    async fn remove_session(&self, session_id: &[u8]) -> Result<(), SessionStoreError>;
}

/// Represents an in-memory TLS session store
pub struct InMemorySessionStore {
    sessions: Arc<DashMap<Vec<u8>, Vec<u8>>>,
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
        }
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn store_session(
        &self,
        session_id: &[u8],
        session_data: &[u8],
    ) -> Result<(), SessionStoreError> {
        self.sessions
            .insert(session_id.to_vec(), session_data.to_vec());
        Ok(())
    }

    async fn get_session(&self, session_id: &[u8]) -> Result<Option<Vec<u8>>, SessionStoreError> {
        Ok(self
            .sessions
            .get(session_id)
            .map(|entry| entry.value().clone()))
    }

    async fn remove_session(&self, session_id: &[u8]) -> Result<(), SessionStoreError> {
        self.sessions.remove(session_id);
        Ok(())
    }
}

/// Redis-based session store implementation
pub struct RedisSessionStore {
    conn: ConnectionManager,
    ttl: Option<u64>,
}

impl RedisSessionStore {
    /// Create a new Redis session store from a connection manager
    pub fn new(conn_manager: ConnectionManager) -> Result<Self, SessionStoreError> {
        Ok(Self {
            conn: conn_manager,
            ttl: None,
        })
    }

    /// Set the time-to-live (TTL) for the stored data
    pub fn with_ttl(mut self, ttl: u64) -> Self {
        self.ttl = Some(ttl);
        self
    }
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn store_session(
        &self,
        session_id: &[u8],
        session_data: &[u8],
    ) -> Result<(), SessionStoreError> {
        use redis::AsyncCommands;

        let mut conn = self.conn.clone();

        if let Some(ttl) = self.ttl {
            let _: () = conn.set_ex(session_id, session_data, ttl).await?;
        } else {
            let _: () = conn.set(session_id, session_data).await?;
        }
        Ok(())
    }

    async fn get_session(&self, session_id: &[u8]) -> Result<Option<Vec<u8>>, SessionStoreError> {
        use redis::AsyncCommands;

        let mut conn = self.conn.clone();
        Ok(conn.get(session_id).await?)
    }

    async fn remove_session(&self, session_id: &[u8]) -> Result<(), SessionStoreError> {
        use redis::AsyncCommands;

        let mut conn = self.conn.clone();
        let _: () = conn.del(session_id).await?;
        Ok(())
    }
}
