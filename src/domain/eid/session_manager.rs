use async_trait::async_trait;
use color_eyre::eyre::eyre;
use redis::AsyncCommands;
use std::sync::Arc;
use tokio::{runtime::Handle, sync::RwLock};
use tracing::{debug, error};
use uuid::Uuid;

use crate::{
    domain::eid::service::SessionInfo,
    tls::{PskStore, PskStoreError},
};

#[async_trait]
pub trait SessionManager
where
    Self: Send + Sync + std::fmt::Debug,
{
    async fn generate_session_id(&self) -> color_eyre::Result<String>;
    async fn get_session(&self, session_id: &str) -> color_eyre::Result<Option<SessionInfo>>;
    async fn store_session(&self, session: SessionInfo) -> color_eyre::Result<()>;
    async fn remove_session(&self, session_id: &str) -> color_eyre::Result<()>;
    async fn remove_expired_sessions(&self) -> color_eyre::Result<()>;
    async fn session_count(&self) -> color_eyre::Result<usize>;
}

#[derive(Clone, Debug)]
pub struct InMemorySessionManager {
    sessions: Arc<RwLock<Vec<SessionInfo>>>,
}

#[async_trait]
impl PskStore for Arc<dyn SessionManager> {
    async fn get_psk(&self, identity: &[u8]) -> Result<Option<Vec<u8>>, PskStoreError> {
        let id = String::from_utf8_lossy(identity).into_owned();

        let task = self.get_session(&id);
        let session = tokio::task::block_in_place(move || Handle::current().block_on(task))
            .map_err(|e| PskStoreError::msg(format!("Session lookup failed: {e}")))?;

        match session {
            Some(s) => hex::decode(&s.psk)
                .map(Some)
                .map_err(|e| PskStoreError::msg(format!("Invalid PSK hex format: {e}"))),
            None => Ok(None),
        }
    }
}

impl InMemorySessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl Default for InMemorySessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionManager for InMemorySessionManager {
    async fn generate_session_id(&self) -> color_eyre::Result<String> {
        const MAX_ATTEMPTS: usize = 5;
        let mut attempts = 0;

        loop {
            if attempts >= MAX_ATTEMPTS {
                error!(
                    "Failed to generate unique session ID after {} attempts",
                    MAX_ATTEMPTS
                );
                return Err(color_eyre::eyre::eyre!(
                    "Failed to generate unique session ID"
                ));
            }

            let session_id = Uuid::new_v4().simple().to_string();
            debug!("Generated session_id: {}", session_id);

            let sessions = self.sessions.read().await;
            if !sessions.iter().any(|s| s.id == session_id) {
                return Ok(session_id);
            }

            debug!("Session ID collision detected for: {}", session_id);
            attempts += 1;
        }
    }

    async fn store_session(&self, session: SessionInfo) -> color_eyre::Result<()> {
        // Validate PSK format before storing
        if hex::decode(&session.psk).is_err() {
            return Err(eyre!("Invalid PSK hex format in session"));
        }

        let mut sessions = self.sessions.write().await;
        let now = chrono::Utc::now();
        sessions.retain(|s| s.expiry > now);
        sessions.push(session);
        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> color_eyre::Result<Option<SessionInfo>> {
        let sessions = self.sessions.read().await;
        Ok(sessions.iter().find(|s| s.id == session_id).cloned())
    }

    async fn remove_expired_sessions(&self) -> color_eyre::Result<()> {
        let mut sessions = self.sessions.write().await;
        let now = chrono::Utc::now();
        sessions.retain(|session| session.expiry > now);
        Ok(())
    }

    async fn remove_session(&self, session_id: &str) -> color_eyre::Result<()> {
        let mut sessions = self.sessions.write().await;
        sessions.retain(|s| s.id != session_id);
        Ok(())
    }

    async fn session_count(&self) -> color_eyre::Result<usize> {
        let sessions = self.sessions.read().await;
        Ok(sessions.len())
    }
}

#[derive(Clone, Debug)]
pub struct RedisSessionManager {
    client: redis::Client,
    session_ttl_seconds: i64,
}

impl RedisSessionManager {
    pub fn new(redis_url: &str, session_ttl_minutes: i64) -> color_eyre::Result<Self> {
        let client = redis::Client::open(redis_url).map_err(|e| {
            error!("Failed to create Redis client: {}", e);
            color_eyre::eyre::eyre!("Failed to create Redis client: {}", e)
        })?;
        Ok(Self {
            client,
            session_ttl_seconds: session_ttl_minutes * 60,
        })
    }

    async fn get_redis_connection(&self) -> color_eyre::Result<redis::aio::MultiplexedConnection> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                error!("Failed to get multiplexed async Redis connection: {}", e);
                color_eyre::eyre::eyre!("Failed to get multiplexed async Redis connection: {}", e)
            })
    }
}

#[async_trait]
impl SessionManager for RedisSessionManager {
    async fn generate_session_id(&self) -> color_eyre::Result<String> {
        const MAX_ATTEMPTS: usize = 5;
        let mut attempts = 0;
        let mut conn = self.get_redis_connection().await?;

        loop {
            if attempts >= MAX_ATTEMPTS {
                error!(
                    "Failed to generate unique session ID after {} attempts",
                    MAX_ATTEMPTS
                );
                return Err(color_eyre::eyre::eyre!(
                    "Failed to generate unique session ID"
                ));
            }

            let session_id = Uuid::new_v4().simple().to_string();
            debug!("Generated session_id: {}", session_id);

            let exists: bool = conn.exists(&session_id).await.map_err(|e| {
                error!("Failed to check session ID existence: {}", e);
                color_eyre::eyre::eyre!("Failed to check session ID existence: {}", e)
            })?;

            if !exists {
                return Ok(session_id);
            }

            debug!("Session ID collision detected for: {}", session_id);
            attempts += 1;
        }
    }

    async fn store_session(&self, session: SessionInfo) -> color_eyre::Result<()> {
        // Validate PSK format before storing
        if hex::decode(&session.psk).is_err() {
            return Err(eyre!("Invalid PSK hex format in session"));
        }

        let mut conn = self.get_redis_connection().await?;
        let serialized = serde_json::to_string(&session).map_err(|e| {
            error!("Failed to serialize session: {}", e);
            color_eyre::eyre::eyre!("Failed to serialize session: {}", e)
        })?;

        // Explicitly specify the return type as () for set_ex
        let _: () = conn
            .set_ex(&session.id, &serialized, self.session_ttl_seconds as u64)
            .await
            .map_err(|e| {
                error!("Failed to store session in Redis: {}", e);
                color_eyre::eyre::eyre!("Failed to store session in Redis: {}", e)
            })?;

        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> color_eyre::Result<Option<SessionInfo>> {
        let mut conn = self.get_redis_connection().await?;
        let result: Option<String> = conn.get(session_id).await.map_err(|e| {
            error!("Failed to get session from Redis: {}", e);
            color_eyre::eyre::eyre!("Failed to get session from Redis: {}", e)
        })?;

        match result {
            Some(serialized) => {
                let session: SessionInfo = serde_json::from_str(&serialized).map_err(|e| {
                    error!("Failed to deserialize session: {}", e);
                    color_eyre::eyre::eyre!("Failed to deserialize session: {}", e)
                })?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn remove_expired_sessions(&self) -> color_eyre::Result<()> {
        // Redis handles expiration automatically via TTL
        debug!("Redis handles session expiration via TTL, no manual cleanup needed");
        Ok(())
    }

    async fn remove_session(&self, session_id: &str) -> color_eyre::Result<()> {
        let mut conn = self.get_redis_connection().await?;
        let _: i64 = conn.del(session_id).await.map_err(|e| {
            error!("Failed to remove session from Redis: {}", e);
            color_eyre::eyre::eyre!("Failed to remove session from Redis: {}", e)
        })?;
        Ok(())
    }

    async fn session_count(&self) -> color_eyre::Result<usize> {
        let mut conn = self.get_redis_connection().await?;
        let keys: Vec<String> = conn.keys("*").await.map_err(|e| {
            error!("Failed to get session keys from Redis: {}", e);
            color_eyre::eyre::eyre!("Failed to get session keys from Redis: {}", e)
        })?;
        Ok(keys.len())
    }
}
