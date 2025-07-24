use crate::session::{
    Session,
    store::{Result, SessionStore},
};
use async_trait::async_trait;
use redis::{AsyncCommands, aio::ConnectionManager};
use time::UtcDateTime;

/// A Redis session store.
#[derive(Clone)]
pub struct RedisStore {
    conn: ConnectionManager,
}

impl RedisStore {
    /// Creates a new Redis store from a connection manager.
    pub fn new(conn: ConnectionManager) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl SessionStore for RedisStore {
    async fn save(&self, session_id: &[u8], data: &[u8]) -> Result<()> {
        let mut conn = self.conn.clone();
        let session: Session = serde_json::from_slice(data)?;
        let ttl = (session.expiry_date - UtcDateTime::now()).whole_seconds();
        let _: () = conn.set_ex(session_id, data, ttl as u64).await?;
        Ok(())
    }

    async fn load(&self, session_id: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut conn = self.conn.clone();
        let result = conn.get(session_id).await?;
        Ok(result)
    }

    async fn delete(&self, session_id: &[u8]) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: () = conn.del(session_id).await?;
        Ok(())
    }

    async fn count(&self) -> Result<usize> {
        let mut conn = self.conn.clone();
        let count = redis::cmd("DBSIZE").query_async(&mut conn).await?;
        Ok(count)
    }
}
