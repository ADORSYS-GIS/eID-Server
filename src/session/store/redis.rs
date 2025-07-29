use std::{
    sync::{
        Arc,
        atomic::{self, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use crate::session::{
    Session,
    store::{Result, SessionStore},
};
use async_trait::async_trait;
use redis::{AsyncCommands, AsyncIter, aio::ConnectionManager};
use time::UtcDateTime;
use tokio::sync::RwLock;

const DEFAULT_PREFIX: &str = "session";
const RESYNC_INTERVAL: Duration = Duration::from_secs(60);

/// A Redis session store.
#[derive(Clone)]
pub struct RedisStore {
    conn: ConnectionManager,
    prefix: String,
    duration: Arc<RwLock<Option<Instant>>>,
    counter: Arc<AtomicUsize>,
}

impl RedisStore {
    /// Creates a new Redis store from a connection manager.
    pub fn new(conn: ConnectionManager) -> Self {
        Self {
            conn,
            prefix: DEFAULT_PREFIX.to_string(),
            duration: Arc::new(RwLock::new(None)),
            counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Configures the prefix for all session keys.
    ///
    /// The default prefix is "session".
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    fn key(&self, session_id: &[u8]) -> Vec<u8> {
        [self.prefix.as_bytes(), session_id].concat()
    }

    async fn get_count(&self) -> Result<usize> {
        let mut conn = self.conn.clone();
        let mut count = 0;
        let pattern = format!("{}*", self.prefix);
        let mut iter: AsyncIter<Vec<u8>> = conn.scan_match(pattern).await?;
        while iter.next_item().await.is_some() {
            count += 1;
        }
        self.counter.store(count, atomic::Ordering::Release);
        Ok(self.counter.load(atomic::Ordering::Acquire))
    }
}

#[async_trait]
impl SessionStore for RedisStore {
    async fn save(&self, session_id: &[u8], data: &[u8]) -> Result<()> {
        let mut conn = self.conn.clone();
        let session: Session = serde_json::from_slice(data)?;
        let ttl = (session.expiry_date - UtcDateTime::now()).whole_seconds();
        let key = self.key(session_id);
        let _: () = conn.set_ex(key, data, ttl as u64).await?;
        Ok(())
    }

    async fn load(&self, session_id: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut conn = self.conn.clone();
        let key = self.key(session_id);
        let result = conn.get(key).await?;
        Ok(result)
    }

    async fn delete(&self, session_id: &[u8]) -> Result<()> {
        let mut conn = self.conn.clone();
        let key = self.key(session_id);

        let _: () = conn.del(key).await?;

        Ok(())
    }

    async fn count(&self) -> Result<usize> {
        // Fast path check
        if let Some(instant) = &*self.duration.read().await {
            if instant.elapsed() <= RESYNC_INTERVAL {
                return Ok(self.counter.load(Ordering::Relaxed));
            }
        }

        let mut guard = self.duration.write().await;
        // We double check after acquiring write lock
        if let Some(instant) = &*guard {
            if instant.elapsed() <= RESYNC_INTERVAL {
                return Ok(self.counter.load(Ordering::Relaxed));
            }
        }

        let count = self.get_count().await?;
        *guard = Some(Instant::now());
        Ok(count)
    }
}
