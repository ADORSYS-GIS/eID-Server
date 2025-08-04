use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use crate::session::store::{Result, SessionStore};
use async_trait::async_trait;
use redis::{AsyncCommands, AsyncIter, aio::ConnectionManager};
use tokio::sync::RwLock;

const DEFAULT_PREFIX: &str = "session";
const RESYNC_INTERVAL: Duration = Duration::from_secs(20);

/// A Redis session store.
#[derive(Clone)]
pub struct RedisStore {
    conn: ConnectionManager,
    prefix: String,
    last_sync: Arc<RwLock<Option<Instant>>>,
    counter: Arc<AtomicUsize>,
}

impl RedisStore {
    /// Creates a new Redis store from a connection manager.
    pub fn new(conn: ConnectionManager) -> Self {
        Self {
            conn,
            prefix: DEFAULT_PREFIX.to_string(),
            last_sync: Arc::new(RwLock::new(None)),
            counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Configures the prefix for all session keys.
    ///
    /// The default prefix is `"session"`.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Force a counter resync
    pub async fn force_resync(&self) -> Result<usize> {
        let count = self.active_sessions_count().await?;
        self.counter.store(count, Ordering::Release);
        *self.last_sync.write().await = Some(Instant::now());
        Ok(count)
    }

    /// Get approximate count
    pub fn cached_count(&self) -> usize {
        self.counter.load(Ordering::Acquire)
    }

    fn key(&self, session_id: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(self.prefix.len() + session_id.len());
        key.extend_from_slice(self.prefix.as_bytes());
        key.extend_from_slice(session_id);
        key
    }

    async fn active_sessions_count(&self) -> Result<usize> {
        let mut conn = self.conn.clone();
        let mut count = 0;
        let pattern = format!("{}*", self.prefix);
        let mut iter: AsyncIter<Vec<u8>> = conn.scan_match(pattern).await?;
        while iter.next_item().await.is_some() {
            count += 1;
        }
        Ok(count)
    }

    #[inline]
    fn needs_resync(&self, last_sync: &Option<Instant>) -> bool {
        match last_sync {
            Some(instant) => instant.elapsed() > RESYNC_INTERVAL,
            None => true,
        }
    }
}

#[async_trait]
impl SessionStore for RedisStore {
    async fn save(&self, session_id: &[u8], data: &[u8], ttl: Option<u64>) -> Result<()> {
        let mut conn = self.conn.clone();
        let key = self.key(session_id);

        let existed_before: bool = conn.exists(&key).await?;

        if let Some(ttl) = ttl {
            let _: () = conn.set_ex(&key, data, ttl).await?;
        } else {
            let _: () = conn.set(&key, data).await?;
        }

        if !existed_before {
            self.counter.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    async fn load(&self, session_id: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut conn = self.conn.clone();
        let key = self.key(session_id);
        let result = conn.get(key).await?;
        Ok(result)
    }

    async fn exists(&self, session_id: &[u8]) -> Result<bool> {
        let mut conn = self.conn.clone();
        let key = self.key(session_id);
        let result = conn.exists(key).await?;
        Ok(result)
    }

    async fn delete(&self, session_id: &[u8]) -> Result<()> {
        let mut conn = self.conn.clone();
        let key = self.key(session_id);
        let deleted: usize = conn.del(key).await?;
        if deleted > 0 {
            self.counter.fetch_sub(1, Ordering::Relaxed);
        }
        Ok(())
    }

    async fn count(&self) -> Result<usize> {
        // Fast path: check if we can use cached value
        {
            let guard = self.last_sync.read().await;
            if !self.needs_resync(&guard) {
                return Ok(self.counter.load(Ordering::Acquire));
            }
        }

        let mut guard = self.last_sync.write().await;
        // Double-check after acquiring write lock
        if !self.needs_resync(&guard) {
            return Ok(self.counter.load(Ordering::Acquire));
        }

        // We need to update the counter
        let count = self.active_sessions_count().await?;
        self.counter.store(count, Ordering::Release);
        *guard = Some(Instant::now());
        Ok(count)
    }
}
