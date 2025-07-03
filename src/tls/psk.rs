//! src/tls/psk.rs

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use rustls::server::{StoresPsk, PskContainer, PskIdentity};
use tracing::info;

/// A thread-safe, in-memory store for Pre-Shared Keys, mapping session IDs to their keys.
/// The session ID is used as the PSK identity by the eID client.
#[derive(Debug, Clone, Default)]
pub struct PskStore(Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>);

impl PskStore {
    /// Creates a new, empty PSK store.
    pub fn new() -> Self { 
        Self::default()
    }

    /// Inserts a PSK into the store, keyed by its identity (session ID).
    pub fn insert(&self, identity: String, key: Vec<u8>) {
        info!("Storing PSK for session ID: {}", identity);
        self.0
            .lock()
            .unwrap()
            .insert(identity.into_bytes(), key);
    }
}

/// Implements the `StoresPsk` trait for `rustls` to look up PSKs.
///
/// This struct is the bridge between `rustls` and our application's `PskStore`.
#[derive(Debug, Clone)]
pub struct ServerPskStorage {
    store: PskStore,
}

impl ServerPskStorage {
    pub fn new(store: PskStore) -> Arc<Self> {
        Arc::new(Self { store })
    }
}

impl StoresPsk for ServerPskStorage {
    /// `rustls` calls this method during the handshake to retrieve the PSK for the given identity.
    fn get_key(&self, identity: PskIdentity<'_>) -> Option<PskContainer> {
        let identity_str = String::from_utf8_lossy(identity.as_ref());
        info!(
            "TLS-PSK handshake: Looking up PSK for client identity: {}",
            identity_str
        );

        let store_lock = self.store.0.lock().unwrap();

        // Find the key in the store and wrap it in `PskContainer`.
        store_lock
            .get(identity.as_ref())
            .map(|key| PskContainer::new(key.clone()))
    }
}
