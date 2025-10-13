use super::error::BlacklistError;
use super::parser::{load_blacklist_from_file, parse_blacklist_csv, parse_blacklist_json};
use super::types::Blacklist;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Manager for blacklist operations with caching
#[derive(Debug, Clone)]
pub struct BlacklistManager {
    cache: Arc<RwLock<Option<Blacklist>>>,
    file_path: Option<PathBuf>,
}

impl BlacklistManager {
    /// Create a new blacklist manager
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(None)),
            file_path: None,
        }
    }

    /// Create a new blacklist manager with a file path
    pub fn with_file_path<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            cache: Arc::new(RwLock::new(None)),
            file_path: Some(path.into()),
        }
    }

    /// Load blacklist from configured file path
    pub async fn load(&self) -> Result<(), BlacklistError> {
        if let Some(path) = &self.file_path {
            let blacklist = load_blacklist_from_file(path).await?;
            let mut cache = self.cache.write().await;
            *cache = Some(blacklist.clone());
            
            tracing::info!(
                "Blacklist loaded and cached: {} entries from {}",
                blacklist.entries.len(),
                path.display()
            );
            
            Ok(())
        } else {
            Err(BlacklistError::InvalidFormat(
                "No file path configured".to_string(),
            ))
        }
    }

    /// Load blacklist from JSON string
    pub async fn load_from_json(&self, json_content: &str) -> Result<(), BlacklistError> {
        let blacklist = parse_blacklist_json(json_content).await?;
        let mut cache = self.cache.write().await;
        *cache = Some(blacklist.clone());
        
        tracing::info!(
            "Blacklist loaded from JSON and cached: {} entries",
            blacklist.entries.len()
        );
        
        Ok(())
    }

    /// Load blacklist from CSV string
    pub async fn load_from_csv(&self, csv_content: &str) -> Result<(), BlacklistError> {
        let blacklist = parse_blacklist_csv(csv_content).await?;
        let mut cache = self.cache.write().await;
        *cache = Some(blacklist.clone());
        
        tracing::info!(
            "Blacklist loaded from CSV and cached: {} entries",
            blacklist.entries.len()
        );
        
        Ok(())
    }

    /// Set blacklist directly
    pub async fn set_blacklist(&self, blacklist: Blacklist) {
        let mut cache = self.cache.write().await;
        *cache = Some(blacklist);
        tracing::info!("Blacklist set directly in cache");
    }

    /// Get the cached blacklist
    pub async fn get(&self) -> Result<Blacklist, BlacklistError> {
        let cache = self.cache.read().await;
        cache.clone().ok_or(BlacklistError::NotLoaded)
    }

    /// Check if blacklist is loaded
    pub async fn is_loaded(&self) -> bool {
        let cache = self.cache.read().await;
        cache.is_some()
    }

    /// Clear the cached blacklist
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        *cache = None;
        tracing::info!("Blacklist cache cleared");
    }

    /// Reload blacklist from file (if configured)
    pub async fn reload(&self) -> Result<(), BlacklistError> {
        self.clear().await;
        self.load().await
    }

    /// Get the number of entries in the cached blacklist
    pub async fn entry_count(&self) -> usize {
        let cache = self.cache.read().await;
        cache.as_ref().map(|bl| bl.entries.len()).unwrap_or(0)
    }

    /// Check if a certificate serial is blacklisted
    pub async fn is_blacklisted(&self, serial: &[u8], issuer: Option<&str>) -> bool {
        if let Ok(blacklist) = self.get().await {
            blacklist.is_blacklisted(serial, issuer).is_some()
        } else {
            false
        }
    }
}

impl Default for BlacklistManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::{BlacklistEntry, BlacklistReason};

    #[tokio::test]
    async fn test_blacklist_manager_json() {
        let manager = BlacklistManager::new();

        let json = r#"{
            "version": "1.0",
            "last_updated": "2024-01-01T00:00:00Z",
            "entries": [
                {
                    "serial_number": "0123456789abcdef",
                    "reason": "compromised",
                    "date_added": "2024-01-01T00:00:00Z"
                }
            ]
        }"#;

        manager.load_from_json(json).await.unwrap();
        assert!(manager.is_loaded().await);
        assert_eq!(manager.entry_count().await, 1);

        let blacklist = manager.get().await.unwrap();
        assert_eq!(blacklist.entries.len(), 1);
    }

    #[tokio::test]
    async fn test_blacklist_manager_csv() {
        let manager = BlacklistManager::new();

        let csv = "serial_number,issuer,reason,date_added,notes
0123456789abcdef,CN=Test CA,compromised,2024-01-01T00:00:00Z,Test
fedcba9876543210,,fraudulent,2024-01-01T00:00:00Z,";

        manager.load_from_csv(csv).await.unwrap();
        assert!(manager.is_loaded().await);
        assert_eq!(manager.entry_count().await, 2);
    }

    #[tokio::test]
    async fn test_blacklist_manager_is_blacklisted() {
        let manager = BlacklistManager::new();
        
        let mut blacklist = Blacklist::new();
        blacklist.add_entry(BlacklistEntry::new(
            "0123456789abcdef".to_string(),
            BlacklistReason::Compromised,
        ));
        
        manager.set_blacklist(blacklist).await;

        let serial = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert!(manager.is_blacklisted(&serial, None).await);

        let other_serial = vec![0xaa, 0xbb, 0xcc, 0xdd];
        assert!(!manager.is_blacklisted(&other_serial, None).await);
    }

    #[tokio::test]
    async fn test_blacklist_manager_clear() {
        let manager = BlacklistManager::new();
        
        let blacklist = Blacklist::new();
        manager.set_blacklist(blacklist).await;
        assert!(manager.is_loaded().await);

        manager.clear().await;
        assert!(!manager.is_loaded().await);
    }
}