use super::error::DefectListError;
use super::parser::{load_defect_list_from_file, parse_defect_list_xml};
use super::types::DefectList;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::pki::defect_list::{DefectEntry, DefectType};

/// Manager for defect list operations with caching
#[derive(Debug, Clone)]
pub struct DefectListManager {
    cache: Arc<RwLock<Option<DefectList>>>,
    file_path: Option<PathBuf>,
}

impl DefectListManager {
    /// Create a new defect list manager
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(None)),
            file_path: None,
        }
    }

    /// Create a new defect list manager with a file path
    pub fn with_file_path<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            cache: Arc::new(RwLock::new(None)),
            file_path: Some(path.into()),
        }
    }

    /// Load defect list from configured file path (XML format)
    pub async fn load(&self) -> Result<(), DefectListError> {
        if let Some(path) = &self.file_path {
            let defect_list = load_defect_list_from_file(path).await?;
            let mut cache = self.cache.write().await;
            *cache = Some(defect_list.clone());

            tracing::info!(
                "Defect list loaded and cached: {} entries from {}",
                defect_list.entries.len(),
                path.display()
            );

            Ok(())
        } else {
            Err(DefectListError::InvalidFormat(
                "No file path configured".to_string(),
            ))
        }
    }

    /// Load defect list from XML string
    pub async fn load_from_xml(&self, xml_content: &str) -> Result<(), DefectListError> {
        let defect_list = parse_defect_list_xml(xml_content).await?;
        let mut cache = self.cache.write().await;
        *cache = Some(defect_list.clone());

        tracing::info!(
            "Defect list loaded from XML and cached: {} entries",
            defect_list.entries.len()
        );

        Ok(())
    }

    /// Set defect list directly
    pub async fn set_defect_list(&self, defect_list: DefectList) {
        let mut cache = self.cache.write().await;
        *cache = Some(defect_list);
        tracing::info!("Defect list set directly in cache");
    }

    /// Get the cached defect list
    pub async fn get(&self) -> Result<DefectList, DefectListError> {
        let cache = self.cache.read().await;
        cache.clone().ok_or(DefectListError::NotLoaded)
    }

    /// Check if defect list is loaded
    pub async fn is_loaded(&self) -> bool {
        let cache = self.cache.read().await;
        cache.is_some()
    }

    /// Clear the cached defect list
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        *cache = None;
        tracing::info!("Defect list cache cleared");
    }

    /// Reload defect list from file (if configured)
    pub async fn reload(&self) -> Result<(), DefectListError> {
        self.clear().await;
        self.load().await
    }

    /// Get the number of entries in the cached defect list
    pub async fn entry_count(&self) -> usize {
        let cache = self.cache.read().await;
        cache.as_ref().map(|dl| dl.entries.len()).unwrap_or(0)
    }

    /// Check if a document has defects
    pub async fn has_defects(&self, serial: &[u8], issuer: Option<&str>) -> bool {
        if let Ok(defect_list) = self.get().await {
            defect_list.has_defects(Some(serial), issuer).is_some()
        } else {
            false
        }
    }

    /// Get defect count by severity
    pub async fn count_by_severity(&self, min_severity: u8) -> usize {
        if let Ok(defect_list) = self.get().await {
            defect_list.get_by_severity(min_severity).len()
        } else {
            0
        }
    }
}

impl Default for DefectListManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_defect_list_manager_xml() {
        let manager = DefectListManager::new();

        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<DefectList>
    <version>1.0</version>
    <last_updated>2024-01-01T00:00:00Z</last_updated>
    <entries>
        <DefectEntry>
            <document_number>DOC123</document_number>
            <serial_number>0123456789abcdef</serial_number>
            <defect_type>manufacturing</defect_type>
            <date_discovered>2024-01-01T00:00:00Z</date_discovered>
            <severity>4</severity>
        </DefectEntry>
    </entries>
</DefectList>"#;

        manager.load_from_xml(xml).await.unwrap();
        assert!(manager.is_loaded().await);
        assert_eq!(manager.entry_count().await, 1);

        let defect_list = manager.get().await.unwrap();
        assert_eq!(defect_list.entries.len(), 1);
    }

    #[tokio::test]
    async fn test_defect_list_manager_has_defects() {
        let manager = DefectListManager::new();

        let mut defect_list = DefectList::new();
        defect_list.add_entry(DefectEntry::with_serial(
            "DOC123".to_string(),
            "0123456789abcdef".to_string(),
            DefectType::CryptographicWeakness,
        ));

        manager.set_defect_list(defect_list).await;

        let serial = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert!(manager.has_defects(&serial, None).await);

        let other_serial = vec![0xaa, 0xbb, 0xcc, 0xdd];
        assert!(!manager.has_defects(&other_serial, None).await);
    }

    #[tokio::test]
    async fn test_defect_list_manager_severity_count() {
        let manager = DefectListManager::new();

        let mut defect_list = DefectList::new();
        defect_list.add_entry(
            DefectEntry::new("DOC1".to_string(), DefectType::Manufacturing).with_severity(3),
        );
        defect_list.add_entry(
            DefectEntry::new("DOC2".to_string(), DefectType::InvalidSignature).with_severity(5),
        );

        manager.set_defect_list(defect_list).await;

        assert_eq!(manager.count_by_severity(1).await, 2);
        assert_eq!(manager.count_by_severity(4).await, 1);
        assert_eq!(manager.count_by_severity(5).await, 1);
    }

    #[tokio::test]
    async fn test_defect_list_manager_clear() {
        let manager = DefectListManager::new();

        let defect_list = DefectList::new();
        manager.set_defect_list(defect_list).await;
        assert!(manager.is_loaded().await);

        manager.clear().await;
        assert!(!manager.is_loaded().await);
    }
}