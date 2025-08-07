use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf};

/// Represents a CSCA certificate with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CscaCertificate {
    /// The X.509 certificate in DER format
    pub certificate_der: Vec<u8>,
    /// Country code that issued this certificate
    pub country_code: String,
    /// Certificate serial number
    pub serial_number: String,
    /// Certificate subject
    pub subject: String,
    /// Certificate issuer
    pub issuer: String,
    /// Not valid before timestamp
    pub not_before: DateTime<Utc>,
    /// Not valid after timestamp
    pub not_after: DateTime<Utc>,
    /// When this certificate was added to the trust store
    pub added_at: DateTime<Utc>,
    /// Source of this certificate (master_list, link_certificate, manual)
    pub source: CertificateSource,
}

/// Source of a CSCA certificate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CertificateSource {
    MasterList {
        url: String,
        downloaded_at: DateTime<Utc>,
    },
    LinkCertificate {
        parent_serial: String,
    },
    Manual {
        operator: String,
    },
}

/// Master List information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterListInfo {
    /// URL where the master list was downloaded from
    pub url: String,
    /// When the master list was last downloaded
    pub last_downloaded: DateTime<Utc>,
    /// ETag or similar identifier for caching
    pub etag: Option<String>,
    /// Hash of the master list content for integrity checking
    pub content_hash: String,
    /// Number of certificates in this master list
    pub certificate_count: usize,
}

/// Trust store configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustStoreConfig {
    /// Path to the trust store file
    pub store_path: PathBuf,
    /// Backup directory for rollback protection
    pub backup_dir: PathBuf,
    /// Master list URLs to download from
    pub master_list_urls: Vec<String>,
    /// How often to refresh master lists (in seconds)
    pub refresh_interval_seconds: u64,
    /// Maximum age of certificates to keep (in days)
    pub max_certificate_age_days: u32,
    /// Whether to automatically remove expired certificates
    pub auto_remove_expired: bool,
    /// HTTP timeout for master list downloads (in seconds)
    pub download_timeout_seconds: u64,
}

impl Default for TrustStoreConfig {
    fn default() -> Self {
        Self {
            store_path: PathBuf::from("trust_store.json"),
            backup_dir: PathBuf::from("trust_store_backups"),
            master_list_urls: Vec::new(),
            refresh_interval_seconds: 24 * 60 * 60, // 24 hours
            max_certificate_age_days: 365 * 5,      // 5 years
            auto_remove_expired: true,
            download_timeout_seconds: 30,
        }
    }
}

/// In-memory representation of the trust store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustStoreData {
    /// Map of certificate serial number to certificate
    pub certificates: HashMap<String, CscaCertificate>,
    /// Information about master lists
    pub master_lists: HashMap<String, MasterListInfo>,
    /// When the trust store was last updated
    pub last_updated: DateTime<Utc>,
    /// Version number for atomic updates
    pub version: u64,
}

impl Default for TrustStoreData {
    fn default() -> Self {
        Self {
            certificates: HashMap::new(),
            master_lists: HashMap::new(),
            last_updated: Utc::now(),
            version: 1,
        }
    }
}
