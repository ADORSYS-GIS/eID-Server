use thiserror::Error;

/// Errors that can occur during CSCA trust store operations
#[derive(Error, Debug)]
pub enum TrustStoreError {
    #[error("Failed to load trust store: {0}")]
    LoadError(String),

    #[error("Failed to save trust store: {0}")]
    SaveError(String),

    #[error("Master list validation failed: {0}")]
    MasterListValidationError(String),

    #[error("Certificate validation failed: {0}")]
    CertificateValidationError(String),

    #[error("Network error during master list download: {0}")]
    NetworkError(#[from] reqwest::Error),

    #[error("CMS parsing error: {0}")]
    CmsParsingError(String),

    #[error("Certificate parsing error: {0}")]
    CertificateParsingError(String),

    #[error("Trust store is locked for updates")]
    TrustStoreLocked,

    #[error("Rollback failed: {0}")]
    RollbackError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Type alias for Results using TrustStoreError
pub type TrustStoreResult<T> = Result<T, TrustStoreError>;
