use thiserror::Error;

#[derive(Debug, Error)]
pub enum TrustStoreError {
    #[error("Certificate parsing error: {0}")]
    CertificateParsingError(String),
    #[error("Certificate not found: {0}")]
    CertificateNotFound(String),
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}
