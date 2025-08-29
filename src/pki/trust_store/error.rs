use thiserror::Error;

#[derive(Debug, Error)]
pub enum TrustStoreError {
    #[error("Certificate parsing error: {0}")]
    CertificateParsingError(#[from] x509_parser::error::X509Error),
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Certificate not found: {0}")]
    CertificateNotFound(String),
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),
    #[error("Update failed: {0}")]
    UpdateError(String),
    #[error("Other error: {0}")]
    Other(String),
}