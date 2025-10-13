use thiserror::Error;

/// Error type for blacklist operations
#[derive(Debug, Error)]
pub enum BlacklistError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parsing error: {0}")]
    JsonParse(#[from] serde_json::Error),

    #[error("Certificate is blacklisted: {reason}")]
    CertificateBlacklisted { reason: String },

    #[error("Invalid blacklist format: {0}")]
    InvalidFormat(String),

    #[error("Blacklist not loaded")]
    NotLoaded,

    #[error(transparent)]
    Custom(#[from] color_eyre::eyre::Report),
}