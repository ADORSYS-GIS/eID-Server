use thiserror::Error;
use x509_parser::prelude::X509Error;

use crate::pki::truststore::TrustStoreError;

/// CRL-related errors
#[derive(Error, Debug)]
pub enum CrlError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("CRL parsing failed: {0}")]
    Parse(#[from] X509Error),

    #[error("Trust store error: {0}")]
    TrustStore(#[from] TrustStoreError),

    #[error("CRL validation failed: {0}")]
    Validation(String),

    #[error("CRL distribution point not found in certificate")]
    NoDistributionPoint,

    #[error("CRL signature verification failed")]
    SignatureVerification,

    #[error("CRL is expired")]
    Expired,

    #[error("Timeout while fetching CRL")]
    Timeout,

    #[error("Issuer not authorized for CRL signing")]
    UnauthorizedIssuer,

    #[error("Invalid CRL URL: {0}")]
    InvalidUrl(String),

    #[error("Custom error: {0}")]
    Custom(String),
}

/// Convenient Result type alias
pub type CrlResult<T> = Result<T, CrlError>;
