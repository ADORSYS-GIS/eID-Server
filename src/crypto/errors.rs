use openssl::error::ErrorStack;
use thiserror::Error;

/// Error types for cryptographic operations
#[derive(Error, Debug)]
pub enum Error {
    #[error("OpenSSL error: {0}")]
    OpenSSL(#[from] ErrorStack),
}
