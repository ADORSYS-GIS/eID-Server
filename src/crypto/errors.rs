use openssl::error::ErrorStack;
use thiserror::Error;

pub(crate) type CryptoResult<T> = Result<T, Error>;

/// Error type for cryptographic operations
#[derive(Error, Debug)]
pub enum Error {
    /// Invalid data format or corrupted data
    #[error("Invalid data: {0}")]
    Invalid(String),

    /// Unsupported curve or algorithm
    #[error("Unsupported curve: {0}")]
    UnsupportedCurve(String),

    /// Internal OpenSSL error
    #[error("OpenSSL error: {0}")]
    OpenSsl(#[from] ErrorStack),

    /// Encoding/decoding error
    #[error("Encoding error: {0}")]
    HexDecode(#[from] hex::FromHexError),
}
