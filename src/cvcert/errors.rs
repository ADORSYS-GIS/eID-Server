use openssl::error::ErrorStack;
use rasn::error::{DecodeError, EncodeError};
use thiserror::Error;

/// Error types for CV certificate operations
#[derive(Error, Debug)]
pub enum Error {
    #[error("ASN.1 encoding error: {0}")]
    Asn1Encode(#[from] EncodeError),

    #[error("ASN.1 decoding error: {0}")]
    Asn1Decode(#[from] DecodeError),

    #[error("Hex decoding error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Cryptographic error: {0}")]
    Crypto(#[from] ErrorStack),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Signature verification failed")]
    SignatureError,

    #[error("Unsupported security protocol: {0}")]
    UnsupportedProtocol(String),
}
