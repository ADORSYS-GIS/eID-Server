use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignedObjectError {
    #[error("CMS/PKI error: {0}")]
    Pki(String),

    #[error("Invalid input: {0}")]
    Invalid(String),

    #[error("Certificate path validation failed: {0}")]
    Path(String),

    #[error("Untrusted signer")]
    UntrustedSigner,

    #[error("Tampered or invalid signature")]
    BadSignature,
}

