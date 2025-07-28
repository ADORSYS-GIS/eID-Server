use crate::tls::psk::PskStoreError;
use crate::tls::session::SessionStoreError;
use openssl::error::ErrorStack;
use thiserror::Error;

/// Errors that can occur during TLS operations.
#[derive(Error, Debug)]
pub enum TlsError {
    #[error(transparent)]
    PskStore(#[from] PskStoreError),

    #[error(transparent)]
    OpenSSL(#[from] ErrorStack),

    #[error(transparent)]
    SessionStore(#[from] SessionStoreError),
}
