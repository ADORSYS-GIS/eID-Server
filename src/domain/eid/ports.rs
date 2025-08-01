use crate::eid::use_id::model::{UseIDRequest, UseIDResponse};
use async_trait::async_trait;
use color_eyre::Result;

use super::models::{AuthError, DIDAuthenticateRequest, DIDAuthenticateResponse, ServerInfo};

#[async_trait]
pub trait EIDService: Clone + Send + Sync + 'static {
    async fn handle_use_id(&self, request: UseIDRequest) -> Result<UseIDResponse>;
}

#[async_trait]
pub trait DIDAuthenticate {
    async fn handle_did_authenticate(
        &self,
        request: DIDAuthenticateRequest,
    ) -> Result<DIDAuthenticateResponse, AuthError>;
}

pub trait EidService: Clone + Send + Sync + 'static {
    /// Returns information about the eID-Server
    fn get_server_info(&self) -> ServerInfo;
}

/// Result type for transmit operations
pub type TransmitResult<T> = Result<T, TransmitError>;

/// Errors that can occur during transmit operations
#[derive(Debug, thiserror::Error)]
pub enum TransmitError {
    #[error("Transmit error: {0}")]
    TransmitError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<quick_xml::Error> for TransmitError {
    fn from(err: quick_xml::Error) -> Self {
        TransmitError::TransmitError(format!("XML error: {err}"))
    }
}

impl From<std::io::Error> for TransmitError {
    fn from(err: std::io::Error) -> Self {
        TransmitError::InternalError(format!("IO error: {err}"))
    }
}

impl From<std::str::Utf8Error> for TransmitError {
    fn from(err: std::str::Utf8Error) -> Self {
        TransmitError::TransmitError(format!("Invalid UTF-8 in request: {err}"))
    }
}

/// Service interface for APDU transmission
/// This abstracts the external dependencies and provides a clean domain interface
#[async_trait]
pub trait TransmitService: Send + Sync {
    /// Transmits an APDU to the eID-Client and returns the response
    ///
    /// # Arguments
    /// * `apdu` - The APDU bytes to transmit
    /// * `slot_handle` - The slot handle for the session
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The response APDU bytes
    /// * `Err(TransmitError)` - If transmission fails
    async fn transmit_apdu(&self, apdu: Vec<u8>, slot_handle: &str) -> TransmitResult<Vec<u8>>;
}
