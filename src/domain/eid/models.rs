use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// ServerInfo model according to TR-03130 specification
/// This structure represents the information returned by the getServerInfo endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "ServerInfo")]
pub struct ServerInfo {
    /// The version of the eID-Server implementation
    #[serde(rename = "Version")]
    pub version: String,

    /// The name of the eID-Server implementation
    #[serde(rename(serialize = "Name", deserialize = "Name"))]
    pub name: String,

    /// The server version according to TR-03130 3.6.3
    #[serde(rename = "ServerVersion")]
    pub server_version: String,

    /// Document verification rights according to TR-03130 3.6.3
    #[serde(rename = "DocumentVerificationRights")]
    pub document_verification_rights: DocumentVerificationRights,

    /// The supported API versions
    #[serde(rename = "SupportedAPIVersions")]
    pub supported_api_versions: Vec<String>,

    /// Optional additional information
    #[serde(rename = "AdditionalInfo", skip_serializing_if = "Option::is_none")]
    pub additional_info: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SoapResponse {
    pub body: String,
    pub status: u16,
}

/// Document verification rights information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentVerificationRights {
    /// Whether document verification is supported
    #[serde(rename = "Supported")]
    pub supported: bool,

    /// The version of document verification supported
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Categorization of authentication error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthErrorKind {
    InvalidConnection,
    InvalidCertificate,
    UserCancellation,
    CardCommunicationError,
    AuthenticationFailed,
    CryptoError,
    ProtocolError,
    TimeoutError,
    InternalError,
}

/// Unified authentication error type
#[derive(Debug, Error)]
#[error("{message}")]
pub struct AuthError {
    kind: AuthErrorKind,
    message: String,
}

impl AuthError {
    // Existing methods (unchanged)
    pub fn new(kind: AuthErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn invalid_connection(reason: impl Into<String>) -> Self {
        Self::new(
            AuthErrorKind::InvalidConnection,
            format!("Invalid connection handle: {}", reason.into()),
        )
    }

    pub fn invalid_certificate(details: impl Into<String>) -> Self {
        Self::new(
            AuthErrorKind::InvalidCertificate,
            format!("Certificate validation failed: {}", details.into()),
        )
    }

    pub fn user_cancellation() -> Self {
        Self::new(
            AuthErrorKind::UserCancellation,
            "User cancelled authentication",
        )
    }

    pub fn card_communication_error(reason: impl Into<String>) -> Self {
        Self::new(
            AuthErrorKind::CardCommunicationError,
            format!("Card communication error: {}", reason.into()),
        )
    }

    pub fn authentication_failed(reason: impl Into<String>) -> Self {
        Self::new(
            AuthErrorKind::AuthenticationFailed,
            format!("Authentication failed: {}", reason.into()),
        )
    }

    pub fn crypto_error(operation: impl Into<String>) -> Self {
        Self::new(
            AuthErrorKind::CryptoError,
            format!("Cryptographic operation failed: {}", operation.into()),
        )
    }

    pub fn protocol_error(details: impl Into<String>) -> Self {
        Self::new(
            AuthErrorKind::ProtocolError,
            format!("Protocol violation: {}", details.into()),
        )
    }

    pub fn timeout_error(operation: impl Into<String>) -> Self {
        Self::new(
            AuthErrorKind::TimeoutError,
            format!("Timeout occurred during {}", operation.into()),
        )
    }

    pub fn internal_error(message: impl Into<String>) -> Self {
        Self::new(
            AuthErrorKind::InternalError,
            format!("Internal server error: {}", message.into()),
        )
    }

    pub fn to_result_codes(&self) -> (String, Option<String>) {
        match self.kind {
            AuthErrorKind::UserCancellation => (
                "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error".to_string(),
                Some(
                    "http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#cancellationByUser"
                        .to_string(),
                ),
            ),
            AuthErrorKind::InvalidCertificate => (
                "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error".to_string(),
                Some(
                    "http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#invalidCertificate"
                        .to_string(),
                ),
            ),
            AuthErrorKind::AuthenticationFailed => (
                "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error".to_string(),
                Some(
                    "http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#authenticationFailed"
                        .to_string(),
                ),
            ),
            _ => (
                "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error".to_string(),
                Some(
                    "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#generalError".to_string(),
                ),
            ),
        }
    }

    // New accessor methods
    pub fn kind(&self) -> AuthErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConnectionHandle {
    pub channel_handle: Option<String>,
    pub ifd_name: Option<String>,
    pub slot_index: Option<u32>,
}

impl ConnectionHandle {
    pub fn new(channel_handle: String, ifd_name: String, slot_index: u32) -> Self {
        Self {
            channel_handle: Some(channel_handle),
            ifd_name: Some(ifd_name),
            slot_index: Some(slot_index),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.channel_handle
            .as_ref()
            .is_some_and(|ch| !ch.is_empty())
            && self.ifd_name.as_ref().is_some_and(|ifd| !ifd.is_empty())
            && self.slot_index.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthenticationProtocolData {
    pub certificate_description: String,
    pub required_chat: String,
    pub optional_chat: Option<String>,
    pub transaction_info: Option<String>,
}

impl AuthenticationProtocolData {
    pub fn new(
        certificate_description: String,
        required_chat: String,
        optional_chat: Option<String>,
        transaction_info: Option<String>,
    ) -> Self {
        Self {
            certificate_description,
            required_chat,
            optional_chat,
            transaction_info,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDAuthenticateRequest {
    pub connection_handle: ConnectionHandle,
    pub did_name: String,
    pub authentication_protocol_data: AuthenticationProtocolData,
}

impl DIDAuthenticateRequest {
    pub fn new(
        connection_handle: ConnectionHandle,
        did_name: String,
        authentication_protocol_data: AuthenticationProtocolData,
    ) -> Self {
        Self {
            connection_handle,
            did_name,
            authentication_protocol_data,
        }
    }

    pub fn validate(&self) -> Result<(), AuthError> {
        if !self.connection_handle.is_valid() {
            return Err(AuthError::invalid_connection(
                "Connection handle contains invalid data",
            ));
        }

        if self.did_name.is_empty() {
            return Err(AuthError::protocol_error("DID name cannot be empty"));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseProtocolData {
    pub challenge: Option<String>,
    pub certificate: Option<String>,
    pub personal_data: Option<String>,
    pub authentication_token: Option<String>,
}

impl ResponseProtocolData {
    pub fn new() -> Self {
        Self {
            challenge: None,
            certificate: None,
            personal_data: None,
            authentication_token: None,
        }
    }

    pub fn with_personal_data(mut self, data: String) -> Self {
        self.personal_data = Some(data);
        self
    }

    pub fn with_certificate(mut self, cert: String) -> Self {
        self.certificate = Some(cert);
        self
    }

    pub fn with_authentication_token(mut self, token: String) -> Self {
        self.authentication_token = Some(token);
        self
    }
}

impl Default for ResponseProtocolData {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDAuthenticateResponse {
    pub result_major: String,
    pub result_minor: Option<String>,
    pub authentication_protocol_data: ResponseProtocolData,
    pub timestamp: u64,
}

impl DIDAuthenticateResponse {
    pub fn success(data: ResponseProtocolData) -> Self {
        Self {
            result_major: "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok".to_string(),
            result_minor: None,
            authentication_protocol_data: data,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn error(error: &AuthError) -> Self {
        let (major, minor) = error.to_result_codes();
        Self {
            result_major: major,
            result_minor: minor,
            authentication_protocol_data: ResponseProtocolData::new(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn is_success(&self) -> bool {
        self.result_major.contains("ok")
    }
}

impl Default for ServerInfo {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            name: "eID-Server (SOAP-based Implementation)".to_string(),
            server_version: "1.0".to_string(),
            document_verification_rights: DocumentVerificationRights {
                supported: false,
                version: None,
            },
            supported_api_versions: vec!["1.0".to_string()],
            additional_info: None,
        }
    }
}
