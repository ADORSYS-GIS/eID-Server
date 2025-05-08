//! Canonical data structures comprising the domain.

use serde::{Deserialize, Serialize};

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
