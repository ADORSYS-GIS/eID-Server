use serde::{Deserialize, Serialize};
use yaserde::{de::from_str, ser::to_string, YaDeserialize, YaSerialize};

// TR-03130 useID SOAP Request and Response Models

/// SOAP XML Namespaces
pub const NS_EID: &str = "urn:iso:std:iso-iec:24727:tech:schema";
pub const NS_DSS: &str = "urn:oasis:names:tc:dss:1.0:core:schema";
pub const NS_DSSEID: &str = "urn:oasis:names:tc:dss-x:1.0:profiles:eID";
pub const NS_XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";

/// Defines the result status of a request
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
#[yaserde(namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
pub struct Result {
    #[yaserde(rename = "ResultMajor")]
    pub result_major: String,

    #[yaserde(rename = "ResultMinor", attribute)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_minor: Option<String>,

    #[yaserde(rename = "ResultMessage", attribute)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_message: Option<String>,
}

impl Result {
    pub fn success() -> Self {
        Self {
            result_major: "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok".to_string(),
            result_minor: None,
            result_message: None,
        }
    }

    pub fn error(minor: &str, message: Option<&str>) -> Self {
        Self {
            result_major: "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error".to_string(),
            result_minor: Some(minor.to_string()),
            result_message: message.map(|s| s.to_string()),
        }
    }

    pub fn warning(minor: &str, message: Option<&str>) -> Self {
        Self {
            result_major: "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#warning".to_string(),
            result_minor: Some(minor.to_string()),
            result_message: message.map(|s| s.to_string()),
        }
    }
}

/// This struct represents the UseOperations parameter in the useID request
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
#[yaserde(namespace = "urn:iso:std:iso-iec:24727:tech:schema")]
pub struct UseOperations {
    #[yaserde(rename = "UseOperation")]
    pub use_operations: Vec<UseOperation>,
}

/// Single UseOperation item
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
#[yaserde(namespace = "urn:iso:std:iso-iec:24727:tech:schema")]
pub struct UseOperation {
    #[yaserde(attribute)]
    pub id: String,
}

/// AgeVerificationRequest parameter
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
#[yaserde(namespace = "urn:iso:std:iso-iec:24727:tech:schema")]
pub struct AgeVerificationRequest {
    #[yaserde(rename = "AgeToVerify")]
    pub age_to_verify: u8,
}

/// PlaceVerificationRequest parameter
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
#[yaserde(namespace = "urn:iso:std:iso-iec:24727:tech:schema")]
pub struct PlaceVerificationRequest {
    #[yaserde(rename = "CommunityIDsToVerify")]
    pub community_ids_to_verify: Vec<String>,
}

/// LevelOfAssuranceRequest parameter
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
#[yaserde(namespace = "urn:iso:std:iso-iec:24727:tech:schema")]
pub struct LevelOfAssuranceRequest {
    #[yaserde(rename = "LevelOfAssurance")]
    pub level_of_assurance: String,
}

/// EIDTypeRequest parameter
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
#[yaserde(namespace = "urn:iso:std:iso-iec:24727:tech:schema")]
pub struct EIDTypeRequest {
    #[yaserde(rename = "EIDType")]
    pub eid_type: String,
}

/// TransactionInfo parameter
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
#[yaserde(namespace = "urn:iso:std:iso-iec:24727:tech:schema")]
pub struct TransactionInfo {
    #[yaserde(text)]
    pub value: String,
}

/// TransactionAttestationRequest parameter
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
#[yaserde(namespace = "urn:iso:std:iso-iec:24727:tech:schema")]
pub struct TransactionAttestationRequest {
    #[yaserde(attribute, rename = "type")]
    pub attestation_type: String,
}

/// PSK parameter
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
#[yaserde(namespace = "urn:iso:std:iso-iec:24727:tech:schema")]
pub struct PSK {
    #[yaserde(text)]
    pub value: String,
}

/// The useID request structure
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone)]
#[yaserde(
    rename = "useID",
    namespace = "urn:iso:std:iso-iec:24727:tech:schema",
    prefix = "iso"
)]
pub struct UseIDRequest {
    #[yaserde(rename = "UseOperations")]
    pub use_operations: UseOperations,

    #[yaserde(rename = "AgeVerificationRequest")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_verification_request: Option<AgeVerificationRequest>,

    #[yaserde(rename = "PlaceVerificationRequest")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub place_verification_request: Option<PlaceVerificationRequest>,

    #[yaserde(rename = "TransactionInfo")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_info: Option<TransactionInfo>,

    #[yaserde(rename = "TransactionAttestationRequest")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_attestation_request: Option<TransactionAttestationRequest>,

    #[yaserde(rename = "LevelOfAssuranceRequest")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level_of_assurance_request: Option<LevelOfAssuranceRequest>,

    #[yaserde(rename = "EIDTypeRequest")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eid_type_request: Option<EIDTypeRequest>,

    #[yaserde(rename = "PSK")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psk: Option<PSK>,
}

/// Session information in the response
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
#[yaserde(namespace = "urn:iso:std:iso-iec:24727:tech:schema")]
pub struct Session {
    #[yaserde(rename = "SessionIdentifier")]
    pub session_identifier: String,

    #[yaserde(rename = "Timeout")]
    pub timeout: String,
}

/// The useID response structure
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone)]
#[yaserde(
    rename = "useIDResponse",
    namespace = "urn:iso:std:iso-iec:24727:tech:schema",
    prefix = "iso"
)]
pub struct UseIDResponse {
    #[yaserde(rename = "Result", prefix = "dss")]
    pub result: Result,

    #[yaserde(rename = "Session")]
    pub session: Session,

    #[yaserde(rename = "eCardServerAddress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecard_server_address: Option<String>,

    #[yaserde(rename = "PSK")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psk: Option<PSK>,
}

/// Used for wrapping requests in a SOAP envelope
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone)]
#[yaserde(
    rename = "Envelope",
    namespace = "http://schemas.xmlsoap.org/soap/envelope/",
    prefix = "soap"
)]
pub struct SoapEnvelope<T> {
    #[yaserde(rename = "Body", prefix = "soap")]
    pub body: SoapBody<T>,
}

/// SOAP Body wrapper
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone)]
#[yaserde(namespace = "http://schemas.xmlsoap.org/soap/envelope/", prefix = "soap")]
pub struct SoapBody<T> {
    #[yaserde(flatten)]
    pub content: T,
}

impl<T> SoapEnvelope<T> {
    pub fn new(content: T) -> Self {
        Self {
            body: SoapBody { content },
        }
    }
}

/// Helper functions for SOAP request/response handling
pub mod soap {
    use super::*;
    use anyhow::{anyhow, Result};

    pub fn deserialize_soap_request<T: YaDeserialize>(xml: &str) -> Result<T> {
        let envelope = from_str::<SoapEnvelope<T>>(xml).map_err(|e| anyhow!("XML deserialization error: {}", e))?;
        Ok(envelope.body.content)
    }

    pub fn serialize_soap_response<T: YaSerialize>(response: T) -> Result<String> {
        let envelope = SoapEnvelope::new(response);
        to_string(&envelope).map_err(|e| anyhow!("XML serialization error: {}", e))
    }
}