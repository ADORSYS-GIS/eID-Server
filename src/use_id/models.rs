use serde::{Deserialize, Serialize};
use yaserde_derive::{YaDeserialize, YaSerialize};
use yaserde::{de::from_str, ser::to_string};

// TR-03130 useID SOAP Request and Response Models

/// SOAP XML Namespaces
pub const NS_EID: &str = "urn:iso:std:iso-iec:24727:tech:schema";
pub const NS_DSS: &str = "urn:oasis:names:tc:dss:1.0:core:schema";
pub const NS_DSSEID: &str = "urn:oasis:names:tc:dss-x:1.0:profiles:eID";
pub const NS_XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";

/// Defines the result status of a request
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
pub struct Result {
    #[yaserde(rename = "ResultMajor")]
    pub result_major: String,

    #[yaserde(rename = "ResultMinor")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_minor: Option<String>,

    #[yaserde(rename = "ResultMessage")]
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
pub struct UseOperations {
    #[yaserde(rename = "UseOperation")]
    pub use_operations: Vec<UseOperation>,
}

/// Single UseOperation item
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
pub struct UseOperation {
    #[yaserde(rename = "id")]
    pub id: String,
}

/// AgeVerificationRequest parameter
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
pub struct AgeVerificationRequest {
    #[yaserde(rename = "AgeToVerify")]
    pub age_to_verify: u8,
}

/// PlaceVerificationRequest parameter
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
pub struct PlaceVerificationRequest {
    #[yaserde(rename = "CommunityIDsToVerify")]
    pub community_ids_to_verify: Vec<String>,
}

/// LevelOfAssuranceRequest parameter
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
pub struct LevelOfAssuranceRequest {
    #[yaserde(rename = "LevelOfAssurance")]
    pub level_of_assurance: String,
}

/// EIDTypeRequest parameter
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
pub struct EIDTypeRequest {
    #[yaserde(rename = "EIDType")]
    pub eid_type: String,
}

/// TransactionInfo parameter
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
pub struct TransactionInfo {
    #[yaserde(text = true)]
    pub value: String,
}

/// TransactionAttestationRequest parameter
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
pub struct TransactionAttestationRequest {
    #[yaserde(rename = "type")]
    pub attestation_type: String,
}

/// PSK parameter
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone, PartialEq)]
pub struct PSK {
    #[yaserde(text = true)]
    pub value: String,
}

/// The useID request structure
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone)]
#[yaserde(rename = "useID")]
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
pub struct Session {
    #[yaserde(rename = "SessionIdentifier")]
    pub session_identifier: String,

    #[yaserde(rename = "Timeout")]
    pub timeout: String,
}

/// The useID response structure
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone)]
#[yaserde(rename = "useIDResponse")]
pub struct UseIDResponse {
    #[yaserde(rename = "Result")]
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
#[yaserde(rename = "Envelope")]
#[yaserde(namespace = "soap: http://schemas.xmlsoap.org/soap/envelope/")]
#[yaserde(prefix = "soap")]
pub struct SoapEnvelope<T>
where
    T: yaserde::YaSerialize + yaserde::YaDeserialize,
{
    #[yaserde(rename = "Body")]
    #[yaserde(prefix = "soap")]
    pub body: SoapBody<T>,
}

/// SOAP Body wrapper
#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, Clone)]
pub struct SoapBody<T>
where
    T: yaserde::YaSerialize + yaserde::YaDeserialize,
{
    #[yaserde(flatten = true)]
    pub content: T,
}

impl<T> SoapEnvelope<T>
where
    T: yaserde::YaSerialize + yaserde::YaDeserialize,
{
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

    // Re-export SoapEnvelope and SoapBody to make them accessible
    pub use super::{SoapEnvelope, SoapBody};

    pub fn deserialize_soap_request<T: yaserde::YaDeserialize + yaserde::YaSerialize>(
        xml: &str,
    ) -> Result<T> {
        let envelope = from_str::<SoapEnvelope<T>>(xml)
            .map_err(|e| anyhow!("XML deserialization error: {}", e))?;
        Ok(envelope.body.content)
    }

    pub fn serialize_soap_response<T: yaserde::YaSerialize + yaserde::YaDeserialize>(
        response: T,
    ) -> Result<String> {
        let envelope = SoapEnvelope::new(response);
        to_string(&envelope).map_err(|e| anyhow!("XML serialization error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_result_success() {
        let result = Result::success();
        assert_eq!(
            result.result_major,
            "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok"
        );
        assert_eq!(result.result_minor, None);
        assert_eq!(result.result_message, None);
    }

    #[test]
    fn test_result_error() {
        let result = Result::error("minor_error", Some("Error message"));
        assert_eq!(
            result.result_major,
            "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error"
        );
        assert_eq!(result.result_minor, Some("minor_error".to_string()));
        assert_eq!(result.result_message, Some("Error message".to_string()));
    }

    #[test]
    fn test_soap_serialization_deserialization() {
        let request = UseIDRequest {
            use_operations: UseOperations {
                use_operations: vec![UseOperation {
                    id: "test_operation".to_string(),
                }],
            },
            age_verification_request: None,
            place_verification_request: None,
            transaction_info: None,
            transaction_attestation_request: None,
            level_of_assurance_request: None,
            eid_type_request: None,
            psk: Some(PSK {
                value: "test_psk".to_string(),
            }),
        };

        let serialized = soap::serialize_soap_response(request.clone()).unwrap();
        let deserialized = soap::deserialize_soap_request::<UseIDRequest>(&serialized).unwrap();

        assert_eq!(
            request.use_operations.use_operations[0].id,
            deserialized.use_operations.use_operations[0].id
        );
        assert_eq!(request.psk.unwrap().value, deserialized.psk.unwrap().value);
    }
}