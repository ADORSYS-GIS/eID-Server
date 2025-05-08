use quick_xml::{de::from_str, se::to_string};
use serde::{Deserialize, Serialize};

/// Defines the result status of a request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct ResultStatus {
    #[serde(rename = "ResultMajor")]
    pub result_major: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_minor: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_message: Option<String>,
}

impl ResultStatus {
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

/// Single UseOperation item
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct UseOperation {
    #[serde(rename = "@id")]
    pub id: String,
}

/// This struct represents the UseOperations parameter in the useID request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct UseOperations {
    #[serde(rename = "UseOperation", default)]
    pub use_operations: Vec<UseOperation>,
}

/// AgeVerificationRequest parameter
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AgeVerificationRequest {
    #[serde(rename = "AgeToVerify")]
    pub age_to_verify: u8,
}

/// PlaceVerificationRequest parameter
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PlaceVerificationRequest {
    #[serde(rename = "CommunityIDsToVerify")]
    pub community_ids_to_verify: Vec<String>,
}

/// LevelOfAssuranceRequest parameter
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct LevelOfAssuranceRequest {
    #[serde(rename = "LevelOfAssurance")]
    pub level_of_assurance: String,
}

/// EIDTypeRequest parameter
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct EIDTypeRequest {
    #[serde(rename = "EIDType")]
    pub eid_type: String,
}

/// TransactionInfo parameter
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct TransactionInfo {
    #[serde(rename = "$text")]
    pub value: String,
}

/// TransactionAttestationRequest parameter
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct TransactionAttestationRequest {
    #[serde(rename = "@type")]
    pub attestation_type: String,
}

/// PSK parameter
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PSK {
    #[serde(rename = "$text")]
    pub value: String,
}

/// The useID request structure
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename = "useID")]
pub struct UseIDRequest {
    #[serde(rename = "UseOperations")]
    pub use_operations: UseOperations,

    #[serde(
        rename = "AgeVerificationRequest",
        skip_serializing_if = "Option::is_none"
    )]
    pub age_verification_request: Option<AgeVerificationRequest>,

    #[serde(
        rename = "PlaceVerificationRequest",
        skip_serializing_if = "Option::is_none"
    )]
    pub place_verification_request: Option<PlaceVerificationRequest>,

    #[serde(rename = "TransactionInfo", skip_serializing_if = "Option::is_none")]
    pub transaction_info: Option<TransactionInfo>,

    #[serde(
        rename = "TransactionAttestationRequest",
        skip_serializing_if = "Option::is_none"
    )]
    pub transaction_attestation_request: Option<TransactionAttestationRequest>,

    #[serde(
        rename = "LevelOfAssuranceRequest",
        skip_serializing_if = "Option::is_none"
    )]
    pub level_of_assurance_request: Option<LevelOfAssuranceRequest>,

    #[serde(rename = "EIDTypeRequest", skip_serializing_if = "Option::is_none")]
    pub eid_type_request: Option<EIDTypeRequest>,

    #[serde(rename = "PSK", skip_serializing_if = "Option::is_none")]
    pub psk: Option<PSK>,
}

/// Session information in the response
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Session {
    #[serde(rename = "SessionIdentifier")]
    pub session_identifier: String,

    #[serde(rename = "Timeout")]
    pub timeout: String,
}

/// The useID response structure
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename = "useIDResponse")]
pub struct UseIDResponse {
    #[serde(rename = "Result")]
    pub result: ResultStatus,

    #[serde(rename = "Session")]
    pub session: Session,

    #[serde(rename = "eCardServerAddress", skip_serializing_if = "Option::is_none")]
    pub ecard_server_address: Option<String>,

    #[serde(rename = "PSK", skip_serializing_if = "Option::is_none")]
    pub psk: Option<PSK>,
}

/// SOAP Body wrapper
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound(deserialize = "T: serde::de::DeserializeOwned"))]
pub struct SoapBody<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    #[serde(rename = "$value")]
    pub content: T,
}

/// Used for wrapping requests in a SOAP envelope
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename = "Envelope")]
#[serde(bound(deserialize = "T: serde::de::DeserializeOwned"))]
pub struct SoapEnvelope<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    #[serde(rename = "Body")]
    pub body: SoapBody<T>,
}

impl<T> SoapEnvelope<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
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
    use anyhow::{Result, anyhow};

    pub fn deserialize_soap_request<T>(xml: &str) -> Result<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        // Explicitly annotate the type to help the compiler
        let envelope: SoapEnvelope<T> =
            from_str(xml).map_err(|e| anyhow!("XML deserialization error: {}", e))?;
        Ok(envelope.body.content)
    }

    pub fn serialize_soap_response<T>(response: T) -> Result<String>
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let envelope = SoapEnvelope::new(response);
        to_string(&envelope).map_err(|e| anyhow!("XML serialization error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_result_success() {
        let result = ResultStatus::success();
        assert_eq!(
            result.result_major,
            "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok"
        );
        assert_eq!(result.result_minor, None);
        assert_eq!(result.result_message, None);
    }

    #[test]
    fn test_result_error() {
        let result = ResultStatus::error("minor_error", Some("Error message"));
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
