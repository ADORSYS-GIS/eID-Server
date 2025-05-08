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

/// SOAP Namespaces
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SoapNamespaces {
    #[serde(rename = "@xmlns:soap")]
    pub soap: String,
    
    #[serde(rename = "@xmlns:xsi")]
    pub xsi: String,
    
    #[serde(rename = "@xmlns:xsd")]
    pub xsd: String,
}

/// SOAP Body wrapper
#[derive(Debug, Clone)]
pub struct SoapBody<T> {
    pub content: T,
}

// Separate implementation of Serialize for SoapBody
impl<T> Serialize for SoapBody<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Helper<'a, T> {
            #[serde(rename = "$value")]
            content: &'a T,
        }

        Helper {
            content: &self.content,
        }
        .serialize(serializer)
    }
}

// Separate implementation of Deserialize for SoapBody
impl<'de, T> Deserialize<'de> for SoapBody<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper<T> {
            #[serde(rename = "$value")]
            content: T,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(SoapBody {
            content: helper.content,
        })
    }
}

/// Used for wrapping requests in a SOAP envelope
#[derive(Debug, Clone)]
pub struct SoapEnvelope<T> {
    pub namespaces: SoapNamespaces,
    pub body: SoapBody<T>,
}

// Separate implementation of Serialize for SoapEnvelope
impl<T> Serialize for SoapEnvelope<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename = "soap:Envelope")]
        struct Helper<'a, T> {
            #[serde(flatten)]
            namespaces: &'a SoapNamespaces,
            
            #[serde(rename = "soap:Body")]
            body: &'a SoapBody<T>,
        }

        Helper {
            namespaces: &self.namespaces,
            body: &self.body,
        }
        .serialize(serializer)
    }
}

// Separate implementation of Deserialize for SoapEnvelope
impl<'de, T> Deserialize<'de> for SoapEnvelope<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename = "soap:Envelope")]
        struct Helper<T> {
            #[serde(flatten)]
            namespaces: SoapNamespaces,
            
            #[serde(rename = "soap:Body")]
            body: SoapBody<T>,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(SoapEnvelope {
            namespaces: helper.namespaces,
            body: helper.body,
        })
    }
}

/// Used for deserializing useID requests
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UseIDRequestWrapper {
    #[serde(rename = "useID")]
    pub use_id: UseIDRequest,
}

/// Used for serializing useID responses
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UseIDResponseWrapper {
    #[serde(rename = "useIDResponse")]
    pub use_id_response: UseIDResponse,
}

impl<T> SoapEnvelope<T> {
    pub fn new(content: T) -> Self {
        Self {
            namespaces: SoapNamespaces {
                soap: "http://schemas.xmlsoap.org/soap/envelope/".to_string(),
                xsi: "http://www.w3.org/2001/XMLSchema-instance".to_string(),
                xsd: "http://www.w3.org/2001/XMLSchema".to_string(),
            },
            body: SoapBody { content },
        }
    }
}

/// Helper functions for SOAP request/response handling
pub mod soap {
    use super::*;
    use anyhow::{Result, anyhow};

    pub fn deserialize_soap_request(xml: &str) -> Result<UseIDRequest> {
        // Parse the XML into a SOAP envelope containing the useID request wrapper
        let envelope: SoapEnvelope<UseIDRequestWrapper> = 
            from_str(xml).map_err(|e| anyhow!("XML deserialization error: {}", e))?;
        
        // Return the actual useID request
        Ok(envelope.body.content.use_id)
    }

    pub fn serialize_soap_response(response: UseIDResponse) -> Result<String> {
        // Create a wrapper for the useID response
        let wrapper = UseIDResponseWrapper {
            use_id_response: response,
        };
        
        // Create a SOAP envelope containing the useID response wrapper
        let envelope = SoapEnvelope::new(wrapper);
        
        // Add XML declaration and serialize
        let xml = to_string(&envelope).map_err(|e| anyhow!("XML serialization error: {}", e))?;
        Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", xml))
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
        // Create a sample useID request
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

        // Test serialization of the request as part of a SOAP request
        let wrapper = UseIDRequestWrapper { use_id: request.clone() };
        let envelope = SoapEnvelope::new(wrapper);
        let xml = to_string(&envelope).unwrap();
        assert!(xml.contains("test_operation"));
        assert!(xml.contains("test_psk"));

        // Create a SOAP XML request
        let soap_xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><soap:Body><useID><UseOperations><UseOperation id=\"test_operation\"/></UseOperations><PSK>test_psk</PSK></useID></soap:Body></soap:Envelope>"
        );

        // Test deserialization of the SOAP request
        let deserialized = soap::deserialize_soap_request(&soap_xml).unwrap();
        assert_eq!(
            deserialized.use_operations.use_operations[0].id,
            "test_operation"
        );
        assert_eq!(deserialized.psk.unwrap().value, "test_psk");

        // Create a sample useID response
        let response = UseIDResponse {
            result: ResultStatus::success(),
            session: Session {
                session_identifier: "session123".to_string(),
                timeout: "2025-05-08T12:58:12Z".to_string(),
            },
            ecard_server_address: Some("https://ecard.example.com".to_string()),
            psk: Some(PSK {
                value: "response_psk".to_string(),
            }),
        };

        // Test serialization of the response as part of a SOAP response
        let soap_response = soap::serialize_soap_response(response).unwrap();
        assert!(soap_response.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(soap_response.contains("session123"));
        assert!(soap_response.contains("response_psk"));
        assert!(soap_response.contains("https://ecard.example.com"));
    }
}
