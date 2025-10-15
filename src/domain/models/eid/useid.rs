use crate::domain::models::{
    ResultType,
    eid::{LevelOfAssurance, Operations, Session},
};
use bincode::{Decode, Encode};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use validator::Validate;

static COMM_ID_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^0[0-9]{3}([0-9]{2}(0[0-9]([0-9]{2}(0[0-9]{3})?)?)?)?$").unwrap());

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, Decode, Encode)]
pub enum AttrRequest {
    ALLOWED,
    #[default]
    PROHIBITED,
    REQUIRED,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, Decode, Encode)]
pub struct AttributeReq {
    #[serde(rename = "$text", default)]
    pub value: AttrRequest,
}

impl AttributeReq {
    pub fn is_required(&self) -> bool {
        matches!(self.value, AttrRequest::REQUIRED)
    }

    pub fn is_allowed(&self) -> bool {
        matches!(self.value, AttrRequest::ALLOWED)
    }

    pub fn is_prohibited(&self) -> bool {
        matches!(self.value, AttrRequest::PROHIBITED)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate, Decode, Encode)]
pub struct AgeVerifReq {
    #[serde(rename = "Age")]
    #[validate(range(min = 0, max = 150))]
    pub age: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate, Decode, Encode)]
pub struct PlaceVerifReq {
    #[serde(rename = "CommunityID")]
    #[validate(regex(path = *COMM_ID_REGEX))]
    pub community_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate, Decode, Encode)]
pub struct TransactionAttestReq {
    #[serde(rename = "TransactionAttestationFormat")]
    #[validate(url)]
    pub trans_attest_format: String,
    #[serde(rename = "TransactionContext")]
    #[validate(length(min = 1))]
    pub transaction_context: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Decode, Encode)]
pub enum EIDTypeSelection {
    ALLOWED,
    DENIED,
}

impl EIDTypeSelection {
    pub fn is_allowed(&self) -> bool {
        matches!(self, EIDTypeSelection::ALLOWED)
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, EIDTypeSelection::DENIED)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Decode, Encode)]
pub struct EIDTypeReq {
    #[serde(rename = "CardCertified")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_certified: Option<EIDTypeSelection>,
    #[serde(rename = "SECertified")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub se_certified: Option<EIDTypeSelection>,
    #[serde(rename = "SEEndorsed")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub se_endorsed: Option<EIDTypeSelection>,
    #[serde(rename = "HWKeyStore")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hw_key_store: Option<EIDTypeSelection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate, Decode, Encode)]
pub struct PreSharedKey {
    #[serde(rename(deserialize = "ID", serialize = "eid:ID"))]
    #[validate(length(min = 16))]
    pub id: String,
    #[serde(rename(deserialize = "Key", serialize = "eid:Key"))]
    #[validate(length(min = 16))]
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate, Decode, Encode)]
#[serde(rename_all = "PascalCase")]
pub struct UseIDRequest {
    pub use_operations: Operations<AttributeReq>,
    #[serde(rename = "AgeVerificationRequest")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub age_verification: Option<AgeVerifReq>,
    #[serde(rename = "PlaceVerificationRequest")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub place_verification: Option<PlaceVerifReq>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_info: Option<String>,
    #[serde(rename = "TransactionAttestationRequest")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub transaction_attestation: Option<TransactionAttestReq>,
    #[serde(rename = "LevelOfAssuranceRequest")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level_of_assurance: Option<LevelOfAssurance>,
    #[serde(rename = "EIDTypeRequest")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eid_type: Option<EIDTypeReq>,
    #[serde(rename(deserialize = "PSK", serialize = "eid:PSK"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub psk: Option<PreSharedKey>,
}

#[derive(Debug, Serialize, Validate)]
pub struct UseIDResponse {
    #[serde(rename = "eid:Session")]
    #[validate(nested)]
    pub session: Session,
    #[serde(rename = "eid:eCardServerAddress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e_card_address: Option<String>,
    #[serde(rename = "eid:PSK")]
    #[validate(nested)]
    pub psk: PreSharedKey,
    #[serde(rename = "dss:Result")]
    pub result: ResultType,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soap::Envelope;

    #[derive(Debug, Serialize, Validate)]
    struct UseIDResp {
        #[serde(rename = "eid:useIDResponse")]
        #[validate(nested)]
        value: UseIDResponse,
    }

    #[test]
    fn test_use_id_request() {
        let request_xml = include_str!("../../../../test_data/eid/useIDRequest.xml");
        let result = Envelope::<UseIDRequest>::parse(request_xml);
        assert!(
            result.is_ok(),
            "Failed to parse XML: {:?}",
            result.unwrap_err()
        );
        let request = result.unwrap();
        assert!(request.body().validate().is_ok());
        #[rustfmt::skip]
        assert!(request.body().use_operations.document_type.as_ref().unwrap().is_required());
        #[rustfmt::skip]
        assert!(request.body().use_operations.academic_title.as_ref().unwrap().is_allowed());
        #[rustfmt::skip]
        assert!(request.body().use_operations.community_id.as_ref().unwrap().is_prohibited());
        #[rustfmt::skip]
        assert_eq!(request.body().age_verification.as_ref().unwrap().age, 18);
        #[rustfmt::skip]
        assert_eq!(request.body().place_verification.as_ref().unwrap().community_id, "027605");
        #[rustfmt::skip]
        assert_eq!(request.body().level_of_assurance.unwrap(), LevelOfAssurance::BsiHoch);
    }

    #[test]
    fn test_use_id_response() {
        let use_id_response = UseIDResp {
            value: UseIDResponse {
                session: Session {
                    id: "12345678901234567890123456789012".to_string(),
                },
                e_card_address: None,
                psk: PreSharedKey {
                    id: "12345678901234567890123456789012".to_string(),
                    key: "12345678901234567890123456789012".to_string(),
                },
                result: ResultType::ok(),
            },
        };
        assert!(use_id_response.validate().is_ok());

        let result = Envelope::new(use_id_response).serialize_soap(true);
        assert!(result.is_ok());
        let xml = result.unwrap();

        assert!(xml.contains("<eid:useIDResponse>"));
        assert!(xml.contains("<eid:Session>"));
        assert!(xml.contains("<eid:PSK>"));
        assert!(xml.contains("<dss:Result>"));
        assert!(xml.contains("http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok"));
    }

    #[test]
    fn test_use_id_fails_session_id_too_short() {
        let use_id_response = UseIDResp {
            value: UseIDResponse {
                session: Session {
                    id: "1234567890123456".to_string(),
                },
                e_card_address: None,
                psk: PreSharedKey {
                    id: "12345678901234567890123456789012".to_string(),
                    key: "12345678901234567890123456789012".to_string(),
                },
                result: ResultType::ok(),
            },
        };
        // validate should fail because session id is too short (min length is 32)
        assert!(use_id_response.validate().is_err());
    }
}
