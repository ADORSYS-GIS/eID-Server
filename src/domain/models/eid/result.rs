use crate::domain::models::{
    ResultType,
    eid::{LevelOfAssurance, Operations, Session},
};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use validator::Validate;

static DOC_TYPE_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Z ]{2}$").unwrap());
static ICAO_COUNTRY_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Z ]{1,3}$").unwrap());
static GENERAL_DATE_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9 ]{8}$").unwrap());

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct GeneralDate {
    #[serde(rename = "eid:DateString")]
    #[validate(regex(path = *GENERAL_DATE_REGEX))]
    pub date_string: String,
    #[serde(rename = "eid:DateValue")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct Place {
    #[serde(rename = "eid:Street")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street: Option<String>,
    #[serde(rename = "eid:City")]
    #[validate(length(min = 1))]
    pub city: String,
    #[serde(rename = "eid:State")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(rename = "eid:Country")]
    #[validate(regex(path = *ICAO_COUNTRY_REGEX))]
    pub country: String,
    #[serde(rename = "eid:ZipCode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct GeneralPlace {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "eid:StructuredPlace")]
    pub structured_place: Option<Place>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "eid:FreetextPlace")]
    pub freetext_place: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "eid:NoPlaceInfo")]
    pub no_place_info: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RestrictedID {
    #[serde(rename = "eid:ID")]
    #[validate(length(min = 1))]
    pub id: String,
    #[serde(rename = "eid:ID2")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id2: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, Validate)]
pub struct PersonalData {
    #[serde(rename = "eid:DocumentType")]
    #[validate(regex(path = *DOC_TYPE_REGEX))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_type: Option<String>,
    #[serde(rename = "eid:IssuingState")]
    #[validate(regex(path = *ICAO_COUNTRY_REGEX))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuing_state: Option<String>,
    #[serde(rename = "eid:DateOfExpiry")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_of_expiry: Option<String>,
    #[serde(rename = "eid:GivenNames")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_names: Option<String>,
    #[serde(rename = "eid:FamilyNames")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_names: Option<String>,
    #[serde(rename = "eid:ArtisticName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artistic_name: Option<String>,
    #[serde(rename = "eid:AcademicTitle")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub academic_title: Option<String>,
    #[serde(rename = "eid:DateOfBirth")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_of_birth: Option<GeneralDate>,
    #[serde(rename = "eid:PlaceOfBirth")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub place_of_birth: Option<GeneralPlace>,
    #[serde(rename = "eid:Nationality")]
    #[validate(regex(path = *ICAO_COUNTRY_REGEX))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nationality: Option<String>,
    #[serde(rename = "eid:BirthName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birth_name: Option<String>,
    #[serde(rename = "eid:PlaceOfResidence")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub place_of_residence: Option<GeneralPlace>,
    #[serde(rename = "eid:CommunityID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub community_id: Option<String>,
    #[serde(rename = "eid:ResidencePermitI")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub residence_permit_i: Option<String>,
    #[serde(rename = "eid:RestrictedID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restricted_id: Option<RestrictedID>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationResult {
    #[serde(rename = "eid:FulfilsRequest")]
    pub fulfils_request: bool,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum AttrResponse {
    NOTONCHIP,
    ALLOWED,
    #[default]
    PROHIBITED,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributeResp {
    #[serde(rename = "$text", default)]
    pub value: AttrResponse,
}

impl AttributeResp {
    pub fn value(attr: AttrResponse) -> Self {
        Self { value: attr }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionAttestResp {
    #[serde(rename = "eid:TransactionAttestationFormat")]
    pub trans_attest_format: String,
    #[serde(rename = "eid:TransactionAttestationData")]
    pub transaction_data: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EIDTypeUsed {
    USED,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EIDTypeResp {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "eid:CardCertified")]
    pub card_certified: Option<EIDTypeUsed>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "eid:SECertified")]
    pub se_certified: Option<EIDTypeUsed>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "eid:SEEndorsed")]
    pub se_endorsed: Option<EIDTypeUsed>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "eid:HWKeyStore")]
    pub hw_key_store: Option<EIDTypeUsed>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Validate)]
#[serde(rename_all = "PascalCase")]
pub struct GetResultRequest {
    #[validate(nested)]
    pub session: Session,
    pub request_counter: u32,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
#[serde(rename = "getResultResponse")]
pub struct GetResultResponse {
    #[serde(rename = "eid:PersonalData")]
    #[validate(nested)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub personal_data: Option<PersonalData>,
    #[serde(rename = "eid:FulfilsAgeVerification")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfils_age: Option<VerificationResult>,
    #[serde(rename = "eid:FulfilsPlaceVerification")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfils_place: Option<VerificationResult>,
    #[serde(rename = "eid:OperationsAllowedByUser")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ops_allowed: Option<Operations<AttributeResp>>,
    #[serde(rename = "eid:TransactionAttestationResponse")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trans_attest_resp: Option<TransactionAttestResp>,
    #[serde(rename = "eid:LevelOfAssuranceResult")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level_of_assurance: Option<LevelOfAssurance>,
    #[serde(rename = "eid:EIDTypeResponse")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eid_type_resp: Option<EIDTypeResp>,
    #[serde(rename = "dss:Result")]
    pub result: ResultType,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soap::Envelope;

    #[derive(Debug, Serialize, Deserialize)]
    struct GetResultResp {
        #[serde(rename = "eid:getResultResponse")]
        value: GetResultResponse,
    }

    #[test]
    fn test_get_result_request_parsing() {
        let req = include_str!("../../../../test_data/eid/getResultRequest.xml");
        let result = Envelope::<GetResultRequest>::parse(req);
        assert!(result.is_ok());

        let request = result.unwrap();
        assert!(request.body().validate().is_ok());
        assert_eq!(
            request.body().session.id,
            "1234567890abcdef1234567890abcdef"
        );
        assert_eq!(request.body().request_counter, 1);
    }

    #[test]
    fn test_get_result_response_serialization() {
        let response = GetResultResp {
            value: GetResultResponse {
                personal_data: Some(PersonalData {
                    document_type: Some("ID".to_string()),
                    issuing_state: Some("D".to_string()),
                    date_of_expiry: Some("2029-10-31".to_string()),
                    given_names: Some("ERIKA".to_string()),
                    family_names: Some("MUSTERMANN".to_string()),
                    academic_title: None,
                    date_of_birth: Some(GeneralDate {
                        date_string: "19640812".to_string(),
                        date_value: Some("1964-08-12".to_string()),
                    }),
                    place_of_birth: Some(GeneralPlace {
                        structured_place: None,
                        freetext_place: Some("BERLIN".to_string()),
                        no_place_info: None,
                    }),
                    nationality: Some("D".to_string()),
                    place_of_residence: Some(GeneralPlace {
                        structured_place: Some(Place {
                            street: Some("HEIDESTRASSE 17".to_string()),
                            city: "KÖLN".to_string(),
                            state: None,
                            country: "D".to_string(),
                            zip_code: Some("51147".to_string()),
                        }),
                        freetext_place: None,
                        no_place_info: None,
                    }),
                    restricted_id: Some(RestrictedID {
                        id: "01A4FB509CEBC6595151A4FB5F9C75C6FE01A4FB59CB655A4FB5F9C75C6FEE"
                            .to_string(),
                        id2: Some(
                            "5C6FE01A4FB59CB655A4FB5F9C75C6FEE01A4FB509CEBC6595151A4FB5F9C7"
                                .to_string(),
                        ),
                    }),
                    ..Default::default()
                }),
                fulfils_age: Some(VerificationResult {
                    fulfils_request: true,
                }),
                fulfils_place: Some(VerificationResult {
                    fulfils_request: true,
                }),
                ops_allowed: Some(Operations {
                    document_type: Some(AttributeResp::value(AttrResponse::ALLOWED)),
                    issuing_state: Some(AttributeResp::value(AttrResponse::ALLOWED)),
                    date_of_expiry: Some(AttributeResp::value(AttrResponse::ALLOWED)),
                    given_names: Some(AttributeResp::value(AttrResponse::ALLOWED)),
                    family_names: Some(AttributeResp::value(AttrResponse::ALLOWED)),
                    academic_title: Some(AttributeResp::value(AttrResponse::ALLOWED)),
                    date_of_birth: Some(AttributeResp::value(AttrResponse::ALLOWED)),
                    place_of_birth: Some(AttributeResp::value(AttrResponse::ALLOWED)),
                    nationality: Some(AttributeResp::value(AttrResponse::ALLOWED)),
                    place_of_residence: Some(AttributeResp::value(AttrResponse::ALLOWED)),
                    restricted_id: Some(AttributeResp::value(AttrResponse::ALLOWED)),
                    age_verification: Some(AttributeResp::value(AttrResponse::ALLOWED)),
                    place_verification: Some(AttributeResp::value(AttrResponse::ALLOWED)),
                    ..Default::default()
                }),
                trans_attest_resp: None,
                level_of_assurance: None,
                eid_type_resp: None,
                result: ResultType::ok(),
            },
        };

        let envelope = crate::soap::Envelope::new(response);
        let serialized = envelope.serialize_soap(true).unwrap();
        assert!(serialized.contains("PersonalData"));
        assert!(serialized.contains("ERIKA"));
        assert!(serialized.contains("MUSTERMANN"));
    }
}
