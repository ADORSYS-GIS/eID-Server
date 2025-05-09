use serde::Serialize;

use crate::eid::common::models::{AttributeSelection, Header};

#[derive(Serialize, Clone)]
pub struct VersionType {
    #[serde(rename = "eid:VersionString")]
    pub version_string: String,
    #[serde(rename = "eid:Major")]
    pub major: u8,
    #[serde(rename = "eid:Minor")]
    pub minor: u8,
    #[serde(rename = "eid:Bugfix")]
    pub bugfix: u8,
}

#[derive(Serialize, Clone)]
pub struct OperationsSelector {
    #[serde(rename = "eid:DocumentType")]
    pub document_type: AttributeSelection,
    #[serde(rename = "eid:IssuingState")]
    pub issuing_state: AttributeSelection,
    #[serde(rename = "eid:DateOfExpiry")]
    pub date_of_expiry: AttributeSelection,
    #[serde(rename = "eid:GivenNames")]
    pub given_names: AttributeSelection,
    #[serde(rename = "eid:FamilyNames")]
    pub family_names: AttributeSelection,
    #[serde(rename = "eid:ArtisticName")]
    pub artistic_names: AttributeSelection,
    #[serde(rename = "eid:AcademicTitle")]
    pub academic_title: AttributeSelection,
    #[serde(rename = "eid:DateOfBirth")]
    pub date_of_birth: AttributeSelection,
    #[serde(rename = "eid:PlaceOfBirth")]
    pub place_of_birth: AttributeSelection,
    #[serde(rename = "eid:Nationality")]
    pub nationality: AttributeSelection,
    #[serde(rename = "eid:BirthName")]
    pub birth_name: AttributeSelection,
    #[serde(rename = "eid:PlaceOfResidence")]
    pub place_of_residence: AttributeSelection,
    #[serde(rename = "eid:CommunityID")]
    pub community_id: Option<AttributeSelection>,
    #[serde(rename = "eid:ResidencePermitI")]
    pub residence_permit_i: Option<AttributeSelection>,
    #[serde(rename = "eid:RestrictedID")]
    pub restricted_id: AttributeSelection,
    #[serde(rename = "eid:AgeVerification")]
    pub age_verification: AttributeSelection,
    #[serde(rename = "eid:PlaceVerification")]
    pub place_verification: AttributeSelection,
}

#[derive(Serialize)]
#[serde(rename = "soapenv:Envelope")]
pub struct GetServerInfoEnvelope {
    #[serde(rename = "soapenv:Header")]
    pub header: Header,

    #[serde(rename = "soapenv:Body")]
    pub body: GetServerInfoBody,
}

#[derive(Serialize)]
#[serde(rename = "soapenv:Body")]
pub struct GetServerInfoBody {
    #[serde(rename = "eid:getServerInfoResponse")]
    pub response: GetServerInfoResponse,
}

#[derive(Serialize)]
pub struct GetServerInfoResponse {
    #[serde(rename = "eid:ServerVersion")]
    pub server_version: VersionType,

    #[serde(rename = "eid:DocumentVerificationRights")]
    pub document_verification_rights: OperationsSelector,
}
