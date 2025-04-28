use crate::eid::common::models::AttributeSelection;

pub struct GetServerInfoResponse {
    pub server_version: VersionType,
    pub document_verification_rights: OperationsSelector
}
pub struct VersionType {
    pub version_string: String,
    pub major: u8,
    pub minor: u8,
    pub bugfix: u8
}

pub struct OperationsSelector {
    pub document_type: AttributeSelection,
    pub issuing_state: AttributeSelection,
    pub date_of_expiry: AttributeSelection,
    pub given_names: AttributeSelection,
    pub family_names: AttributeSelection,
    pub artistic_names: AttributeSelection,
    pub academic_title: AttributeSelection,
    pub date_of_birth: AttributeSelection,
    pub place_of_birth: AttributeSelection,
    pub nationality: AttributeSelection,
    pub birth_name: AttributeSelection,
    pub place_of_residence: AttributeSelection,
    pub community_id: AttributeSelection,
    pub residence_permit: AttributeSelection,
    pub restricted_id: AttributeSelection,
    pub age_verification: AttributeSelection,
    pub place_verification: AttributeSelection
}

