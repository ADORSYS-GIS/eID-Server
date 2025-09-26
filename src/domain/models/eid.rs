pub mod useid;

pub use useid::*;

use serde::{Deserialize, Serialize};

// Operations types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operations<T: Default> {
    #[serde(rename(serialize = "eid:DocumentType"))]
    #[serde(rename(deserialize = "DocumentType"), default)]
    pub document_type: T,
    #[serde(rename(serialize = "eid:IssuingState"))]
    #[serde(rename(deserialize = "IssuingState"), default)]
    pub issuing_state: T,
    #[serde(rename(serialize = "eid:DateOfExpiry"))]
    #[serde(rename(deserialize = "DateOfExpiry"), default)]
    pub date_of_expiry: T,
    #[serde(rename(serialize = "eid:GivenNames"))]
    #[serde(rename(deserialize = "GivenNames"), default)]
    pub given_names: T,
    #[serde(rename(serialize = "eid:FamilyNames"))]
    #[serde(rename(deserialize = "FamilyNames"), default)]
    pub family_names: T,
    #[serde(rename(serialize = "eid:ArtisticName"))]
    #[serde(rename(deserialize = "ArtisticName"), default)]
    pub artistic_name: T,
    #[serde(rename(serialize = "eid:AcademicTitle"))]
    #[serde(rename(deserialize = "AcademicTitle"), default)]
    pub academic_title: T,
    #[serde(rename(serialize = "eid:DateOfBirth"))]
    #[serde(rename(deserialize = "DateOfBirth"), default)]
    pub date_of_birth: T,
    #[serde(rename(serialize = "eid:PlaceOfBirth"))]
    #[serde(rename(deserialize = "PlaceOfBirth"), default)]
    pub place_of_birth: T,
    #[serde(rename(serialize = "eid:Nationality"))]
    #[serde(rename(deserialize = "Nationality"), default)]
    pub nationality: T,
    #[serde(rename(serialize = "eid:BirthName"))]
    #[serde(rename(deserialize = "BirthName"), default)]
    pub birth_name: T,
    #[serde(rename(serialize = "eid:PlaceOfResidence"))]
    #[serde(rename(deserialize = "PlaceOfResidence"), default)]
    pub place_of_residence: T,
    #[serde(rename(serialize = "eid:CommunityID"))]
    #[serde(rename(deserialize = "CommunityID"), default)]
    pub community_id: T,
    #[serde(rename(serialize = "eid:ResidencePermitI"))]
    #[serde(rename(deserialize = "ResidencePermitI"), default)]
    pub residence_permit_i: T,
    #[serde(rename(serialize = "eid:RestrictedID"))]
    #[serde(rename(deserialize = "RestrictedID"), default)]
    pub restricted_id: T,
    #[serde(rename(serialize = "eid:AgeVerification"))]
    #[serde(rename(deserialize = "AgeVerification"), default)]
    pub age_verification: T,
    #[serde(rename(serialize = "eid:PlaceVerification"))]
    #[serde(rename(deserialize = "PlaceVerification"), default)]
    pub place_verification: T,
}
