pub mod info;
pub mod result;
pub mod useid;

pub use info::*;
pub use result::*;
pub use useid::*;

use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};
use validator::Validate;

// Operations types
#[derive(Debug, Clone, Default, Serialize, Deserialize, Decode, Encode)]
pub struct Operations<T: Default> {
    #[serde(rename(serialize = "eid:DocumentType"))]
    #[serde(rename(deserialize = "DocumentType"), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_type: Option<T>,
    #[serde(rename(serialize = "eid:IssuingState"))]
    #[serde(rename(deserialize = "IssuingState"), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuing_state: Option<T>,
    #[serde(rename(serialize = "eid:DateOfExpiry"))]
    #[serde(rename(deserialize = "DateOfExpiry"), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_of_expiry: Option<T>,
    #[serde(rename(serialize = "eid:GivenNames"))]
    #[serde(rename(deserialize = "GivenNames"), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_names: Option<T>,
    #[serde(rename(serialize = "eid:FamilyNames"))]
    #[serde(rename(deserialize = "FamilyNames"), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_names: Option<T>,
    #[serde(rename(serialize = "eid:ArtisticName"))]
    #[serde(rename(deserialize = "ArtisticName"), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artistic_name: Option<T>,
    #[serde(rename(serialize = "eid:AcademicTitle"))]
    #[serde(rename(deserialize = "AcademicTitle"), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub academic_title: Option<T>,
    #[serde(rename(serialize = "eid:DateOfBirth"))]
    #[serde(rename(deserialize = "DateOfBirth"), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_of_birth: Option<T>,
    #[serde(rename(serialize = "eid:PlaceOfBirth"))]
    #[serde(rename(deserialize = "PlaceOfBirth"), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub place_of_birth: Option<T>,
    #[serde(rename(serialize = "eid:Nationality"))]
    #[serde(rename(deserialize = "Nationality"), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nationality: Option<T>,
    #[serde(rename(serialize = "eid:BirthName"))]
    #[serde(rename(deserialize = "BirthName"), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birth_name: Option<T>,
    #[serde(rename(serialize = "eid:PlaceOfResidence"))]
    #[serde(rename(deserialize = "PlaceOfResidence"), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub place_of_residence: Option<T>,
    #[serde(rename(serialize = "eid:CommunityID"))]
    #[serde(rename(deserialize = "CommunityID"), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub community_id: Option<T>,
    #[serde(rename(serialize = "eid:ResidencePermitI"))]
    #[serde(rename(deserialize = "ResidencePermitI"), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub residence_permit_i: Option<T>,
    #[serde(rename(serialize = "eid:RestrictedID"))]
    #[serde(rename(deserialize = "RestrictedID"), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restricted_id: Option<T>,
    #[serde(rename(serialize = "eid:AgeVerification"))]
    #[serde(rename(deserialize = "AgeVerification"), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_verification: Option<T>,
    #[serde(rename(serialize = "eid:PlaceVerification"))]
    #[serde(rename(deserialize = "PlaceVerification"), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub place_verification: Option<T>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Decode, Encode)]
pub enum LevelOfAssurance {
    #[serde(rename = "http://eidas.europa.eu/LoA/low")]
    EidasLow,
    #[serde(rename = "http://eidas.europa.eu/LoA/substantial")]
    EidasSubstantial,
    #[serde(rename = "http://eidas.europa.eu/LoA/high")]
    EidasHigh,
    #[serde(rename = "http://bsi.bund.de/eID/LoA/normal")]
    BsiNormal,
    #[serde(rename = "http://bsi.bund.de/eID/LoA/substantiell")]
    BsiSubstantiell,
    #[serde(rename = "http://bsi.bund.de/eID/LoA/hoch")]
    BsiHoch,
    #[serde(rename = "http://bsi.bund.de/eID/LoA/undefined")]
    BsiUndefined,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Validate)]
pub struct Session {
    #[serde(rename(serialize = "eid:ID", deserialize = "ID"))]
    #[validate(length(min = 32))]
    pub id: String,
}
