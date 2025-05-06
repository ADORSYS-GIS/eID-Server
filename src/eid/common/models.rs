use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EIDTypeSelection {
    ALLOWED,
    DENIED,
}

pub type ICAOCounrty = String;

#[derive(Debug, Default)]
pub struct EIDTypeRequest {
    pub se_certified: Option<EIDTypeSelection>,
    pub se_endorsed: Option<EIDTypeSelection>,
    pub card_certified: Option<EIDTypeSelection>,
    pub hwkeystore: Option<EIDTypeSelection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionAttestationRequest {
    /// URI that identifies the expected format for the transaction attestation
    pub transaction_attestation_format: String,

    /// Optional context information like an ID or hash
    pub transaction_context: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UseOperations {
    pub name: String,
    pub requirement: AttributeRequest,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Operations {
    pub document_type: AttributeRequest,
    pub issuing_state: AttributeRequest,
    pub date_of_expiry: AttributeRequest,
    pub given_names: AttributeRequest,
    pub family_names: AttributeRequest,
    pub artistic_name: Option<AttributeRequest>,
    pub academic_title: Option<AttributeRequest>,
    pub date_of_birth: AttributeRequest,
    pub place_of_birth: AttributeRequest,
    pub nationality: AttributeRequest,
    pub birth_name: AttributeRequest,
    pub place_of_residence: AttributeRequest,
    pub community_id: Option<AttributeRequest>,
    pub residence_permit_id: Option<AttributeRequest>,
    pub restricted_id: AttributeRequest,
    pub age_verification: Option<AttributeRequest>,
    pub place_verification: Option<AttributeRequest>,
}

#[derive(Serialize)]
pub struct PersonalData {
    #[serde(rename = "eid:DocumentType")]
    pub document_type: String,
    #[serde(rename = "eid:IssuingState")]
    pub issuing_state: ICAOCounrty,
    #[serde(rename = "eid:DateOfExpiry")]
    pub date_of_expiry: String,
    #[serde(rename = "eid:GivenNames")]
    pub given_names: String,
    #[serde(rename = "eid:FamilyNames")]
    pub family_names: String,
    #[serde(rename = "eid:ArtisticName")]
    pub artistic_name: String,
    #[serde(rename = "eid:AcademicTitle")]
    pub academic_title: String,
    #[serde(rename = "eid:DateOfBirth")]
    pub date_of_birth: GeneralDateType,
    #[serde(rename = "eid:PlaceOfBirth")]
    pub place_of_birth: GeneralPlaceType,
    #[serde(rename = "Nationality")]
    pub nationality: ICAOCounrty,
    #[serde(rename = "eid:BirthName")]
    pub birth_name: String,
    #[serde(rename = "eid:PlaceOfResidence")]
    pub place_of_residence: GeneralPlaceType,
    #[serde(rename = "eid:CommunityID")]
    pub community_id: String,
    #[serde(rename = "eid:ResidencePermitID")]
    pub residence_permit_id: String,
    #[serde(rename = "eid:RestrictedID")]
    pub restricted_id: RestrictedID,
}

#[derive(Serialize)]
pub struct RestrictedID {
    #[serde(rename = "eid:ID")]
    pub id: String,
    #[serde(rename = "eid:ID2")]
    pub id2: String,
}

#[derive(Serialize)]
pub struct TransactionAttestationResponse {
    #[serde(rename = "eid:TransactionAttestationFormat")]
    pub transaction_attestation_format: String,
    #[serde(rename = "eid:TransactionAttestationData")]
    pub transaction_attestation_data: String,
}

#[derive(Serialize)]
pub struct EIDTypeResponse {
    #[serde(rename = "eid:CardCertified")]
    pub card_certified: EIDTypeUsedType,
    #[serde(rename = "eid:SeCertified")]
    pub se_certified: EIDTypeUsedType,
    #[serde(rename = "eid:SeEndorsed")]
    pub se_endorsed: EIDTypeUsedType,
    #[serde(rename = "eid:HwKeystore")]
    pub hw_keystore: EIDTypeUsedType,
}

pub type EIDTypeUsedType = String;

#[derive(Debug, Serialize, Deserialize)]
pub struct GeneralDateType {
    /// The DateString contains the date in yyyymmdd format (8 characters, with spaces and digits).
    #[serde(rename = "eid:DateString")]
    pub date_string: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "eid:DateValue")]
    pub date_value: Option<String>,
}

#[derive(Serialize)]
pub struct GeneralPlaceType {
    #[serde(rename = "eid:StructuredPlace")]
    pub structured_place: Option<PlaceType>,
    #[serde(rename = "eid:FreetextPlace")]
    pub freetextplace: Option<String>,
    #[serde(rename = "eid:NoPlaceInfo")]
    pub noplaceinfo: Option<String>,
}

#[derive(Default, Clone, Serialize)]
pub struct PlaceType {
    #[serde(rename = "eid:Street")]
    pub street: String,
    #[serde(rename = "eid:City")]
    pub city: String,
    #[serde(rename = "eid:State")]
    pub state: String,
    #[serde(rename = "eid:Country")]
    pub country: ICAOCounrty,
    #[serde(rename = "eid:ZipCode")]
    pub zipcode: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttributeRequest {
    REQUIRED,
    ALLOWED,
    PROHIBITED,
}

pub enum AttributeSelection {
    ALLOWED,
    PROHIBITED,
}

// From Technical Guideline TR-03130
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ResultCode {
    Ok,
    NoResultYet,
    TooManyOpenSessions,
    InvalidSession,
    InvalidRequest,
    InternalError,
    UnknownError(String),
}

// From section 3.3.12 of the technical guideline TR-03130
#[derive(PartialEq, Eq, Debug, Serialize)]
pub enum LevelOfAssurance {
    Undefined,
    Normal,
    Substantiell,
    Hoch,
    Substantial,
    High,
    Low,
}

impl FromStr for LevelOfAssurance {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "http://bsi.bund.de/eID/LoA/undefined" => Ok(LevelOfAssurance::Undefined),
            "http://bsi.bund.de/eID/LoA/normal" => Ok(LevelOfAssurance::Normal),
            "http://bsi.bund.de/eID/LoA/substantiell" => Ok(LevelOfAssurance::Substantiell),
            "http://bsi.bund.de/eID/LoA/hoch" => Ok(LevelOfAssurance::Hoch),
            "http://eidas.europa.eu/LoA/low" => Ok(LevelOfAssurance::Low),
            "http://eidas.europa.eu/LoA/substantial" => Ok(LevelOfAssurance::Substantial),
            "http://eidas.europa.eu/LoA/high" => Ok(LevelOfAssurance::High),
            _ => Err("Unkown Level of assurance".to_string()),
        }
    }
}

impl fmt::Display for LevelOfAssurance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LevelOfAssurance::Undefined => "Undefined",
            LevelOfAssurance::Normal => "Normal",
            LevelOfAssurance::Substantiell => "Substantiell",
            LevelOfAssurance::Hoch => "Hoch",
            LevelOfAssurance::Substantial => "Substantial",
            LevelOfAssurance::High => "High",
            LevelOfAssurance::Low => "Low",
        };
        write!(f, "{}", s)
    }
}

impl FromStr for AttributeRequest {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "ALLOWED" => Ok(AttributeRequest::ALLOWED),
            "PROHIBITED" => Ok(AttributeRequest::PROHIBITED),
            "REQUIRED" => Ok(AttributeRequest::REQUIRED),
            _ => Err("unknown attribute ".to_owned()),
        }
    }
}

impl fmt::Display for ResultCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            ResultCode::Ok => "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok",
            ResultCode::NoResultYet => {
                "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#noResultYet"
            }
            ResultCode::TooManyOpenSessions => {
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/useID#tooManyOpenSessions"
            }
            ResultCode::InvalidSession => {
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/useID#invalidSession"
            }
            ResultCode::InvalidRequest => {
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/useID#invalidRequest"
            }
            ResultCode::InternalError => {
                "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#internalError"
            }
            ResultCode::UnknownError(msg) => msg.as_str(), // Custom unknown errors
        };
        write!(f, "{text}")
    }
}

impl Display for AttributeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            AttributeRequest::ALLOWED => "ALLOWED",
            AttributeRequest::PROHIBITED => "PROHIBITED",
            AttributeRequest::REQUIRED => "REQUIRED",
        };
        write!(f, "{text}")
    }
}
