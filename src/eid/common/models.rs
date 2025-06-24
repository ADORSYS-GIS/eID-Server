use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum EIDTypeSelection {
    ALLOWED,
    DENIED,
}

pub type ICAOCounrty = String;

#[derive(Debug, Deserialize)]
pub struct EIDTypeRequest {
    #[serde(rename = "eid:SeCertified")]
    pub se_certified: Option<EIDTypeSelection>,
    #[serde(rename = "eid:SeEndorsed")]
    pub se_endorsed: Option<EIDTypeSelection>,
    #[serde(rename = "eid:CardCertified")]
    pub card_certified: Option<EIDTypeSelection>,
    #[serde(rename = "eid:HwKeystore")]
    pub hwkeystore: Option<EIDTypeSelection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TransactionAttestationRequest {
    /// URI that identifies the expected format for the transaction attestation
    #[serde(rename = "TransactionAttestationFormat")]
    pub transaction_attestation_format: String,

    /// Optional context information like an ID or hash
    #[serde(rename = "TransactionContext")]
    pub transaction_context: Option<String>,
}

#[derive(Serialize)]
pub struct OperationsResponder {
    #[serde(rename = "eid:DocumentType")]
    pub document_type: AttributeResponder,
    #[serde(rename = "eid:IssuingState")]
    pub issuing_state: AttributeResponder,
    #[serde(rename = "eid:DateOfExpiry")]
    pub date_of_expiry: AttributeResponder,
    #[serde(rename = "eid:GivenNames")]
    pub given_names: AttributeResponder,
    #[serde(rename = "eid:FamilyNames")]
    pub family_names: AttributeResponder,
    #[serde(rename = "eid:ArtisticName")]
    pub artistic_name: Option<AttributeResponder>,
    #[serde(rename = "eid:AcademicTitle")]
    pub academic_title: Option<AttributeResponder>,
    #[serde(rename = "eid:DateOfBirth")]
    pub date_of_birth: AttributeResponder,
    #[serde(rename = "eid:PlaceOfBirth")]
    pub place_of_birth: AttributeResponder,
    #[serde(rename = "eid:Nationality")]
    pub nationality: AttributeResponder,
    #[serde(rename = "eid:BirthName")]
    pub birth_name: AttributeResponder,
    #[serde(rename = "eid:PlaceOfResidence")]
    pub place_of_residence: AttributeResponder,
    #[serde(rename = "eid:CommunityID")]
    pub community_id: AttributeResponder,
    #[serde(rename = "eid:ResidencePermitID")]
    pub residence_permit_id: AttributeResponder,
    #[serde(rename = "eid:RestrictedID")]
    pub restricted_id: AttributeResponder,
    #[serde(rename = "eid:AgeVerification")]
    pub age_verification: AttributeResponder,
    #[serde(rename = "eid:PlaceVerification")]
    pub place_verification: AttributeResponder,
}

#[derive(Deserialize, Debug)]
pub struct OperationsRequester {
    #[serde(rename = "DocumentType")]
    pub document_type: AttributeRequester,
    #[serde(rename = "IssuingState")]
    pub issuing_state: AttributeRequester,
    #[serde(rename = "DateOfExpiry")]
    pub date_of_expiry: AttributeRequester,
    #[serde(rename = "GivenNames")]
    pub given_names: AttributeRequester,
    #[serde(rename = "FamilyNames")]
    pub family_names: AttributeRequester,
    #[serde(rename = "ArtisticName")]
    pub artistic_name: AttributeRequester,
    #[serde(rename = "AcademicTitle")]
    pub academic_title: AttributeRequester,
    #[serde(rename = "DateOfBirth")]
    pub date_of_birth: AttributeRequester,
    #[serde(rename = "PlaceOfBirth")]
    pub place_of_birth: AttributeRequester,
    #[serde(rename = "Nationality")]
    pub nationality: AttributeRequester,
    #[serde(rename = "BirthName")]
    pub birth_name: AttributeRequester,
    #[serde(rename = "PlaceOfResidence")]
    pub place_of_residence: AttributeRequester,
    #[serde(rename = "CommunityID")]
    pub community_id: Option<AttributeRequester>,
    #[serde(rename = "ResidencePermitID")]
    pub residence_permit_id: Option<AttributeRequester>,
    #[serde(rename = "RestrictedID")]
    pub restricted_id: AttributeRequester,
    #[serde(rename = "AgeVerification")]
    pub age_verification: AttributeRequester,
    #[serde(rename = "PlaceVerification")]
    pub place_verification: AttributeRequester,
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
    #[serde(rename = "eid:Nationality")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured_place: Option<PlaceType>,
    #[serde(rename = "eid:FreetextPlace")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freetextplace: Option<String>,
    #[serde(rename = "eid:NoPlaceInfo")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noplaceinfo: Option<String>,
}

#[derive(Default, Clone, Serialize)]
pub struct PlaceType {
    #[serde(rename = "eid:Street")]
    pub street: String,
    #[serde(rename = "eid:City")]
    pub city: String,
    #[serde(rename = "eid:State")]
    #[serde(default)]
    pub state: String,
    #[serde(rename = "eid:Country")]
    pub country: ICAOCounrty,
    #[serde(rename = "eid:ZipCode")]
    pub zipcode: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum AttributeRequester {
    REQUIRED,
    ALLOWED,
    PROHIBITED,
}

#[derive(Serialize, Clone)]
pub enum AttributeSelection {
    ALLOWED,
    PROHIBITED,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum AttributeResponder {
    ALLOWED,
    PROHIBITED,
    NOTONCHIP,
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

#[derive(Serialize, Default)]
pub struct ResultMajor {
    #[serde(rename = "ResultMajor")]
    pub result_major: String,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Header {}

#[derive(Debug, Deserialize, PartialEq, Eq, Clone)]
pub struct Session {
    #[serde(rename = "ID")]
    pub id: String,
}

#[derive(Serialize, Default)]
pub struct SessionResponse {
    #[serde(rename = "eid:ID")]
    pub id: String,
}

// From section 3.3.12 of the technical guideline TR-03130
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
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
            LevelOfAssurance::Undefined => "http://bsi.bund.de/eID/LoA/undefined",
            LevelOfAssurance::Normal => "http://bsi.bund.de/eID/LoA/normal",
            LevelOfAssurance::Substantiell => "http://bsi.bund.de/eID/LoA/substantiell",
            LevelOfAssurance::Hoch => "http://bsi.bund.de/eID/LoA/hoch",
            LevelOfAssurance::Substantial => "http://eidas.europa.eu/LoA/substantial",
            LevelOfAssurance::High => "http://eidas.europa.eu/LoA/high",
            LevelOfAssurance::Low => "http://eidas.europa.eu/LoA/low",
        };
        write!(f, "{s}")
    }
}

impl FromStr for AttributeRequester {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "ALLOWED" => Ok(AttributeRequester::ALLOWED),
            "PROHIBITED" => Ok(AttributeRequester::PROHIBITED),
            "REQUIRED" => Ok(AttributeRequester::REQUIRED),
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
            ResultCode::UnknownError(msg) => msg.as_str(),
        };
        write!(f, "{text}")
    }
}

impl Display for AttributeRequester {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            AttributeRequester::ALLOWED => "ALLOWED",
            AttributeRequester::PROHIBITED => "PROHIBITED",
            AttributeRequester::REQUIRED => "REQUIRED",
        };
        write!(f, "{text}")
    }
}
