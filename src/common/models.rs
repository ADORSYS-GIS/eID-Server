use std::str::FromStr;

use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EIDTypeSelection {
    ALLOWED,
    DENIED,
}

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



#[derive(Debug, Serialize, Deserialize)]
pub enum AttributeRequest {
    REQUIRED,
    ALLOWED,
    PROHIBITED,
}

// From Technical Guideline TR-03130
#[derive(Debug, Clone, PartialEq, Eq)]
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

