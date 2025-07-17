use serde::{Deserialize, Serialize};

use crate::eid::common::models::{
    EIDTypeRequest, Header, LevelOfAssurance, OperationsRequester, ResultMajor, SessionResponse,
    TransactionAttestationRequest,
};

#[derive(Deserialize, Debug)]
#[serde(rename = "eid:useIDRequest")]
pub struct UseIDRequest {
    #[serde(rename = "eid:UseOperations")]
    pub _use_operations: OperationsRequester,
    #[serde(rename = "eid:AgeVerificationRequest")]
    pub _age_verification: AgeVerificationRequest,
    #[serde(rename = "eid:PlaceVerificationRequest")]
    pub _place_verification: PlaceVerificationRequest,
    #[serde(rename = "eid:TransactionInfo")]
    pub _transaction_info: Option<String>,
    #[serde(rename = "eid:TransactionAttestationRequest")]
    pub _transaction_attestation_request: Option<TransactionAttestationRequest>,
    #[serde(rename = "eid:LevelOfAssuranceRequest")]
    pub _level_of_assurance: Option<LevelOfAssurance>,
    #[serde(rename = "eid:EIDTypeRequest")]
    pub _eid_type_request: Option<EIDTypeRequest>,
    #[serde(rename = "eid:Psk")]
    pub _psk: Option<Psk>,
}

#[derive(Debug, Deserialize)]
pub struct AgeVerificationRequest {
    #[serde(rename = "Age")]
    pub _age: u8,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "eid:PlaceVerificationRequest")]
pub struct PlaceVerificationRequest {
    #[serde(rename = "CommunityID")]
    pub _community_id: String,
}

#[derive(Serialize, Default, Debug)]
pub struct UseIDResponse {
    #[serde(rename = "eid:Session")]
    pub session: SessionResponse,
    #[serde(rename = "eid:eCardServerAddress")]
    pub ecard_server_address: Option<String>,
    #[serde(rename = "eid:PSK")]
    pub psk: Psk,
    #[serde(rename = "dss:Result")]
    pub result: ResultMajor,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Psk {
    #[serde(rename = "eid:ID")]
    pub id: String,
    #[serde(rename = "eid:Key")]
    pub key: String,
}

#[derive(Serialize)]
#[serde(rename = "soapenv:Envelope")]
pub struct UseIdEnvelope<'a> {
    #[serde(rename = "soapenv:Header")]
    pub header: Header,

    #[serde(rename = "soapenv:Body")]
    pub body: UseIdBody<'a>,
}

#[derive(Serialize)]
#[serde(rename = "soapenv:Body")]
pub struct UseIdBody<'a> {
    #[serde(rename = "eid:useIDResponse")]
    pub response: &'a UseIDResponse,
}

