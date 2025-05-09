use serde::{Deserialize, Serialize};

use crate::eid::common::models::{
    EIDTypeRequest, Header, LevelOfAssurance, OperationsRequester, ResultMajor, SessionResponse,
    TransactionAttestationRequest,
};

#[derive(Deserialize, Debug)]
pub struct UseIDRequest {
    #[serde(rename = "UseOperations")]
    pub _use_operations: OperationsRequester,
    #[serde(rename = "AgeVerificationRequest")]
    pub _age_verification: AgeVerificationRequest,
    #[serde(rename = "PlaceVerificationRequest")]
    pub _place_verification: PlaceVerificationRequest,
    #[serde(rename = "TransactionInfo")]
    pub _transaction_info: Option<String>,
    #[serde(rename = "TransactionAttestationRequest")]
    pub _transaction_attestation_request: Option<TransactionAttestationRequest>,
    #[serde(rename = "LevelOfAssurance")]
    pub _level_of_assurance: Option<LevelOfAssurance>,
    #[serde(rename = "EIDTypeRequest")]
    pub _eid_type_request: Option<EIDTypeRequest>,
    #[serde(rename = "Psk")]
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

#[derive(Serialize)]
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

#[derive(Serialize, Deserialize, Debug)]
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

#[derive(Deserialize)]
#[serde(rename = "Envelope")]
pub struct UseIDRequestEnvelope {
    #[serde(rename = "Body")]
    pub _body: UseIDRequestBody,
}

#[derive(Debug, Deserialize)]
pub struct UseIDRequestBody {
    #[serde(rename = "useIDRequest")]
    pub _use_id_request: UseIDRequest,
}
