use serde::Serialize;

use crate::eid::common::models::{
    EIDTypeRequest, Header, LevelOfAssurance, ResultMajor, Session, TransactionAttestationRequest, UseOperations
};

#[derive(Default)]
pub struct UseIDRequest {
    pub use_operations: Vec<UseOperations>,
    pub age_verification: Option<u8>,
    pub place_verification: Option<String>,
    pub transaction_info: Option<String>,
    pub transaction_attestation_uri: Option<TransactionAttestationRequest>,
    pub level_of_assurance: Option<LevelOfAssurance>,
    pub eid_type_request: Option<EIDTypeRequest>,
    pub psk: Option<Psk>,
}

impl UseIDRequest {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Serialize)]
pub struct UseIDResponse {
    #[serde(rename = "eid:Session")]
    pub session: Session,
    #[serde(rename = "eid:eCardServerAddress")]
    pub ecard_server_address: Option<String>,
    #[serde(rename = "eid:PSK")]
    pub psk: Psk,
    #[serde(rename = "dss:Result")]
    pub result: ResultMajor,
}

#[derive(Serialize)]
pub struct Psk {
    pub id: String,
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
