use serde::Serialize;

use crate::eid::common::models::{
    EIDTypeResponse, LevelOfAssurance, Operations, PersonalData, ResultCode,
    TransactionAttestationResponse,
};

#[derive(Default)]
pub struct GetResultRequest {
    pub session: String,
    pub request_counter: u8,
}

#[derive(Serialize)]    
pub struct GetResultResponse {
    pub personal_data: PersonalData,
    pub fulfils_age_verification: bool,
    pub fulfils_place_verification: bool,
    pub operations_allowed_by_user: Operations,
    pub transaction_attestation_response: TransactionAttestationResponse,
    pub level_of_assurance: LevelOfAssurance,
    pub eid_type_response: EIDTypeResponse,
    pub result: ResultCode,
}

#[derive(Serialize)]
pub struct GetResultResponseBody {
    #[serde(rename = "eid:getResultResponse")]
    pub get_result_response: GetResultResponse,
}


#[derive(Serialize)]
#[serde(rename = "soapenv:Envelope")]
#[serde(rename_all = "PascalCase")]
pub struct GetResultResponseEnvelope {
    #[serde(rename = "xmlns:soapenv")]
    pub soapenv: &'static str,

    #[serde(rename = "xmlns:eid")]
    pub eid: &'static str,

    #[serde(rename = "xmlns:dss")]
    pub dss: &'static str,

    #[serde(rename = "soapenv:Body")]
    pub body: GetResultResponseBody,
}


