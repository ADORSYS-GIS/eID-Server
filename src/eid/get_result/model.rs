use serde::{Deserialize, Serialize};

use crate::eid::common::models::{
    EIDTypeResponse, OperationsResponder, PersonalData, ResultMajor, Session,
    TransactionAttestationResponse,
};

#[derive(Deserialize, Debug, Clone)]
pub struct GetResultRequest {
    #[serde(rename = "Session")]
    pub session: Session,
    #[serde(rename = "RequestCounter")]
    pub request_counter: u8,
}

#[derive(Serialize)]
pub struct GetResultResponse {
    #[serde(rename = "eid:PersonalData")]
    pub personal_data: PersonalData,
    #[serde(rename = "eid:FulfilsAgeVerification")]
    pub fulfils_age_verification: FulfilsRequest,
    #[serde(rename = "eid:FulfilsPlaceVerification")]
    pub fulfils_place_verification: FulfilsRequest,
    #[serde(rename = "eid:OperationsAllowedByUser")]
    pub operations_allowed_by_user: OperationsResponder,
    #[serde(rename = "eid:TransactionAttestationResponse")]
    pub transaction_attestation_response: TransactionAttestationResponse,
    #[serde(rename = "eid:LevelOfAssuranceResponse")]
    pub level_of_assurance: String,
    #[serde(rename = "eid:EidTypeResponse")]
    pub eid_type_response: EIDTypeResponse,
    #[serde(rename = "dss:Result")]
    pub result: ResultMajor,
}

#[derive(Serialize)]
pub struct FulfilsRequest {
    #[serde(rename = "eid:FulfilsRequest")]
    pub fulfils_request: bool,
}

#[derive(Serialize)]
pub struct GetResultResponseBody {
    #[serde(rename = "eid:getResultResponse")]
    pub get_result_response: GetResultResponse,
}

#[derive(Serialize, Default)]
pub struct SoapHeader;

#[derive(Serialize)]
#[serde(rename = "soapenv:Envelope")]
pub struct GetResultResponseEnvelope {
    #[serde(rename = "soapenv:Header")]
    pub header: SoapHeader,

    #[serde(rename = "soapenv:Body")]
    pub body: GetResultResponseBody,
}

#[derive(Deserialize)]
#[serde(rename = "Envelope")]
pub struct GetResultRequestEnvelope {
    #[serde(rename = "Body")]
    pub body: SoapBody,
}

#[derive(Deserialize)]
pub struct SoapBody {
    #[serde(rename = "getResultRequest")]
    pub request: GetResultRequest,
}
