use serde::{Deserialize, Serialize};

use crate::eid::common::models::{
    EIDTypeResponse, OperationsResponder, PersonalData, ResultMajor, Session,
    TransactionAttestationResponse,
};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "eid:getResultRequest")]
pub struct GetResultRequest {
    #[serde(rename = "eid:Session")]
    pub session: Session,
    #[serde(rename = "eid:RequestCounter")]
    pub request_counter: u32,
}

#[derive(Serialize)]
#[serde(rename = "eid:getResultResponse")]
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
