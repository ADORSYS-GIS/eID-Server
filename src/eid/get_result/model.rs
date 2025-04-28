use crate::eid::common::models::{
    EIDTypeResponse, LevelOfAssurance, Operations, PersonalData, ResultCode,
    TransactionAttestationResponse,
};

#[derive(Default)]
pub struct GetResultRequest {
    pub session: String,
    pub request_counter: u8,
}

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
