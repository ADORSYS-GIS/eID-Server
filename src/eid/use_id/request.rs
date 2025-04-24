use crate::common::models::{
    EIDTypeRequest, LevelOfAssurance, ResultCode, TransactionAttestationRequest, UseOperations,
};

pub struct UseIDRequest {
    pub use_operations: Vec<UseOperations>,
    pub age_verification: Option<u8>,
    pub place_verification: Option<String>,
    pub transaction_info: Option<String>,
    pub transaction_attestation_uri: Option<TransactionAttestationRequest>,
    pub level_of_assurance: Option<LevelOfAssurance>,
    pub eid_type_request: Option<EIDTypeRequest>,
    pub psk: Option<String>,
}

pub struct UseIDResponse {
    pub session: String,
    pub ecard_server_address: Option<String>,
    pub psk: Option<String>,
    pub result: ResultCode,
}
