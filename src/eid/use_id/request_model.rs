use crate::common::models::{
    EIDTypeRequest, LevelOfAssurance, ResultCode, TransactionAttestationRequest, UseOperations,
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
    pub psk: Option<PSK>,
}

impl UseIDRequest {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Default)]
pub struct PSK {
    pub id: String,
    pub key: String
}

