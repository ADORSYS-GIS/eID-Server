pub mod eid;
pub mod paos;

use bincode::{Decode, Encode};
use paos::ConnectionHandle;
use serde::{Deserialize, Serialize};

use crate::{apdu::ProtectedAPDU, asn1::utils::ChipAuthAlg, crypto::Curve};

pub const RESULT_OK: &str = "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok";
pub const RESULT_ERROR: &str = "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error";

/// Result type for error handling
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ResultType {
    pub result_major: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_minor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_message: Option<String>,
}

impl ResultType {
    pub fn ok() -> Self {
        Self {
            result_major: RESULT_OK.into(),
            result_minor: None,
            result_message: None,
        }
    }

    pub fn error(error_code: &str, message: Option<&str>) -> Self {
        Self {
            result_major: RESULT_ERROR.into(),
            result_minor: Some(error_code.into()),
            result_message: message.map(|s| s.into()),
        }
    }

    pub fn is_ok(&self) -> bool {
        self.result_major == RESULT_OK
    }

    pub fn is_error(&self) -> bool {
        self.result_major == RESULT_ERROR
    }
}

#[derive(Debug, Clone, Decode, Encode)]
pub enum State {
    Initial,
    EAC1 {
        conn_handle: ConnectionHandle,
        aux_data: Option<String>,
        built_chat: (Option<String>, Option<String>),
    },
    EAC2 {
        slot_handle: String,
        restricted_chat: Option<String>,
        eph_key: Vec<u8>,
        chip_auth: (Curve, ChipAuthAlg),
        built_chat: (Option<String>, Option<String>),
    },
    Transmit {
        apdu_cmds: Vec<ProtectedAPDU>,
        cmds_len: usize,
        secure_keys: Option<SecureMessagingKeys>,
    },
    TransmitResponse {
        responses: Vec<ProcessedAPDUResponse>,
    },
}

/// Secure messaging keys for decrypting responses
#[derive(Debug, Clone, Decode, Encode)]
pub struct SecureMessagingKeys {
    pub k_enc: Vec<u8>,
    pub k_mac: Vec<u8>,
    pub cipher_type: u8, // Store cipher type as u8 for serialization
    pub initial_ssc: u32,
}

impl SecureMessagingKeys {
    pub fn new(k_enc: Vec<u8>, k_mac: Vec<u8>, cipher: crate::crypto::sym::Cipher, initial_ssc: u32) -> Self {
        let cipher_type = match cipher {
            crate::crypto::sym::Cipher::Aes128Cbc => 1,
            crate::crypto::sym::Cipher::Aes192Cbc => 2,
            crate::crypto::sym::Cipher::Aes256Cbc => 3,
        };
        Self {
            k_enc,
            k_mac,
            cipher_type,
            initial_ssc,
        }
    }

    pub fn to_cipher(&self) -> crate::crypto::sym::Cipher {
        match self.cipher_type {
            1 => crate::crypto::sym::Cipher::Aes128Cbc,
            2 => crate::crypto::sym::Cipher::Aes192Cbc,
            3 => crate::crypto::sym::Cipher::Aes256Cbc,
            _ => crate::crypto::sym::Cipher::Aes128Cbc, // default
        }
    }
}

/// Processed APDU response with metadata for later decoding
#[derive(Debug, Clone, Decode, Encode)]
pub struct ProcessedAPDUResponse {
    pub response_data: Vec<u8>,
    pub cmd_type: crate::apdu::CmdType,
    pub ssc_before_cmd: u32,
    pub ssc_before_resp: u32,
    pub status_code: u16,
    pub is_success: bool,
}
