//! Test service implementation for the transmit module.
//! This provides a mock implementation of TransmitService for testing purposes.

use async_trait::async_trait;
use hex;

use crate::domain::eid::ports::{TransmitResult, TransmitService};
use crate::server::session::TlsSessionInfo;

#[derive(Debug, Clone)]
pub struct TestTransmitService;

#[async_trait]
impl TransmitService for TestTransmitService {
    async fn transmit_apdu(&self, apdu: Vec<u8>, _slot_handle: &str) -> TransmitResult<Vec<u8>> {
        // Convert APDU to uppercase hex for easier comparison
        let apdu_hex = hex::encode_upper(&apdu);

        // Return predefined responses for test APDUs
        match apdu_hex.as_str() {
            // SELECT eID application
            "00A4040008A000000167455349" => {
                Ok(hex::decode("6F108408A000000167455349A5049F6501FF9000")
                    .expect("Hardcoded test hex should decode successfully"))
            }
            // READ BINARY
            "00B0000000" => Ok(hex::decode("0102030405060708090A0B0C0D0E0F109000")
                .expect("Hardcoded test hex should decode successfully")),
            "00B0000010" => Ok(hex::decode("1112131415161718191A1B1C1D1E1F209000")
                .expect("Hardcoded test hex should decode successfully")),
            // SELECT eID.SIGN application
            "00A4040008A000000167455349474E" => {
                Ok(hex::decode("9000").expect("Hardcoded test hex should decode successfully"))
            }
            // Default success response for unknown APDUs
            _ => Ok(vec![0x90, 0x00]),
        }
    }
}

/// Creates mock TLS session info for testing purposes
pub fn create_mock_tls_session_info(slot_handle: &str) -> TlsSessionInfo {
    TlsSessionInfo {
        session_id: format!("mock-session-{slot_handle}"),
        cipher_suite: "TLS_RSA_PSK_WITH_AES_256_CBC_SHA".to_string(),
        psk_id: Some(format!("mock-psk-{slot_handle}")),
        psk_key: Some("mock-psk-key".to_string()),
    }
}
