//! Service implementation for the transmit domain.
//! This contains the business logic for APDU transmission.

use async_trait::async_trait;
use hex;
use quick_xml::{de::from_str, se::to_string};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::error;

use super::ports::{TransmitError, TransmitResult, TransmitService};
use crate::config::TransmitConfig;

/// Configuration for the transmit service
#[derive(Debug, Clone)]
pub struct TransmitServiceConfig {
    pub client_url: String,
    pub session_timeout_secs: u64,
    pub max_retries: u32,
}

impl From<TransmitConfig> for TransmitServiceConfig {
    fn from(config: TransmitConfig) -> Self {
        Self {
            client_url: config.client_url,
            session_timeout_secs: config.session_timeout_secs,
            max_retries: 3, // Default retry count
        }
    }
}

/// XML structures for eID-Client communication
#[derive(Debug, Serialize)]
#[serde(rename = "Transmit", rename_all = "PascalCase")]
struct TransmitRequest {
    #[serde(rename = "@xmlns")]
    xmlns: String,
    slot_handle: String,
    #[serde(rename = "InputAPDUInfo")]
    input_apdu_info: InputAPDUInfoRequest,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct InputAPDUInfoRequest {
    #[serde(rename = "InputAPDU")]
    input_apdu: String,
    acceptable_status_code: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ClientResponse {
    #[serde(rename = "OutputAPDU")]
    output_apdu: String,
}

/// HTTP-based transmit service implementation
/// This service handles the business logic for APDU transmission including
/// HTTP client management, retry logic, XML serialization, and error handling
pub struct HttpTransmitService {
    client: Client,
    config: TransmitServiceConfig,
}

impl HttpTransmitService {
    /// Creates a new HTTP transmit service
    pub fn new(config: TransmitServiceConfig) -> TransmitResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.session_timeout_secs))
            .tls_built_in_root_certs(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .build()
            .map_err(|e| {
                TransmitError::NetworkError(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self { client, config })
    }

    /// Serializes the APDU request to XML format
    fn serialize_request(&self, apdu: &[u8], slot_handle: &str) -> TransmitResult<String> {
        let apdu_hex = hex::encode_upper(apdu);

        let transmit_request = TransmitRequest {
            xmlns: "urn:iso:std:iso-iec:24727:tech:schema".to_string(),
            slot_handle: slot_handle.to_string(),
            input_apdu_info: InputAPDUInfoRequest {
                input_apdu: apdu_hex,
                acceptable_status_code: "9000".to_string(),
            },
        };

        let xml = to_string(&transmit_request).map_err(|e| {
            TransmitError::SerializationError(format!("Failed to serialize XML: {}", e))
        })?;

        Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>{}", xml))
    }

    /// Parses the XML response from the eID-Client
    fn parse_response(&self, response_text: &str) -> TransmitResult<Vec<u8>> {
        let client_response: ClientResponse = from_str(response_text).map_err(|e| {
            TransmitError::SerializationError(format!("Failed to parse XML response: {}", e))
        })?;

        hex::decode(&client_response.output_apdu)
            .map_err(|e| TransmitError::InvalidApdu(format!("Failed to decode APDU hex: {}", e)))
    }

    /// Sends a single HTTP request to the eID-Client
    async fn send_request(&self, xml_payload: &str) -> TransmitResult<String> {
        let response = self
            .client
            .post(&self.config.client_url)
            .header("Content-Type", "application/xml")
            .body(xml_payload.to_string())
            .send()
            .await
            .map_err(|e| TransmitError::NetworkError(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(TransmitError::NetworkError(format!(
                "HTTP request failed with status: {}",
                status
            )));
        }

        response.text().await.map_err(|e| {
            TransmitError::NetworkError(format!("Failed to read response body: {}", e))
        })
    }
}

#[async_trait]
impl TransmitService for HttpTransmitService {
    async fn transmit_apdu(&self, apdu: Vec<u8>, slot_handle: &str) -> TransmitResult<Vec<u8>> {
        // Serialize the request
        let xml_payload = self.serialize_request(&apdu, slot_handle)?;

        // Send request with retries
        let mut retries = 0;
        let mut last_error = None;

        while retries < self.config.max_retries {
            match self.send_request(&xml_payload).await {
                Ok(response_text) => {
                    // Parse and return the response
                    return self.parse_response(&response_text);
                }
                Err(e) => {
                    error!("APDU transmission attempt {} failed: {}", retries + 1, e);
                    last_error = Some(e);
                    retries += 1;
                }
            }
        }

        // All retries failed
        Err(last_error
            .unwrap_or_else(|| TransmitError::TransmissionFailed("All retries failed".to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transmit_service_config_from_transmit_config() {
        let transmit_config = TransmitConfig {
            client_url: "http://test.example.com".to_string(),
            session_timeout_secs: 60,
            max_apdu_size: 4096,
            allowed_cipher_suites: vec!["TLS_AES_128_GCM_SHA256".to_string()],
            max_requests_per_minute: 60,
            require_client_certificate: true,
            min_tls_version: "TLSv1.2".to_string(),
        };

        let service_config = TransmitServiceConfig::from(transmit_config);
        assert_eq!(service_config.client_url, "http://test.example.com");
        assert_eq!(service_config.session_timeout_secs, 60);
        assert_eq!(service_config.max_retries, 3);
    }

    #[test]
    fn test_serialize_request() {
        let config = TransmitServiceConfig {
            client_url: "http://test.example.com".to_string(),
            session_timeout_secs: 30,
            max_retries: 3,
        };

        let service = HttpTransmitService::new(config).expect("Service creation should succeed");
        let apdu = vec![0x00, 0xA4, 0x04, 0x00];
        let slot_handle = "test-slot";

        let xml = service
            .serialize_request(&apdu, slot_handle)
            .expect("Serialization should succeed");

        assert!(xml.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("<SlotHandle>test-slot</SlotHandle>"));
        assert!(xml.contains("<InputAPDU>00A40400</InputAPDU>"));
    }

    #[test]
    fn test_parse_response() {
        let config = TransmitServiceConfig {
            client_url: "http://test.example.com".to_string(),
            session_timeout_secs: 30,
            max_retries: 3,
        };

        let service = HttpTransmitService::new(config).expect("Service creation should succeed");
        let response_xml = r#"<TransmitResponse><OutputAPDU>9000</OutputAPDU></TransmitResponse>"#;

        let result = service
            .parse_response(response_xml)
            .expect("Parsing should succeed");
        assert_eq!(result, vec![0x90, 0x00]);
    }
}
