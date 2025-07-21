use crate::domain::eid::ports::TransmitError;
use quick_xml::{de::from_str, se::to_string as to_xml_string};
use serde::{Deserialize, Serialize};

/// Namespace constants according to ISO 24727-3 and eCard-API Framework
pub const ISO24727_3_NS: &str = "urn:iso:std:iso-iec:24727:tech:schema";
pub const ECARDAPI_NS: &str = "http://www.bsi.bund.de/ecard/api/1.1";

/// Status code constants
pub const APDU_SUCCESS_STATUS: &str = "9000";

/// Result major constants
pub const RESULT_MAJOR_OK: &str = "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok";
pub const RESULT_MAJOR_ERROR: &str = "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error";

/// Result minor constants
pub const RESULT_MINOR_GENERAL_ERROR: &str =
    "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#generalError";

// MinorCode implementation moved to result_codes.rs

/// Result structure as defined in TR-03112 Part 1, Section A
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TransmitResult {
    pub result_major: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_minor: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_message: Option<String>,
}

impl TransmitResult {
    pub fn ok() -> Self {
        Self {
            result_major: RESULT_MAJOR_OK.to_string(),
            result_minor: None,
            result_message: None,
        }
    }

    pub fn error(minor_code: &str, message: Option<String>) -> Self {
        Self {
            result_major: RESULT_MAJOR_ERROR.to_string(),
            result_minor: Some(minor_code.to_string()),
            result_message: message,
        }
    }
}

/// Represents a parsed request from the eID-Client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedRequest {
    pub request_type: String,
    pub session_id: Option<String>,
    pub data: Option<String>,
}

/// Represents a response to be sent to the eID-Client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub status: String,
    pub session_id: Option<String>,
    pub data: Option<String>,
}

/// Represents a Transmit request from the eID-Client according to ISO 24727-3
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "Transmit")]
#[serde(rename_all = "PascalCase")]
pub struct Transmit {
    #[serde(rename = "SlotHandle")]
    pub slot_handle: String,

    #[serde(rename = "InputAPDUInfo")]
    pub input_apdu_info: Vec<InputAPDUInfo>,

    // Additional fields that may be present according to specs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclusive: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// Represents an APDU request from the eID-Client according to ISO 24727-3
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct InputAPDUInfo {
    #[serde(rename = "InputAPDU")]
    pub input_apdu: String,

    #[serde(
        rename = "AcceptableStatusCode",
        skip_serializing_if = "Option::is_none"
    )]
    pub acceptable_status_code: Option<String>,

    // According to TR-03130, timeout is also part of the specification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
}

/// Represents a Transmit response to be sent to the eID-Client according to ISO 24727-3
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "TransmitResponse")]
#[serde(rename_all = "PascalCase")]
pub struct TransmitResponse {
    pub result: TransmitResult,

    #[serde(rename = "OutputAPDU", skip_serializing_if = "Vec::is_empty")]
    pub output_apdu: Vec<String>,
}

/// Handles the protocol communication between eID-Client and eID-Server
/// according to ISO 24727-3 and eCard-API Framework specifications
#[derive(Clone, Debug)]
pub struct ProtocolHandler {
    // Configuration parameters according to TR-03130
    pub protocol_version: String,
    pub namespace: String,
    pub schema_location: String,
}

impl ProtocolHandler {
    /// Creates a new protocol handler with default configuration
    pub fn new() -> Self {
        Self {
            protocol_version: "1.1.5".to_string(),
            namespace: ISO24727_3_NS.to_string(), // ISO 24727-3 namespace
            schema_location: format!("{} {}", ISO24727_3_NS, "iso-24727-3.xsd"),
        }
    }

    /// Creates a simple Transmit request with a single APDU
    /// This is a convenience method for creating single-APDU requests
    pub fn create_single_apdu_request(
        slot_handle: &str,
        apdu_hex: &str,
        acceptable_status_code: Option<&str>,
    ) -> Transmit {
        Transmit {
            slot_handle: slot_handle.to_string(),
            input_apdu_info: vec![InputAPDUInfo {
                input_apdu: apdu_hex.to_string(),
                acceptable_status_code: acceptable_status_code.map(|s| s.to_string()),
                timeout: None,
            }],
            exclusive: None,
            protocol: None,
        }
    }

    /// Serializes a Transmit request to XML format with proper namespaces
    pub fn serialize_transmit_request(&self, transmit: &Transmit) -> Result<String, TransmitError> {
        // Serialize the main body with Serde
        let mut xml = to_xml_string(transmit)
            .map_err(|e| TransmitError::TransmitError(format!("XML serialization error: {e}")))?;

        // Inject namespaces into the root tag
        xml = xml.replacen(
            "<Transmit>",
            &format!("<Transmit xmlns=\"{}\">", self.namespace),
            1,
        );

        // Prepend XML declaration
        Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>{xml}"))
    }

    /// Creates a new protocol handler with custom configuration
    pub fn with_config(protocol_version: &str, namespace: &str, schema_location: &str) -> Self {
        Self {
            protocol_version: protocol_version.to_string(),
            namespace: namespace.to_string(),
            schema_location: schema_location.to_string(),
        }
    }

    /// Parses a request from the eID-Client
    pub fn parse_request(&self, request: &[u8]) -> Result<ParsedRequest, TransmitError> {
        serde_json::from_slice(request)
            .map_err(|e| TransmitError::TransmitError(format!("Failed to parse request: {e}")))
    }

    /// Formats a response to be sent to the eID-Client
    pub fn format_response(&self, response: Response) -> Result<Vec<u8>, TransmitError> {
        serde_json::to_vec(&response)
            .map_err(|e| TransmitError::TransmitError(format!("Failed to format response: {e}")))
    }

    /// Processes data from the eID-Client
    pub fn process_data(&self, data: Option<String>) -> Result<String, TransmitError> {
        data.ok_or_else(|| TransmitError::TransmitError("No data provided".to_string()))
    }

    /// Parses a Transmit request from the eID-Client with XML namespace handling
    /// according to ISO 24727-3 and eCard-API Framework specifications
    pub fn parse_transmit(&self, xml: &str) -> Result<Transmit, TransmitError> {
        // Parse XML with namespace awareness
        from_str(xml).map_err(|e| {
            // Map quick_xml errors to our TransmitError
            TransmitError::TransmitError(format!("Malformed XML: {e}"))
        })
    }

    /// Formats a Transmit response to be sent to the eID-Client
    /// with proper XML namespaces according to ISO 24727-3
    pub fn format_transmit_response(
        &self,
        response: &TransmitResponse,
    ) -> Result<String, TransmitError> {
        // Serialize the main body with Serde
        let mut xml = to_xml_string(response)
            .map_err(|e| TransmitError::TransmitError(format!("XML serialization error: {e}")))?;
        // Inject namespaces and schema location into the root tag
        xml = xml.replacen(
            "<TransmitResponse>",
            &format!(
                "<TransmitResponse xmlns=\"{}\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"{}\">",
                self.namespace, self.schema_location
            ),
            1,
        );
        // Prepend XML declaration
        let mut result = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        result.push_str(&xml);
        Ok(result)
    }

    /// Validates the request version against the protocol version
    pub fn validate_version(&self, request_version: &str) -> Result<(), TransmitError> {
        // Version validation according to TR-03130 requirements
        let req_parts: Vec<&str> = request_version.split('.').collect();
        let our_parts: Vec<&str> = self.protocol_version.split('.').collect();

        // Check major version - must match exactly
        if req_parts.first() != our_parts.first() {
            return Err(TransmitError::TransmitError(format!(
                "Incompatible protocol major version: {} vs {}",
                request_version, self.protocol_version
            )));
        }

        // Check minor version - our minor version must be >= requested minor version
        if let (Some(req_minor), Some(our_minor)) = (req_parts.get(1), our_parts.get(1)) {
            if let (Ok(req_minor_num), Ok(our_minor_num)) =
                (req_minor.parse::<u32>(), our_minor.parse::<u32>())
            {
                if our_minor_num < req_minor_num {
                    return Err(TransmitError::TransmitError(format!(
                        "Incompatible protocol minor version: {} vs {}",
                        request_version, self.protocol_version
                    )));
                }
            }
        }

        Ok(())
    }

    /// Converts a TransmitError into a proper TransmitResult for the XML response
    pub fn error_to_result(&self, error: &TransmitError) -> TransmitResult {
        match error {
            TransmitError::TransmitError(msg) => TransmitResult::error(
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#transmitError",
                Some(msg.clone()),
            ),
            TransmitError::InternalError(msg) => TransmitResult::error(
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#internalError",
                Some(msg.clone()),
            ),
        }
    }
}

impl Default for ProtocolHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malformed_xml_handling() {
        let handler = ProtocolHandler::new();
        let malformed_xml = "<Transmit><SlotHandle>abc</SlotHandle><InputAPDUInfo></Transmit>";
        let result = handler.parse_transmit(malformed_xml);
        assert!(result.is_err(), "Malformed XML should return an error");
    }

    #[test]
    fn test_transmit_result_ok() {
        let result = TransmitResult::ok();
        assert_eq!(
            result.result_major,
            "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok"
        );
        assert!(result.result_minor.is_none());
        assert!(result.result_message.is_none());
    }

    #[test]
    fn test_transmit_result_error() {
        let result = TransmitResult::error(
            "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#invalidRequest",
            Some("Test error".to_string()),
        );
        assert_eq!(
            result.result_major,
            "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error"
        );
        assert_eq!(
            result.result_minor,
            Some("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#invalidRequest".to_string())
        );
        assert_eq!(result.result_message, Some("Test error".to_string()));
    }

    #[test]
    fn test_protocol_handler_version_validation() {
        let handler = ProtocolHandler::new();
        assert!(handler.validate_version("1.1.5").is_ok());
        assert!(handler.validate_version("1.1.0").is_ok());
        assert!(handler.validate_version("1.2.0").is_err());
        assert!(handler.validate_version("2.0.0").is_err());
    }

    #[test]
    fn test_format_transmit_response() {
        let handler = ProtocolHandler::new();

        // Create a successful response
        let response = TransmitResponse {
            result: TransmitResult::ok(),
            output_apdu: vec!["9000".to_string(), "010203049000".to_string()],
        };

        // Format the response
        let xml = handler
            .format_transmit_response(&response)
            .expect("Response formatting should succeed");

        // Verify XML structure (simplified check)
        assert!(xml.contains("<?xml version=\"1.0\" encoding=\"UTF-8\""));
        assert!(xml.contains("xmlns=\""));
        assert!(xml.contains("<ResultMajor>"));
        assert!(xml.contains("<OutputAPDU>9000</OutputAPDU>"));
        assert!(xml.contains("<OutputAPDU>010203049000</OutputAPDU>"));
    }

    #[test]
    fn test_parse_transmit_request() {
        let handler = ProtocolHandler::new();

        // Create a valid Transmit request XML
        let xml = format!(
            r#"<Transmit xmlns="{ISO24727_3_NS}">  
            <SlotHandle>slot-123</SlotHandle>
            <InputAPDUInfo>
                <InputAPDU>00A4040008A000000167455349</InputAPDU>
                <AcceptableStatusCode>9000</AcceptableStatusCode>
            </InputAPDUInfo>
            <InputAPDUInfo>
                <InputAPDU>00B0000000</InputAPDU>
            </InputAPDUInfo>
        </Transmit>"#,
        );

        // Parse the request
        let result = handler.parse_transmit(&xml);
        assert!(result.is_ok(), "Valid XML should parse successfully");

        let transmit = result.expect("Valid XML should parse successfully");
        assert_eq!(transmit.slot_handle, "slot-123");
        assert_eq!(transmit.input_apdu_info.len(), 2);
        assert_eq!(
            transmit.input_apdu_info[0].input_apdu,
            "00A4040008A000000167455349"
        );
        assert_eq!(
            transmit.input_apdu_info[0].acceptable_status_code,
            Some("9000".to_string())
        );
        assert_eq!(transmit.input_apdu_info[1].input_apdu, "00B0000000");
        assert!(transmit.input_apdu_info[1].acceptable_status_code.is_none());
    }
}
