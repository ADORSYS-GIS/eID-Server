use super::{
    error::TransmitError,
    result_codes::{MajorCode, MinorCode},
};
use quick_xml::{
    Writer,
    de::from_str,
    events::{BytesEnd, BytesStart, BytesText, Event},
};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

/// Namespace constants according to ISO 24727-3 and eCard-API Framework
pub const ISO24727_3_NS: &str = "urn:iso:std:iso-iec:24727:tech:schema";
pub const ECARDAPI_NS: &str = "http://www.bsi.bund.de/ecard/api/1.1";

// MinorCode implementation moved to result_codes.rs

/// Result structure as defined in TR-03112 Part 1, Section A
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransmitResult {
    #[serde(rename = "ResultMajor")]
    pub result_major: String,

    #[serde(rename = "ResultMinor", skip_serializing_if = "Option::is_none")]
    pub result_minor: Option<String>,

    #[serde(rename = "ResultMessage", skip_serializing_if = "Option::is_none")]
    pub result_message: Option<String>,
}

impl TransmitResult {
    pub fn new(major: MajorCode, minor: MinorCode, message: Option<String>) -> Self {
        let result_minor = if minor == MinorCode::None {
            None
        } else {
            Some(minor.to_string())
        };

        Self {
            result_major: major.to_string(),
            result_minor,
            result_message: message,
        }
    }

    pub fn ok() -> Self {
        Self::new(MajorCode::Ok, MinorCode::None, None)
    }

    pub fn error(minor: MinorCode, message: Option<String>) -> Self {
        Self::new(MajorCode::Error, minor, message)
    }

    pub fn warning(minor: MinorCode, message: Option<String>) -> Self {
        Self::new(MajorCode::Warning, minor, message)
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
            protocol_version: "1.1.5".to_string(), // Version according to eCard-API Framework
            namespace: ISO24727_3_NS.to_string(),  // ISO 24727-3 namespace
            schema_location: format!("{} {}", ISO24727_3_NS, "iso-24727-3.xsd"),
        }
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
            .map_err(|e| TransmitError::ProtocolError(format!("Failed to parse request: {}", e)))
    }

    /// Formats a response to be sent to the eID-Client
    pub fn format_response(&self, response: Response) -> Result<Vec<u8>, TransmitError> {
        serde_json::to_vec(&response)
            .map_err(|e| TransmitError::ProtocolError(format!("Failed to format response: {}", e)))
    }

    /// Processes data from the eID-Client
    pub fn process_data(&self, data: Option<String>) -> Result<String, TransmitError> {
        data.ok_or_else(|| TransmitError::InvalidRequest("No data provided".to_string()))
    }

    /// Parses a Transmit request from the eID-Client with XML namespace handling
    /// according to ISO 24727-3 and eCard-API Framework specifications
    pub fn parse_transmit(&self, xml: &str) -> Result<Transmit, TransmitError> {
        // Parse XML with namespace awareness
        from_str(xml).map_err(|e| {
            // Map quick_xml errors to our TransmitError
            TransmitError::InvalidRequest(format!("Malformed XML: {}", e))
        })
    }

    /// Formats a Transmit response to be sent to the eID-Client
    /// with proper XML namespaces according to ISO 24727-3
    pub fn format_transmit_response(
        &self,
        response: &TransmitResponse,
    ) -> Result<String, TransmitError> {
        // Create a new XML writer with a cursor as output
        let mut writer = Writer::new_with_indent(Cursor::new(Vec::new()), b' ', 2);

        // Write XML declaration
        writer
            .write_event(Event::Decl(quick_xml::events::BytesDecl::new(
                "1.0",
                Some("UTF-8"),
                None,
            )))
            .map_err(|e| TransmitError::ProtocolError(format!("XML writing error: {}", e)))?;

        // Create the root element with namespaces
        let mut root = BytesStart::new("TransmitResponse");
        root.push_attribute(("xmlns", self.namespace.as_str()));
        root.push_attribute(("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance"));
        root.push_attribute(("xsi:schemaLocation", self.schema_location.as_str()));

        // Write root element start
        writer
            .write_event(Event::Start(root))
            .map_err(|e| TransmitError::ProtocolError(format!("XML writing error: {}", e)))?;

        // Write Result element
        let result_start = BytesStart::new("Result");
        writer
            .write_event(Event::Start(result_start))
            .map_err(|e| TransmitError::ProtocolError(format!("XML writing error: {}", e)))?;

        // Write ResultMajor
        writer
            .write_event(Event::Start(BytesStart::new("ResultMajor")))
            .map_err(|e| TransmitError::ProtocolError(format!("XML writing error: {}", e)))?;
        writer
            .write_event(Event::Text(BytesText::new(&response.result.result_major)))
            .map_err(|e| TransmitError::ProtocolError(format!("XML writing error: {}", e)))?;
        writer
            .write_event(Event::End(BytesEnd::new("ResultMajor")))
            .map_err(|e| TransmitError::ProtocolError(format!("XML writing error: {}", e)))?;

        // Write ResultMinor if present
        if let Some(minor) = &response.result.result_minor {
            writer
                .write_event(Event::Start(BytesStart::new("ResultMinor")))
                .map_err(|e| TransmitError::ProtocolError(format!("XML writing error: {}", e)))?;
            writer
                .write_event(Event::Text(BytesText::new(minor)))
                .map_err(|e| TransmitError::ProtocolError(format!("XML writing error: {}", e)))?;
            writer
                .write_event(Event::End(BytesEnd::new("ResultMinor")))
                .map_err(|e| TransmitError::ProtocolError(format!("XML writing error: {}", e)))?;
        }

        // Write ResultMessage if present
        if let Some(message) = &response.result.result_message {
            writer
                .write_event(Event::Start(BytesStart::new("ResultMessage")))
                .map_err(|e| TransmitError::ProtocolError(format!("XML writing error: {}", e)))?;
            writer
                .write_event(Event::Text(BytesText::new(message)))
                .map_err(|e| TransmitError::ProtocolError(format!("XML writing error: {}", e)))?;
            writer
                .write_event(Event::End(BytesEnd::new("ResultMessage")))
                .map_err(|e| TransmitError::ProtocolError(format!("XML writing error: {}", e)))?;
        }

        // Close Result element
        writer
            .write_event(Event::End(BytesEnd::new("Result")))
            .map_err(|e| TransmitError::ProtocolError(format!("XML writing error: {}", e)))?;

        // Write OutputAPDU elements
        for apdu in &response.output_apdu {
            writer
                .write_event(Event::Start(BytesStart::new("OutputAPDU")))
                .map_err(|e| TransmitError::ProtocolError(format!("XML writing error: {}", e)))?;
            writer
                .write_event(Event::Text(BytesText::new(apdu)))
                .map_err(|e| TransmitError::ProtocolError(format!("XML writing error: {}", e)))?;
            writer
                .write_event(Event::End(BytesEnd::new("OutputAPDU")))
                .map_err(|e| TransmitError::ProtocolError(format!("XML writing error: {}", e)))?;
        }

        // Close root element
        writer
            .write_event(Event::End(BytesEnd::new("TransmitResponse")))
            .map_err(|e| TransmitError::ProtocolError(format!("XML writing error: {}", e)))?;

        // Get the resulting XML as a string
        let result = writer.into_inner().into_inner();
        String::from_utf8(result)
            .map_err(|e| TransmitError::ProtocolError(format!("Invalid UTF-8 in XML: {}", e)))
    }

    /// Validates the request version against the protocol version
    pub fn validate_version(&self, request_version: &str) -> Result<(), TransmitError> {
        // Version validation according to TR-03130 requirements
        let req_parts: Vec<&str> = request_version.split('.').collect();
        let our_parts: Vec<&str> = self.protocol_version.split('.').collect();

        // Check major version - must match exactly
        if req_parts.get(0) != our_parts.get(0) {
            return Err(TransmitError::ProtocolError(format!(
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
                    return Err(TransmitError::ProtocolError(format!(
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
            TransmitError::InvalidRequest(_) => {
                TransmitResult::error(MinorCode::ParameterError, Some(error.to_string()))
            }

            TransmitError::ProtocolError(_) => {
                TransmitResult::error(MinorCode::InternalError, Some(error.to_string()))
            }

            TransmitError::SessionError(_) => {
                TransmitResult::error(MinorCode::InvalidContext, Some(error.to_string()))
            }

            TransmitError::InvalidStatusCode { .. } => {
                TransmitResult::error(MinorCode::CardError, Some(error.to_string()))
            }

            TransmitError::CardError(_) => {
                TransmitResult::error(MinorCode::CardError, Some(error.to_string()))
            }

            TransmitError::InternalError(_) => {
                TransmitResult::error(MinorCode::InternalError, Some(error.to_string()))
            }
        }
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
    fn test_protocol_result_ok() {
        // Test the OK result creation
        let result = TransmitResult::ok();
        assert_eq!(result.result_major, MajorCode::Ok.to_string());
        assert!(result.result_minor.is_none());
        assert!(result.result_message.is_none());
    }

    #[test]
    fn test_protocol_result_error() {
        // Test error result creation with minor code
        let message = "Test error message";
        let result = TransmitResult::error(MinorCode::CardError, Some(message.to_string()));

        assert_eq!(result.result_major, MajorCode::Error.to_string());
        assert!(result.result_minor.is_some());
        assert_eq!(
            result.result_minor.unwrap(),
            MinorCode::CardError.to_string()
        );
        assert_eq!(result.result_message.unwrap(), message);
    }

    #[test]
    fn test_protocol_version_validation() {
        // Create protocol handler with version 1.1.5
        let handler = ProtocolHandler::new();

        // Test compatible version - exact match
        assert!(handler.validate_version("1.1.5").is_ok());

        // Test compatible version - client requesting older minor version
        assert!(handler.validate_version("1.1.0").is_ok());

        // Test incompatible version - client requesting newer minor version
        assert!(handler.validate_version("1.2.0").is_err());

        // Test incompatible version - different major version
        assert!(handler.validate_version("2.0.0").is_err());
    }

    #[test]
    fn test_error_to_result_mapping() {
        let handler = ProtocolHandler::new();

        // Test mapping for InvalidRequest
        let err = TransmitError::InvalidRequest("Test error".to_string());
        let result = handler.error_to_result(&err);
        assert_eq!(result.result_major, MajorCode::Error.to_string());
        assert_eq!(
            result.result_minor.unwrap(),
            MinorCode::ParameterError.to_string()
        );

        // Test mapping for CardError
        let err = TransmitError::CardError("Card error".to_string());
        let result = handler.error_to_result(&err);
        assert_eq!(result.result_major, MajorCode::Error.to_string());
        assert_eq!(
            result.result_minor.unwrap(),
            MinorCode::CardError.to_string()
        );
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
        let xml = handler.format_transmit_response(&response).unwrap();

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
            r#"<Transmit xmlns="{}">  
            <SlotHandle>slot-123</SlotHandle>
            <InputAPDUInfo>
                <InputAPDU>00A4040008A000000167455349</InputAPDU>
                <AcceptableStatusCode>9000</AcceptableStatusCode>
            </InputAPDUInfo>
            <InputAPDUInfo>
                <InputAPDU>00B0000000</InputAPDU>
            </InputAPDUInfo>
        </Transmit>"#,
            ISO24727_3_NS
        );

        // Parse the request
        let result = handler.parse_transmit(&xml);
        assert!(result.is_ok(), "Valid XML should parse successfully");

        let transmit = result.unwrap();
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
