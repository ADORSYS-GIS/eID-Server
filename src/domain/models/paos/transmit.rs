use serde::{Deserialize, Serialize};

use crate::domain::models::ResultType;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Transmit {
    #[serde(rename = "SlotHandle")]
    pub slot_handle: String,
    #[serde(rename = "InputAPDUInfo", default)]
    pub input_apdus: Vec<InputAPDUInfo>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct InputAPDUInfo {
    #[serde(rename = "InputAPDU")]
    pub input_apdu: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "AcceptableStatusCode")]
    pub accept_statuses: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct TransmitResponse {
    #[serde(rename = "Result")]
    pub result: ResultType,
    #[serde(rename = "OutputAPDU", default)]
    pub output_apdus: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soap::{Envelope, Header};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TransmitReq {
        #[serde(rename = "Transmit")]
        pub transmit: Transmit,
    }

    #[test]
    fn test_transmit_parsing() {
        let req = include_str!("../../../../test_data/eid/transmit.xml");
        let result = Envelope::<Transmit>::parse(req);
        assert!(result.is_ok());

        let request = result.unwrap();
        assert!(request.header().is_some());
        assert!(request.header().as_ref().unwrap().message_id.is_some());
        assert!(request.header().as_ref().unwrap().relates_to.is_some());
        assert!(request.body().slot_handle == "00");
        assert!(request.body().input_apdus.len() == 3);
    }

    #[test]
    fn test_transmit_serialization() {
        let req = TransmitReq {
            transmit: Transmit {
                slot_handle: "00".to_string(),
                input_apdus: vec![InputAPDUInfo {
                    input_apdu: "000000000000".into(),
                    accept_statuses: None,
                }],
            },
        };
        let header = Header {
            message_id: Some("12345678-1234-1234-1234-123456789012".to_string()),
            relates_to: Some("12345678-1234-1234-1234-123456789012".to_string()),
        };
        let result = Envelope::new(req).with_header(header).serialize_paos(true);
        assert!(result.is_ok());
        assert!(
            result
                .as_ref()
                .unwrap()
                .contains("<SlotHandle>00</SlotHandle>")
        );
        assert!(result.as_ref().unwrap().contains("<InputAPDUInfo>"));
    }

    #[test]
    fn test_transmit_response_parsing() {
        let req = include_str!("../../../../test_data/eid/transmitResponse.xml");
        let result = Envelope::<TransmitResponse>::parse(req);
        assert!(result.is_ok());

        let request = result.unwrap();
        assert!(request.header().is_some());
        assert!(request.header().as_ref().unwrap().message_id.is_some());
        assert!(request.header().as_ref().unwrap().relates_to.is_some());
        assert!(request.body().result.result_major.contains("#ok"));
        assert!(request.body().output_apdus.len() == 3);
    }
}
