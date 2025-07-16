use quick_xml::de::from_str;

use super::envelope::{SoapEnvelope, SoapBody};
use super::error::SoapError;
use crate::eid::get_result::model::GetResultRequest;
use crate::eid::use_id::model::UseIDRequest;

pub fn deserialize_soap<T: for<'de> serde::Deserialize<'de>>(
    xml: &str,
    root_element: &str,
) -> Result<T, SoapError> {
    let xml = xml.trim();
    
    match root_element {
        "eid:getResultRequest" => {
            let envelope: SoapEnvelope<SoapBody<GetResultRequest>> = from_str(xml)
                .map_err(|e| SoapError::DeserializationError {
                    path: root_element.to_string(),
                    message: format!("Failed to deserialize XML: {}", e),
                })?;
            Ok(unsafe { std::mem::transmute_copy(&envelope.body.request) })
        }
        "eid:useIDRequest" => {
            let envelope: SoapEnvelope<SoapBody<UseIDRequest>> = from_str(xml)
                .map_err(|e| SoapError::DeserializationError {
                    path: root_element.to_string(),
                    message: format!("Failed to deserialize XML: {}", e),
                })?;
            Ok(unsafe { std::mem::transmute_copy(&envelope.body.request) })
        }
        _ => Err(SoapError::DeserializationError {
            path: root_element.to_string(),
            message: "Unsupported root element".to_string(),
        }),
    }
}