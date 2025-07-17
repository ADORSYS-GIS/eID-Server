use quick_xml::de::from_str;
use serde::de::DeserializeOwned;

use super::envelope::{SoapBody, SoapEnvelope};
use super::error::SoapError;
use crate::eid::get_result::model::GetResultRequest;

pub fn deserialize_soap<T: DeserializeOwned + 'static>(
    xml: &str,
    root_element: &str,
) -> Result<T, SoapError> {
    // Normalize XML minimally to avoid breaking structure
    let xml = xml.trim();

    match root_element {
        "eid:getResultRequest" => {
            let envelope: SoapEnvelope<SoapBody<GetResultRequest>> =
                from_str(xml).map_err(|e| SoapError::DeserializationError {
                    path: root_element.to_string(),
                    message: format!("Failed to deserialize XML: {e}"),
                })?;
            eprintln!("Deserialized getResultRequest envelope: {envelope:?}");
            Ok(unsafe { std::mem::transmute_copy(&envelope.body.request) })
        }
        _ => Err(SoapError::DeserializationError {
            path: root_element.to_string(),
            message: "Unsupported root element".to_string(),
        }),
    }
}