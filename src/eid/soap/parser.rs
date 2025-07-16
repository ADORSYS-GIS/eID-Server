use quick_xml::de::from_str;

use super::envelope::{SoapBody, SoapEnvelope};
use super::error::SoapError;
use crate::eid::get_result::model::GetResultRequest;
use crate::eid::use_id::model::UseIDRequest;

pub fn deserialize_soap<T: for<'de> serde::Deserialize<'de> + 'static>(
    xml: &str,
    root_element: &str,
) -> Result<T, SoapError> {
    // Normalize XML by removing extra whitespace
    let xml = xml.trim().replace("\n", "").replace("> <", "><");

    match root_element {
        "eid:getResultRequest" => {
            let envelope: SoapEnvelope<SoapBody<GetResultRequest>> =
                from_str(&xml).map_err(|e| SoapError::DeserializationError {
                    path: root_element.to_string(),
                    message: format!("Failed to deserialize XML: {}", e),
                })?;
            eprintln!("Deserialized envelope: {:?}", envelope);
            if std::any::TypeId::of::<T>() != std::any::TypeId::of::<GetResultRequest>() {
                return Err(SoapError::DeserializationError {
                    path: root_element.to_string(),
                    message: "Type mismatch: expected GetResultRequest".to_string(),
                });
            }
            Ok(unsafe { std::mem::transmute_copy(&envelope.body.request) })
        }
        "eid:useIDRequest" => {
            let envelope: SoapEnvelope<SoapBody<UseIDRequest>> =
                from_str(&xml).map_err(|e| SoapError::DeserializationError {
                    path: root_element.to_string(),
                    message: format!("Failed to deserialize XML: {}", e),
                })?;
            eprintln!("Deserialized envelope: {:?}", envelope);
            if std::any::TypeId::of::<T>() != std::any::TypeId::of::<UseIDRequest>() {
                return Err(SoapError::DeserializationError {
                    path: root_element.to_string(),
                    message: "Type mismatch: expected UseIDRequest".to_string(),
                });
            }
            Ok(unsafe { std::mem::transmute_copy(&envelope.body.request) })
        }
        _ => Err(SoapError::DeserializationError {
            path: root_element.to_string(),
            message: "Unsupported root element".to_string(),
        }),
    }
}
