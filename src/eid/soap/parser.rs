use quick_xml::de::from_str;

use crate::eid::{
    get_result::model::GetResultRequest,
    soap::{envelope::SoapEnvelope, error::SoapError},
    use_id::model::UseIDRequest,
};

pub fn deserialize_soap<T: for<'de> serde::Deserialize<'de>>(
    xml: &str,
    root_element: &str,
) -> Result<T, SoapError> {
    let xml = xml.trim();
    // Log the XML for debugging
    tracing::debug!("Deserializing XML: {}", xml);
    
    match root_element {
        "eid:getResultRequest" => {
            let envelope: SoapEnvelope<GetResultRequest> =
                from_str(xml).map_err(|e| SoapError::DeserializationError {
                    path: root_element.to_string(),
                    message: format!("Failed to deserialize XML: {}. Input XML: {}", e, xml),
                })?;
            Ok(unsafe { std::mem::transmute_copy(&envelope.body.request) })
        }
        "eid:useIDRequest" => {
            let envelope: SoapEnvelope<UseIDRequest> =
                from_str(xml).map_err(|e| SoapError::DeserializationError {
                    path: root_element.to_string(),
                    message: format!("Failed to deserialize XML: {}. Input XML: {}", e, xml),
                })?;
            Ok(unsafe { std::mem::transmute_copy(&envelope.body.request) })
        }
        _ => Err(SoapError::DeserializationError {
            path: root_element.to_string(),
            message: "Unsupported root element".to_string(),
        }),
    }
}