// helper.rs
use quick_xml::{de::from_str, se::to_string};
use serde::de::DeserializeOwned;

use super::{envelope::SoapResponseEnvelope, error::SoapError};

pub fn serialize_soap_response<T: serde::Serialize>(response: T) -> Result<String, SoapError> {
    use crate::eid::common::models::Header;

    let envelope = SoapResponseEnvelope {
        header: Header::default(),
        body: super::envelope::SoapResponseBody { response },
    };

    let xml = to_string(&envelope).map_err(|e| SoapError::SerializationError(e.to_string()))?;

    let xml_with_ns = xml.replacen(
        "<soapenv:Envelope",
        "<soapenv:Envelope \
         xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         xmlns:eid=\"http://bsi.bund.de/eID/\" \
         xmlns:dss=\"urn:oasis:names:tc:dss:1.0:core:schema\"",
        1,
    );

    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>{xml_with_ns}"
    ))
}

pub fn deserialize_soap_request<T: for<'de> serde::Deserialize<'de>>(
    xml: &str,
) -> Result<T, SoapError> {
    use super::envelope::SoapRequestEnvelope;
    let trimmed_xml = xml.trim();
    eprintln!("Deserializing XML: {}", trimmed_xml); // Debug print
    let envelope: SoapRequestEnvelope<T> =
        from_str(trimmed_xml).map_err(|e| {
            eprintln!("Deserialization error details: {:?}", e); // Detailed error logging
            SoapError::DeserializationError {
                path: "Envelope".to_string(),
                message: e.to_string(),
                source: Some(e),
            }
        })?;
    Ok(envelope.body.request)
}
// Helper for deserializing complex nested elements with better error context
pub fn deserialize_element<T: DeserializeOwned>(
    xml: &str,
    element_name: &str,
) -> Result<T, SoapError> {
    from_str(xml).map_err(|e| SoapError::DeserializationError {
        path: element_name.to_string(),
        message: e.to_string(),
        source: Some(e),
    })
}
