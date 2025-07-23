use quick_xml::de::from_str;
use serde::de::DeserializeOwned;

use super::envelope::{SoapBody, SoapEnvelope};
use super::error::{ErrorKind, SoapError};
use crate::eid::get_result::model::GetResultRequest;

pub trait SoapRequest: DeserializeOwned {
    fn root_element() -> &'static str;
}

impl SoapRequest for GetResultRequest {
    fn root_element() -> &'static str {
        "eid:getResultRequest"
    }
}

pub fn deserialize_soap<T: SoapRequest>(xml: &str, root_element: &str) -> Result<T, SoapError> {
    let xml = xml.trim();

    if root_element != T::root_element() {
        return Err(SoapError::XmlError {
            kind: ErrorKind::Deserialization,
            path: Some(root_element.to_string()),
            message: "Unsupported root element".to_string(),
        });
    }

    let envelope: SoapEnvelope<SoapBody<T>> = from_str(xml).map_err(|e| SoapError::XmlError {
        kind: ErrorKind::Deserialization,
        path: Some(root_element.to_string()),
        message: format!("Failed to deserialize XML: {e}"),
    })?;

    Ok(envelope.body.request)
}
