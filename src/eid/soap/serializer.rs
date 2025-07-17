use quick_xml::se::to_string;

use super::envelope::{SoapBody, SoapEnvelope};
use super::error::SoapError;
use crate::eid::common::models::Header;

pub fn serialize_soap<T: serde::Serialize>(
    body: T,
    include_dss_namespace: bool,
) -> Result<String, SoapError> {
    let envelope = SoapEnvelope {
        header: Some(Header::default()),
        body: SoapBody { request: body },
    };

    let xml = to_string(&envelope).map_err(|e| SoapError::SerializationError(e.to_string()))?;

    let namespaces = if include_dss_namespace {
        "<soapenv:Envelope \
         xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         xmlns:eid=\"http://bsi.bund.de/eID/\" \
         xmlns:dss=\"urn:oasis:names:tc:dss:1.0:core:schema\""
    } else {
        "<soapenv:Envelope \
         xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         xmlns:eid=\"http://bsi.bund.de/eID/\""
    };

    let xml_with_ns = xml.replacen("<soapenv:Envelope", namespaces, 1);

    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>{xml_with_ns}"
    ))
}
