use super::envelope::SoapBody;
use super::error::{ErrorKind, SoapError};
use crate::eid::common::models::Header;
use quick_xml::se::to_string;
use serde::Serialize;

// Define namespace constants
const SOAPENV_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const EID_NS: &str = "http://bsi.bund.de/eID/";
const DSS_NS: &str = "urn:oasis:names:tc:dss:1.0:core:schema";

pub fn serialize_soap<T: Serialize>(
    body: T,
    header: Option<Header>,
    include_dss_namespace: bool,
) -> Result<String, SoapError> {
    #[derive(Serialize)]
    #[serde(rename = "soapenv:Envelope")]
    struct SoapEnvelopeWithNs<T: Serialize> {
        #[serde(rename = "@xmlns:soapenv")]
        soapenv_ns: &'static str,
        #[serde(rename = "@xmlns:eid")]
        eid_ns: &'static str,
        #[serde(rename = "@xmlns:dss", skip_serializing_if = "Option::is_none")]
        dss_ns: Option<&'static str>,
        #[serde(rename = "soapenv:Header")]
        header: Option<Header>,
        #[serde(rename = "soapenv:Body")]
        body: SoapBody<T>,
    }

    let envelope = SoapEnvelopeWithNs {
        soapenv_ns: SOAPENV_NS,
        eid_ns: EID_NS,
        dss_ns: if include_dss_namespace {
            Some(DSS_NS)
        } else {
            None
        },
        header,
        body: SoapBody { request: body },
    };

    let xml = to_string(&envelope).map_err(|e| SoapError::XmlError {
        kind: ErrorKind::Serialization,
        path: None,
        message: e.to_string(),
    })?;

    Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>{xml}"))
}
