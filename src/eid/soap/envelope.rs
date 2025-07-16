use serde::{Deserialize, Serialize};

use crate::eid::common::models::Header;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "soapenv:Envelope")]
pub struct SoapEnvelope<T> {
    #[serde(rename = "soapenv:Header")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<Header>,
    #[serde(rename = "soapenv:Body")]
    pub body: T,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SoapBody<T> {
    #[serde(rename = "eid:useIDRequest", alias = "eid:getResultRequest")]
    pub request: T,
}
