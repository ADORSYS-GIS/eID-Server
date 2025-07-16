use serde::{Deserialize, Serialize};

use crate::eid::common::models::Header;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "soapenv:Envelope")]
pub struct SoapEnvelope<T> {
    #[serde(rename = "soapenv:Header")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<Header>,
    #[serde(rename = "soapenv:Body")]
    pub body: SoapBody<T>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "soapenv:Body")]
pub struct SoapBody<T> {
    #[serde(flatten)]
    pub request: T,
}
