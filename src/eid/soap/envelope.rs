use serde::{Deserialize, Serialize};
use crate::eid::common::models::Header;

#[derive(Serialize)]
#[serde(rename = "soapenv:Envelope")]
pub struct SoapResponseEnvelope<T: Serialize> {
    #[serde(rename = "soapenv:Header")]
    pub header: Header,
    #[serde(rename = "soapenv:Body")]
    pub body: SoapResponseBody<T>,
}

#[derive(Serialize)]
#[serde(rename = "soapenv:Body")]
pub struct SoapResponseBody<T: Serialize> {
    #[serde(flatten)]
    pub response: T,
}

#[derive(Deserialize)]
#[serde(rename = "{http://schemas.xmlsoap.org/soap/envelope/}Envelope")]
pub struct SoapRequestEnvelope<T> {
    #[serde(rename = "{http://schemas.xmlsoap.org/soap/envelope/}Header", default)]
    pub header: Option<Header>,
    #[serde(rename = "{http://schemas.xmlsoap.org/soap/envelope/}Body")]
    pub body: SoapRequestBody<T>,
}

#[derive(Deserialize)]
#[serde(rename = "{http://schemas.xmlsoap.org/soap/envelope/}Body")]
pub struct SoapRequestBody<T> {
    #[serde(flatten)]
    pub request: T,
}
