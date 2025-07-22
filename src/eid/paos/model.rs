use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Envelope {
    pub body: Body,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Body {
    #[serde(rename = "StartPAOS", alias = "iso:StartPAOS")]
    pub start_paos: StartPAOS,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct StartPAOS {
    pub session_identifier: String,
    #[serde(rename = "ConnectionHandle")]
    pub connection_handle: ConnectionHandle,
    pub user_agent: Option<UserAgent>,
    #[serde(rename = "SupportedAPIVersions")]
    pub supported_api_versions: Option<SupportedAPIVersions>,
    #[serde(rename = "SupportedDIDProtocols")]
    pub supported_did_protocols: Option<SupportedDIDProtocols>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct ConnectionHandle {
    #[serde(rename = "@xsi:type", default)]
    pub xsi_type: String,
    #[serde(rename = "CardApplication")]
    pub card_application: String,
    #[serde(rename = "SlotHandle")]
    pub slot_handle: String,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct UserAgent {
    pub name: String,
    pub version_major: u32,
    pub version_minor: u32,
    pub version_subminor: u32,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct SupportedAPIVersions {
    pub major: u32,
    pub minor: u32,
    pub subminor: u32,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct SupportedDIDProtocols {
    #[serde(rename = "Protocol")]
    pub protocols: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct StartPAOSResponse {
    #[serde(rename = "Result")]
    pub result: ResultType,
}

#[derive(Debug, Serialize)]
pub struct ResultType {
    #[serde(rename = "ResultMajor")]
    pub major: String,
    #[serde(rename = "ResultMinor", skip_serializing_if = "Option::is_none")]
    pub minor: Option<String>,
}
