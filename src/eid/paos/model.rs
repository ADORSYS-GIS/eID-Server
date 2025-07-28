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
    pub connection_handle: ConnectionHandle,
    pub user_agent: Option<UserAgent>,
    #[serde(rename = "SupportedAPIVersions", alias = "iso:SupportedAPIVersions")]
    pub supported_api_versions: Option<SupportedAPIVersions>,
    #[serde(rename = "SupportedDIDProtocols", alias = "iso:SupportedDIDProtocols")]
    pub supported_did_protocols: Option<SupportedDIDProtocols>,
    pub message_id: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct ConnectionHandle {
    #[serde(rename = "@xsi:type", default)]
    pub xsi_type: String,
    pub card_application: String,
    pub slot_handle: String,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct UserAgent {
    pub name: Option<String>,
    pub version_major: Option<u32>,
    pub version_minor: Option<u32>,
    pub version_subminor: Option<u32>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct SupportedAPIVersions {
    pub major: u32,
    pub minor: Option<u32>,
    pub subminor: Option<u32>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct SupportedDIDProtocols {
    #[serde(rename = "Protocol")]
    pub protocols: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct StartPAOSResponse {
    pub result: ResultType,
}

#[derive(Debug, Serialize)]
pub struct ResultType {
    pub major: String,
    pub minor: Option<String>,
}
