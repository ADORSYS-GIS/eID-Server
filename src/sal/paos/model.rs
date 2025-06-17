use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Envelope {
    #[serde(rename = "Body")]
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
    #[serde(rename = "SessionIdentifier")]
    pub session_identifier: String,
    #[serde(rename = "ConnectionHandle")]
    pub connection_handles: Vec<String>,
    #[serde(rename = "UserAgent")]
    pub user_agent: Option<UserAgent>,
    #[serde(rename = "SupportedAPIVersions")]
    pub supported_api_versions: Option<SupportedAPIVersions>,
    #[serde(rename = "SupportedDIDProtocols")]
    pub supported_did_protocols: Option<SupportedDIDProtocols>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct UserAgent {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "VersionMajor")]
    pub version_major: u32,
    #[serde(rename = "VersionMinor")]
    pub version_minor: u32,
    #[serde(rename = "VersionSubminor")]
    pub version_subminor: u32,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct SupportedAPIVersions {
    #[serde(rename = "Major")]
    pub major: u32,
    #[serde(rename = "Minor")]
    pub minor: u32,
    #[serde(rename = "Subminor")]
    pub subminor: u32,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct SupportedDIDProtocols {
    #[serde(rename = "Protocol")]
    pub protocols: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct StartPAOSResponse {
    pub session_identifier: String,
    #[serde(rename = "Result")]
    pub result: String,
}
