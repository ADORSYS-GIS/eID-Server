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
    pub session_identifier: String,
    #[serde(rename = "ConnectionHandle")]
    pub connection_handles: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct StartPAOSResponse {
    pub session_identifier: String,
    #[serde(rename = "Result")]
    pub result: String,
}

