use crate::domain::models::ResultType;
use crate::domain::models::paos::ConnectionHandle;
use serde::{Deserialize, Serialize};
use validator::Validate;

const VERSION_MAJOR: u32 = 1;
const VERSION_MINOR: u32 = 1;
const VERSION_SUBMINOR: u32 = 5;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct UserAgent {
    pub name: String,
    pub version_major: u32,
    pub version_minor: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_subminor: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct APIVersion {
    pub major: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minor: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subminor: Option<u32>,
}

impl APIVersion {
    /// Checks if the API version is compliant with the current eCard Framework (1.1.5)
    pub fn is_compliant(&self) -> bool {
        self.major == VERSION_MAJOR
            && self.minor == Some(VERSION_MINOR)
            && self.subminor == Some(VERSION_SUBMINOR)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Validate)]
#[serde(rename_all = "PascalCase")]
pub struct StartPaosReq {
    #[validate(length(min = 32))]
    pub session_identifier: String,
    #[serde(rename = "ConnectionHandle", default)]
    pub connection_handles: Vec<ConnectionHandle>,
    pub user_agent: UserAgent,
    #[serde(rename = "SupportedAPIVersions")]
    pub supported_api_versions: Vec<APIVersion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "SupportedDIDProtocols", default)]
    pub supported_did_proto: Option<Vec<String>>,
}

impl StartPaosReq {
    pub fn select_connection_handle(&self, target_aids: &[&str]) -> Option<&ConnectionHandle> {
        let matches: Vec<&ConnectionHandle> = self
            .connection_handles
            .iter()
            .filter(|h| {
                h.card_application
                    .as_ref()
                    .map(|aid| target_aids.iter().any(|t| t.eq_ignore_ascii_case(aid)))
                    .unwrap_or(false)
            })
            .collect();
        matches.first().copied()
    }
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct StartPaosResponse {
    pub result: ResultType,
}

impl StartPaosResponse {
    pub fn ok() -> Self {
        Self {
            result: ResultType::ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soap::Envelope;

    #[test]
    fn test_start_paos_parsing() {
        let req = include_str!("../../../../test_data/eid/startPAOS.xml");
        let result = Envelope::<StartPaosReq>::parse(req);
        assert!(result.is_ok());

        let request = result.unwrap();
        assert!(request.body().validate().is_ok());
        assert!(request.header().is_some());
        assert!(request.header().as_ref().unwrap().message_id.is_some());
        assert_eq!(
            request.body().session_identifier,
            "77b5472b-83e0-4f17-8d42-1d2dee213402"
        );
        assert_eq!(request.body().connection_handles.len(), 1);
        assert_eq!(
            request.body().connection_handles[0].card_application,
            Some("e80704007f00070302".to_string())
        );
        assert_eq!(
            request.body().connection_handles[0].slot_handle,
            Some("00".to_string())
        );
        assert_eq!(request.body().supported_api_versions[0].major, 1);
        assert_eq!(request.body().supported_api_versions[0].minor, Some(1));
        assert_eq!(request.body().supported_api_versions[0].subminor, Some(5));
    }

    #[test]
    fn test_select_connection_handle() {
        let req = StartPaosReq {
            session_identifier: "77b5472b83e04f178d421d2dee213402".to_string(),
            connection_handles: vec![ConnectionHandle {
                context_handle: None,
                ifd_name: None,
                slot_index: None,
                card_application: Some("e80704007f00070302".to_string()),
                slot_handle: None,
            }],
            user_agent: UserAgent {
                name: "UserAgent".to_string(),
                version_major: 1,
                version_minor: 0,
                version_subminor: Some(0),
            },
            supported_api_versions: vec![APIVersion {
                major: 1,
                minor: Some(1),
                subminor: Some(5),
            }],
            supported_did_proto: None,
        };
        let result = req.select_connection_handle(&["e80704007f00070302"]);
        assert!(result.is_some());
        let result = req.select_connection_handle(&["A000000167455349474E"]);
        assert!(result.is_none());
    }
}
