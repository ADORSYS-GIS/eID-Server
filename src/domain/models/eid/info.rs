use serde::{Deserialize, Serialize};

use crate::domain::models::eid::Operations;

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub enum AttrSelect {
    ALLOWED,
    #[default]
    PROHIBITED,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributeSelect {
    #[serde(rename = "$text", default)]
    pub value: AttrSelect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    #[serde(rename = "eid:VersionString")]
    pub version_string: String,
    #[serde(rename = "eid:Major")]
    pub major: i32,
    #[serde(rename = "eid:Minor")]
    pub minor: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "eid:Bugfix")]
    pub bugfix: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetServerInfoRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct GetServerInfoResponse {
    #[serde(rename = "eid:ServerVersion")]
    pub version: Version,
    #[serde(rename = "eid:DocumentVerificationRights")]
    pub verif_rights: Operations<AttributeSelect>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soap::Envelope;

    #[test]
    fn test_get_server_info_request_parsing() {
        let req = include_str!("../../../../test_data/eid/getServerInfoRequest.xml");
        let result = Envelope::<GetServerInfoRequest>::parse(req);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_server_info_response_serialization() {
        let response = GetServerInfoResponse {
            version: Version {
                version_string: "Version 2.4.0 02.08.2021".to_string(),
                major: 2,
                minor: 4,
                bugfix: Some(0),
            },
            verif_rights: Operations {
                document_type: Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                }),
                issuing_state: Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                }),
                date_of_expiry: Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                }),
                given_names: Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                }),
                family_names: Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                }),
                artistic_name: Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                }),
                academic_title: Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                }),
                date_of_birth: Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                }),
                place_of_birth: Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                }),
                nationality: Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                }),
                birth_name: Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                }),
                place_of_residence: Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                }),
                community_id: Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                }),
                residence_permit_i: Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                }),
                restricted_id: Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                }),
                age_verification: Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                }),
                place_verification: Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                }),
                ..Default::default()
            },
        };

        let envelope = crate::soap::Envelope::new(response);
        let serialized = envelope.serialize_soap(true).unwrap();

        // Verify the response contains expected elements
        assert!(serialized.contains("Version 2.4.0 02.08.2021"));
        assert!(serialized.contains("<eid:Major>2</eid:Major>"));
        assert!(serialized.contains("<eid:Minor>4</eid:Minor>"));
        assert!(serialized.contains("<eid:Bugfix>0</eid:Bugfix>"));
        assert!(serialized.contains("<eid:DocumentType>ALLOWED</eid:DocumentType>"));
        assert!(serialized.contains("<eid:IssuingState>ALLOWED</eid:IssuingState>"));
        assert!(serialized.contains("<eid:GivenNames>ALLOWED</eid:GivenNames>"));
        assert!(serialized.contains("<eid:FamilyNames>ALLOWED</eid:FamilyNames>"));
    }
}
