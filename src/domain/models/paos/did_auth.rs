use crate::domain::models::{ResultType, paos::ConnectionHandle};
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

const EAC2_PROTOCOL_ID: &str = "urn:oid:1.3.162.15480.3.0.14.2";

// Validates that the protocol identifier is the EAC2 protocol identifier
fn must_be_oid(val: &str) -> Result<(), ValidationError> {
    if val != EAC2_PROTOCOL_ID {
        return Err(ValidationError::new("Invalid protocol identifier"));
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Validate)]
#[serde(transparent)]
pub struct AuthProtoData<T: Validate> {
    #[validate(nested)]
    pub data: T,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Validate)]
#[serde(rename_all = "PascalCase")]
pub struct EAC1InputType {
    #[serde(rename = "@Protocol")]
    #[validate(custom(function = "must_be_oid"))]
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@xsi:type")]
    pub type_: Option<String>,
    #[serde(rename = "Certificate", default)]
    pub certificates: Vec<String>,
    #[serde(rename = "CertificateDescription")]
    pub cert_description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "RequiredCHAT")]
    pub required_chat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "OptionalCHAT")]
    pub optional_chat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "AuthenticatedAuxiliaryData")]
    pub auth_aux_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_info: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Validate)]
pub struct EAC2InputType {
    #[serde(rename = "@Protocol")]
    #[validate(custom(function = "must_be_oid"))]
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@xsi:type")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "Certificate")]
    pub certificates: Option<Vec<String>>,
    #[serde(rename = "EphemeralPublicKey")]
    pub eph_pubkey: String,
    #[serde(rename = "Signature")]
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Validate)]
#[serde(rename_all = "PascalCase")]
pub struct DIDAuthenticate<T: Validate> {
    pub connection_handle: ConnectionHandle,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "DIDScope")]
    pub did_scope: Option<String>,
    #[serde(rename = "DIDName")]
    pub did_name: String,
    #[validate(nested)]
    #[serde(rename = "AuthenticationProtocolData")]
    pub auth_protocol_data: AuthProtoData<T>,
}

impl<T: Validate> DIDAuthenticate<T> {
    pub fn data(self) -> T {
        self.auth_protocol_data.data
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Validate)]
pub struct EAC1OutputType {
    #[serde(rename = "@Protocol")]
    #[validate(custom(function = "must_be_oid"))]
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@xsi:type")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "CertificateHolderAuthorizationTemplate")]
    pub chat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "CertificationAuthorityReference", default)]
    pub car: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "EFCardAccess")]
    pub card_access: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "IDPICC")]
    pub id_picc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "Challenge")]
    pub challenge: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Validate)]
#[serde(rename_all = "PascalCase")]
pub struct EAC2OutputType {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "EFCardSecurity")]
    pub card_security: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "AuthenticationToken")]
    #[validate(length(min = 16, max = 16))]
    pub auth_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Validate)]
pub struct DIDAuthenticateResponse<T: Validate> {
    #[serde(rename = "Result")]
    pub result: ResultType,
    #[validate(nested)]
    #[serde(rename = "AuthenticationProtocolData")]
    pub auth_protocol_data: AuthProtoData<T>,
}

impl<T: Validate> DIDAuthenticateResponse<T> {
    pub fn data(self) -> T {
        self.auth_protocol_data.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soap::{Envelope, Header};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Validate)]
    struct DIDAuthReqEAC1 {
        #[serde(rename = "DIDAuthenticate")]
        pub did_auth: DIDAuthenticate<EAC1InputType>,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Validate)]
    struct DIDAuthReqEAC2 {
        #[serde(rename = "DIDAuthenticate")]
        pub did_auth: DIDAuthenticate<EAC2InputType>,
    }

    #[test]
    fn test_did_authenticate_eac1_input_parsing() {
        let req = include_str!("../../../../test_data/eid/didAuthenticateEAC1.xml");
        let result = Envelope::<DIDAuthenticate<EAC1InputType>>::parse(req);
        assert!(
            result.is_ok(),
            "Failed to parse XML: {:?}",
            result.unwrap_err()
        );

        let request = result.unwrap();
        assert!(request.body().validate().is_ok());
        assert!(request.header().is_some());
        assert!(request.header().as_ref().unwrap().message_id.is_some());
        assert!(request.header().as_ref().unwrap().relates_to.is_some());
    }

    #[test]
    fn test_did_auth_eac1_serialization() {
        let req = DIDAuthReqEAC1 {
            did_auth: DIDAuthenticate {
                connection_handle: ConnectionHandle {
                    context_handle: None,
                    ifd_name: None,
                    slot_index: Some(0),
                    card_application: Some("e80704007f00070302".to_string()),
                    slot_handle: Some("00".to_string()),
                },
                did_scope: None,
                did_name: "PIN".to_string(),
                auth_protocol_data: AuthProtoData {
                    data: EAC1InputType {
                        protocol: "urn:oid:1.3.162.15480.3.0.14.2".to_string(),
                        type_: None,
                        certificates: vec!["certificate1".to_string(), "certificate2".to_string()],
                        cert_description: "certificate description".to_string(),
                        required_chat: None,
                        optional_chat: None,
                        auth_aux_data: None,
                        transaction_info: None,
                    },
                },
            },
        };
        let header = Header {
            message_id: Some("12345678-1234-1234-1234-123456789012".to_string()),
            relates_to: Some("12345678-1234-1234-1234-123456789012".to_string()),
            security: None,
        };
        let result = Envelope::new(req).with_header(header).serialize_paos(true);
        assert!(result.is_ok());
        assert!(result.as_ref().unwrap().contains("</soap:Envelope>"));
        assert!(result.as_ref().unwrap().contains("<soap:Header>"));
        assert!(result.as_ref().unwrap().contains("<wsa:MessageID>"));
        assert!(result.as_ref().unwrap().contains("<wsa:RelatesTo>"));
        assert!(result.as_ref().unwrap().contains("<DIDAuthenticate>"));
        assert!(result.as_ref().unwrap().contains("<DIDName>"));
        assert!(
            result
                .as_ref()
                .unwrap()
                .contains("<Certificate>certificate1</Certificate>")
        );
        assert!(
            result
                .as_ref()
                .unwrap()
                .contains("<Certificate>certificate2</Certificate>")
        );
        assert!(
            result.as_ref().unwrap().contains(
                "<CertificateDescription>certificate description</CertificateDescription>"
            )
        );
    }

    #[test]
    fn test_did_authenticate_eac2_input_parsing() {
        let req = include_str!("../../../../test_data/eid/didAuthenticateEAC2.xml");
        let result = Envelope::<DIDAuthenticate<EAC2InputType>>::parse(req);
        assert!(result.is_ok());

        let request = result.unwrap();
        assert!(request.body().validate().is_ok());
        assert!(request.header().is_some());
        assert!(request.header().as_ref().unwrap().message_id.is_some());
        assert!(request.header().as_ref().unwrap().relates_to.is_some());
    }

    #[test]
    fn test_did_authenticate_eac2_serialization() {
        let req = DIDAuthReqEAC2 {
            did_auth: DIDAuthenticate {
                connection_handle: ConnectionHandle {
                    context_handle: None,
                    ifd_name: None,
                    slot_index: Some(0),
                    card_application: Some("e80704007f00070302".to_string()),
                    slot_handle: Some("00".to_string()),
                },
                did_scope: None,
                did_name: "PIN".to_string(),
                auth_protocol_data: AuthProtoData {
                    data: EAC2InputType {
                        protocol: "urn:oid:1.3.162.15480.3.0.14.2".to_string(),
                        type_: None,
                        certificates: None,
                        eph_pubkey: "04646ceed8cd570dea4f5eda2a85b0e6bd45ad1de7a394b0fffab6ff0e7da8c79b6fb3d43ba8737366bcc3f06a538025c979593c3b42bf007d925d4c844cbc9aff".to_string(),
                        signature: "71f914880b5dc54f2aad66659f3fe13b25b1ff24cfe80bd7eadc5d961d3e1819313cb953661fda4ee029604ccc63de2dded3afb4ea70dc29ddbed3e8ff3665ab".to_string(),
                    },
                },
            },
        };
        let header = Header {
            message_id: Some("12345678-1234-1234-1234-123456789012".to_string()),
            relates_to: Some("12345678-1234-1234-1234-123456789012".to_string()),
            security: None,
        };
        let result = Envelope::new(req).with_header(header).serialize_paos(true);
        assert!(result.is_ok());
        assert!(result.as_ref().unwrap().contains("</soap:Envelope>"));
        assert!(result.as_ref().unwrap().contains("<soap:Header>"));
        assert!(result.as_ref().unwrap().contains("<wsa:MessageID>"));
        assert!(result.as_ref().unwrap().contains("<wsa:RelatesTo>"));
        assert!(result.as_ref().unwrap().contains("<DIDAuthenticate>"));
        assert!(result.as_ref().unwrap().contains("<DIDName>"));
        assert!(result.as_ref().unwrap().contains("<EphemeralPublicKey>"));
        assert!(result.as_ref().unwrap().contains("<Signature>"));
    }

    #[test]
    fn test_did_authenticate_eac1_response_parsing() {
        let req = include_str!("../../../../test_data/eid/didAuthEAC1Response.xml");
        let result = Envelope::<DIDAuthenticateResponse<EAC1OutputType>>::parse(req);
        assert!(result.is_ok());

        let request = result.unwrap();
        assert!(request.body().validate().is_ok());
        assert!(request.header().is_some());
        assert!(request.header().as_ref().unwrap().message_id.is_some());
        assert!(request.header().as_ref().unwrap().relates_to.is_some());
    }

    #[test]
    fn test_did_authenticate_eac2_response_parsing() {
        let req = include_str!("../../../../test_data/eid/didAuthEAC2Response.xml");
        let result = Envelope::<DIDAuthenticateResponse<EAC2OutputType>>::parse(req);
        assert!(result.is_ok());

        let request = result.unwrap();
        assert!(request.body().validate().is_ok());
        assert!(request.header().is_some());
        assert!(request.header().as_ref().unwrap().message_id.is_some());
        assert!(request.header().as_ref().unwrap().relates_to.is_some());
    }
}
