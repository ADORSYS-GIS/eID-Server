use crate::domain::models::paos::ConnectionHandle;
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
    #[serde(rename = "@xsi:type")]
    pub type_: String,
    #[serde(rename = "Certificate")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soap::{Envelope, Header};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Validate)]
    struct DIDAuthReq {
        #[serde(rename = "DIDAuthenticate")]
        pub did_auth: DIDAuthenticate<EAC1InputType>,
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
        let req = DIDAuthReq {
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
                        type_: "EAC1InputType".to_string(),
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
            result.as_ref().unwrap().contains(
                "<AuthenticationProtocolData Protocol=\"urn:oid:1.3.162.15480.3.0.14.2\">"
            )
        );
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
}
