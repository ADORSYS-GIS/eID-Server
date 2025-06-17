use std::io;

use crate::eid::common::models::Header;

use super::model::{GetServerInfoBody, GetServerInfoEnvelope, GetServerInfoResponse};
use quick_xml::se::to_string;

/// Builds a SOAP XML response string from a `GetServerInfoResponse` data structure.
///
/// This function constructs a complete SOAP envelope containing server version info
/// and document verification rights as specified in `GetServerInfoResponse`. It serializes
/// the data into an XML format compliant with the expected eID service schema.
///
/// # Arguments
///
/// * `response` - A reference to a [`GetServerInfoResponse`] struct containing the data to serialize.
///
/// # Returns
///
/// * `Ok(String)` - The serialized XML document as a UTF-8 encoded string.
/// * `Err(std::io::Error)` - If an error occurs during writing to the underlying buffer.
pub fn build_get_server_info_response(
    response: &GetServerInfoResponse,
) -> Result<String, std::io::Error> {
    let envelope = GetServerInfoEnvelope {
        header: Header::default(),
        body: GetServerInfoBody {
            response: GetServerInfoResponse {
                server_version: response.server_version.clone(),
                document_verification_rights: response.document_verification_rights.clone(),
            },
        },
    };

    let xml = to_string(&envelope).map_err(|e| io::Error::other( e))?;

    let xml_with_ns = xml.replacen(
        "<soapenv:Envelope",
        "<soapenv:Envelope \
         xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         xmlns:eid=\"http://bsi.bund.de/eID/\"",
        1,
    );

    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        xml_with_ns
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eid::{
        common::models::AttributeSelection,
        get_server_info::model::{OperationsSelector, VersionType},
    };

    #[test]
    fn test_build_get_server_info_response() {
        let response = GetServerInfoResponse {
            server_version: VersionType {
                version_string: "Version 2.4.0\n02.08.2021".to_string(),
                major: 2,
                minor: 4,
                bugfix: 0,
            },
            document_verification_rights: OperationsSelector {
                document_type: AttributeSelection::ALLOWED,
                issuing_state: AttributeSelection::ALLOWED,
                date_of_expiry: AttributeSelection::ALLOWED,
                given_names: AttributeSelection::ALLOWED,
                family_names: AttributeSelection::ALLOWED,
                artistic_names: AttributeSelection::ALLOWED,
                academic_title: AttributeSelection::ALLOWED,
                date_of_birth: AttributeSelection::ALLOWED,
                place_of_birth: AttributeSelection::ALLOWED,
                nationality: AttributeSelection::ALLOWED,
                birth_name: AttributeSelection::ALLOWED,
                place_of_residence: AttributeSelection::ALLOWED,
                community_id: None,
                residence_permit_i: None,
                restricted_id: AttributeSelection::ALLOWED,
                age_verification: AttributeSelection::ALLOWED,
                place_verification: AttributeSelection::ALLOWED,
            },
        };

        // Normalize whitespace for comparison
        let normalize = |s: &str| s.split_whitespace().collect::<String>();

        let xml = build_get_server_info_response(&response).unwrap();
        let expected_xml = std::fs::read_to_string("test_data/get_server_info_response.xml")
            .expect("Failed to read expected XML file");
        assert_eq!(normalize(&xml), normalize(&expected_xml));
    }

    #[test]
    fn test_build_get_server_info_response_minimal() {
        let response = GetServerInfoResponse {
            server_version: VersionType {
                version_string: "1.0.0".to_string(),
                major: 1,
                minor: 0,
                bugfix: 0,
            },
            document_verification_rights: OperationsSelector {
                document_type: AttributeSelection::PROHIBITED,
                issuing_state: AttributeSelection::PROHIBITED,
                date_of_expiry: AttributeSelection::PROHIBITED,
                given_names: AttributeSelection::PROHIBITED,
                family_names: AttributeSelection::PROHIBITED,
                artistic_names: AttributeSelection::PROHIBITED,
                academic_title: AttributeSelection::PROHIBITED,
                date_of_birth: AttributeSelection::PROHIBITED,
                place_of_birth: AttributeSelection::PROHIBITED,
                nationality: AttributeSelection::PROHIBITED,
                birth_name: AttributeSelection::PROHIBITED,
                place_of_residence: AttributeSelection::PROHIBITED,
                community_id: None,
                residence_permit_i: None,
                restricted_id: AttributeSelection::PROHIBITED,
                age_verification: AttributeSelection::PROHIBITED,
                place_verification: AttributeSelection::PROHIBITED,
            },
        };
        let xml = build_get_server_info_response(&response).unwrap();
        assert!(xml.contains("<soapenv:Envelope"));
        assert!(xml.contains("xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\""));
        assert!(xml.contains("xmlns:eid=\"http://bsi.bund.de/eID/\""));
        assert!(xml.contains("<eid:ServerVersion>"));
        assert!(xml.contains("<eid:DocumentVerificationRights>"));
    }
}
