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

    let xml = to_string(&envelope).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let xml_with_ns = xml.replacen(
        "<soapenv:Envelope",
        "<soapenv:Envelope \
         xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         xmlns:eid=\"http://bsi.bund.de/eID/\" \
         xmlns:dss=\"urn:oasis:names:tc:dss:1.0:core:schema\"",
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
                community_id: AttributeSelection::PROHIBITED,
                residence_permit: AttributeSelection::PROHIBITED,
                restricted_id: AttributeSelection::ALLOWED,
                age_verification: AttributeSelection::ALLOWED,
                place_verification: AttributeSelection::ALLOWED,
            },
        };

        let xml = build_get_server_info_response(&response).unwrap();

        // VersionInfo
        assert!(xml.contains("<eid:VersionString>Version 2.4.0\n02.08.2021</eid:VersionString>"));
        assert!(xml.contains("<eid:Major>2</eid:Major>"));
        assert!(xml.contains("<eid:Minor>4</eid:Minor>"));
        assert!(xml.contains("<eid:Bugfix>0</eid:Bugfix>"));
        assert!(xml.contains("<eid:IssuingState>ALLOWED</eid:IssuingState>"));
        assert!(xml.contains("<eid:DateOfExpiry>ALLOWED</eid:DateOfExpiry>"));
        assert!(xml.contains("<eid:GivenNames>ALLOWED</eid:GivenNames>"));
        assert!(xml.contains("<eid:FamilyNames>ALLOWED</eid:FamilyNames>"));
        assert!(xml.contains("<eid:AgeVerification>ALLOWED</eid:AgeVerification>"));
        assert!(xml.contains("<eid:PlaceVerification>ALLOWED</eid:PlaceVerification>"));

        // DocumentVerificationRights allowed fields
        assert!(xml.contains("<eid:DocumentType>ALLOWED</eid:DocumentType>"));
        assert!(xml.contains("<eid:ArtisticName>ALLOWED</eid:ArtisticName>"));

        // Empty elements for not allowed
        assert!(xml.contains("<eid:RestrictedID>ALLOWED</eid:RestrictedID>"));
        assert!(xml.contains("<eid:CommunityID>PROHIBITED</eid:CommunityID>"));
    }
}
