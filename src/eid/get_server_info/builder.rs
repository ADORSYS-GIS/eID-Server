use super::model::GetServerInfoResponse;
use crate::eid::common::models::AttributeSelection;
use quick_xml::{
    Writer,
    events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event},
};
use std::io::Cursor;

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
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    // XML declaration
    writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;

    // <soapenv:Envelope>
    let mut env = BytesStart::new("soapenv:Envelope");
    env.push_attribute(("xmlns:soapenv", "http://schemas.xmlsoap.org/soap/envelope/"));
    env.push_attribute(("xmlns:eid", "http://bsi.bund.de/eID/"));
    writer.write_event(Event::Start(env))?;

    // <soapenv:Header />
    writer.write_event(Event::Empty(BytesStart::new("soapenv:Header")))?;

    // <soapenv:Body>
    writer.write_event(Event::Start(BytesStart::new("soapenv:Body")))?;

    // <eid:getServerInfoResponse>
    writer.write_event(Event::Start(BytesStart::new("eid:getServerInfoResponse")))?;

    // <eid:ServerVersion>
    writer.write_event(Event::Start(BytesStart::new("eid:ServerVersion")))?;
    writer.write_event(Event::Start(BytesStart::new("eid:VersionString")))?;
    writer.write_event(Event::Text(BytesText::new(
        response.server_version.version_string.as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:VersionString")))?;
    writer.write_event(Event::Start(BytesStart::new("eid:Major")))?;
    writer.write_event(Event::Text(BytesText::new(
        &response.server_version.major.to_string(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:Major")))?;
    writer.write_event(Event::Start(BytesStart::new("eid:Minor")))?;
    writer.write_event(Event::Text(BytesText::new(
        &response.server_version.minor.to_string(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:Minor")))?;
    writer.write_event(Event::Start(BytesStart::new("eid:Bugfix")))?;
    writer.write_event(Event::Text(BytesText::new(
        &response.server_version.bugfix.to_string(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:Bugfix")))?;
    writer.write_event(Event::End(BytesEnd::new("eid:ServerVersion")))?;

    // <eid:DocumentVerificationRights>
    writer.write_event(Event::Start(BytesStart::new(
        "eid:DocumentVerificationRights",
    )))?;

    // Helper to write each attribute
    macro_rules! write_sel {
        ($tag:expr, $field:expr) => {{
            if let AttributeSelection::ALLOWED = $field {
                writer
                    .write_event(Event::Start(BytesStart::new($tag)))
                    .unwrap();
                writer
                    .write_event(Event::Text(BytesText::new("ALLOWED")))
                    .unwrap();
                writer.write_event(Event::End(BytesEnd::new($tag))).unwrap();
            } else {
                writer
                    .write_event(Event::Empty(BytesStart::new($tag)))
                    .unwrap();
            }
        }};
    }

    write_sel!(
        "eid:DocumentType",
        response.document_verification_rights.document_type
    );
    write_sel!(
        "eid:IssuingState",
        response.document_verification_rights.issuing_state
    );
    write_sel!(
        "eid:DateOfExpiry",
        response.document_verification_rights.date_of_expiry
    );
    write_sel!(
        "eid:GivenNames",
        response.document_verification_rights.given_names
    );
    write_sel!(
        "eid:FamilyNames",
        response.document_verification_rights.family_names
    );
    write_sel!(
        "eid:ArtisticName",
        response.document_verification_rights.artistic_names
    );
    write_sel!(
        "eid:AcademicTitle",
        response.document_verification_rights.academic_title
    );
    write_sel!(
        "eid:DateOfBirth",
        response.document_verification_rights.date_of_birth
    );
    write_sel!(
        "eid:PlaceOfBirth",
        response.document_verification_rights.place_of_birth
    );
    write_sel!(
        "eid:Nationality",
        response.document_verification_rights.nationality
    );
    write_sel!(
        "eid:BirthName",
        response.document_verification_rights.birth_name
    );
    write_sel!(
        "eid:PlaceOfResidence",
        response.document_verification_rights.place_of_residence
    );
    write_sel!(
        "eid:CommunityID",
        response.document_verification_rights.community_id
    );
    write_sel!(
        "eid:ResidencePermitI",
        response.document_verification_rights.residence_permit
    );
    write_sel!(
        "eid:RestrictedID",
        response.document_verification_rights.restricted_id
    );
    write_sel!(
        "eid:AgeVerification",
        response.document_verification_rights.age_verification
    );
    write_sel!(
        "eid:PlaceVerification",
        response.document_verification_rights.place_verification
    );

    writer.write_event(Event::End(BytesEnd::new("eid:DocumentVerificationRights")))?;

    // Close tags
    writer.write_event(Event::End(BytesEnd::new("eid:getServerInfoResponse")))?;
    writer.write_event(Event::End(BytesEnd::new("soapenv:Body")))?;
    writer.write_event(Event::End(BytesEnd::new("soapenv:Envelope")))?;

    let xml = writer.into_inner().into_inner();
    Ok(String::from_utf8(xml).expect("UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eid::{common::models::AttributeSelection, get_server_info::model::{OperationsSelector, VersionType}};

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
        assert!(xml.contains("<eid:ResidencePermitI/>"));
        assert!(xml.contains("<eid:CommunityID/>"));
    }
}
