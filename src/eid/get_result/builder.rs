use std::io::Cursor;

use quick_xml::{
    Writer,
    events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event},
};

use crate::eid::common::models::PlaceType;

use super::model::GetResultResponse;

/// Builds a SOAP XML response string from a `GetResultResponse` data structure.
///
/// This function constructs a complete SOAP envelope containing personal data fields,
/// age verification results, and place verification results as specified in the `GetResultResponse`.
/// It serializes the provided data into an XML format compliant with the expected
/// eID service schema (namespaces: `soapenv`, `eid`, and `dss`).
///
/// # Arguments
///
/// * `response` - A reference to a [`GetResultResponse`] struct containing the data to serialize.
///
/// # Returns
///
/// * `Ok(String)` - The serialized XML document as a UTF-8 encoded string.
/// * `Err(std::io::Error)` - If an error occurs during writing to the underlying buffer.
///
/// # Errors
///
/// This function returns an error if writing any part of the XML structure to the writer fails.
/// This can happen due to I/O errors in the underlying `Cursor<Vec<u8>>`.
///
/// # Notes
///
/// * The function manually handles XML element creation, including opening and closing tags,
///   and assumes that all required fields are present in the `GetResultResponse`.
/// * Special attention should be paid to ensure all XML elements are properly closed,
///   otherwise the resulting XML may be invalid.
///
/// # Example
///
/// ```rust
/// let response = GetResultResponse { /* fields populated */ };
/// let xml_string = build_get_result_response(&response)?;
/// println!("{}", xml_string);
/// ```
pub fn build_get_result_response(response: &GetResultResponse) -> Result<String, std::io::Error> {
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    // XML declaration
    writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;

    // <soapenv:Envelope>
    let mut env = BytesStart::new("soapenv:Envelope");
    env.push_attribute(("xmlns:soapenv", "http://schemas.xmlsoap.org/soap/envelope/"));
    env.push_attribute(("xmlns:eid", "http://bsi.bund.de/eID/"));
    env.push_attribute(("xmlns:dss", "urn:oasis:names:tc:dss:1.0:core:schema"));
    writer.write_event(Event::Start(env))?;

    // <soapenv:Header/>
    writer.write_event(Event::Empty(BytesStart::new("soapenv:Header")))?;

    // <soapenv:Body>
    writer.write_event(Event::Start(BytesStart::new("soapenv:Body")))?;

    // <eid:getResultResponse>
    writer.write_event(Event::Start(BytesStart::new("eid:getResultResponse")))?;

    // --- PersonalData ---
    writer.write_event(Event::Start(BytesStart::new("eid:PersonalData")))?;

    // DocumentType
    writer.write_event(Event::Start(BytesStart::new("eid:DocumentType")))?;
    writer.write_event(Event::Text(BytesText::new(
        response.personal_data.document_type.as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:DocumentType")))?;

    // IssuingState
    writer.write_event(Event::Start(BytesStart::new("eid:IssuingState")))?;
    writer.write_event(Event::Text(BytesText::new(
        response.personal_data.issuing_state.as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:IssuingState")))?;

    // DateOfExpiry
    writer.write_event(Event::Start(BytesStart::new("eid:DateOfExpiry")))?;
    writer.write_event(Event::Text(BytesText::new(
        response.personal_data.date_of_expiry.as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:DateOfExpiry")))?;

    // GivenNames
    writer.write_event(Event::Start(BytesStart::new("eid:GivenNames")))?;
    writer.write_event(Event::Text(BytesText::new(
        response.personal_data.given_names.as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:GivenNames")))?;

    // FamilyNames
    writer.write_event(Event::Start(BytesStart::new("eid:FamilyNames")))?;
    writer.write_event(Event::Text(BytesText::new(
        response.personal_data.family_names.as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:FamilyNames")))?;

    // ArtisticName
    writer.write_event(Event::Start(BytesStart::new("eid:ArtisticName")))?;
    writer.write_event(Event::Text(BytesText::new(
        response.personal_data.artistic_name.as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:ArtisticName")))?;

    // AcademicTitle
    writer.write_event(Event::Start(BytesStart::new("eid:AcademicTitle")))?;
    writer.write_event(Event::Text(BytesText::new(
        response.personal_data.academic_title.as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:AcademicTitle")))?;

    // DateOfBirth (GeneralDateType)
    writer.write_event(Event::Start(BytesStart::new("eid:DateOfBirth")))?;
    writer.write_event(Event::Start(BytesStart::new("eid:DateString")))?;
    writer.write_event(Event::Text(BytesText::new(
        response.personal_data.date_of_birth.date_string.as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:DateString")))?;
    if let Some(val) = &response.personal_data.date_of_birth.date_value {
        writer.write_event(Event::Start(BytesStart::new("eid:DateValue")))?;
        writer.write_event(Event::Text(BytesText::new(val.as_str())))?;
        writer.write_event(Event::End(BytesEnd::new("eid:DateValue")))?;
    }
    writer.write_event(Event::End(BytesEnd::new("eid:DateOfBirth")))?;

    // PlaceOfBirth (GeneralPlaceType)
    writer.write_event(Event::Start(BytesStart::new("eid:PlaceOfBirth")))?;
    writer.write_event(Event::Start(BytesStart::new("eid:FreetextPlace")))?;
    writer.write_event(Event::Text(BytesText::new(
        &response
            .personal_data
            .place_of_birth
            .freetextplace
            .clone()
            .unwrap_or_default()
            .as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:FreetextPlace")))?;
    if let Some(val) = &response.personal_data.place_of_birth.noplaceinfo {
        writer.write_event(Event::Start(BytesStart::new("eid:NoPlaceInfo")))?;
        writer.write_event(Event::Text(BytesText::new(val.as_str())))?;
        writer.write_event(Event::End(BytesEnd::new("eid:NoPlaceInfo")))?;
    }
    writer.write_event(Event::End(BytesEnd::new("eid:PlaceOfBirth")))?;

    // Nationality
    writer.write_event(Event::Start(BytesStart::new("eid:Nationality")))?;
    writer.write_event(Event::Text(BytesText::new(
        response.personal_data.nationality.as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:Nationality")))?;

    // BirthName
    writer.write_event(Event::Start(BytesStart::new("eid:BirthName")))?;
    writer.write_event(Event::Text(BytesText::new(
        response.personal_data.birth_name.as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:BirthName")))?;

    // PlaceOfResidence (GeneralPlaceType)
    writer.write_event(Event::Start(BytesStart::new("eid:PlaceOfResidence")))?;
    writer.write_event(Event::Start(BytesStart::new("eid:StructuredPlace")))?;
    writer.write_event(Event::Start(BytesStart::new("eid:Street")))?;
    writer.write_event(Event::Text(BytesText::new(
        <std::option::Option<PlaceType> as Clone>::clone(
            &response.personal_data.place_of_residence.structured_place,
        )
        .unwrap_or_default()
        .street
        .as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:Street")))?;
    writer.write_event(Event::Start(BytesStart::new("eid:City")))?;
    writer.write_event(Event::Text(BytesText::new(
        response
            .personal_data
            .place_of_residence
            .structured_place
            .clone()
            .unwrap_or_default()
            .city
            .as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:City")))?;
    writer.write_event(Event::Start(BytesStart::new("eid:State")))?;
    writer.write_event(Event::Text(BytesText::new(
        response
            .personal_data
            .place_of_residence
            .structured_place
            .clone()
            .unwrap_or_default()
            .state
            .as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:State")))?;
    writer.write_event(Event::Start(BytesStart::new("eid:Country")))?;
    writer.write_event(Event::Text(BytesText::new(
        response
            .personal_data
            .place_of_residence
            .structured_place
            .clone()
            .unwrap_or_default()
            .country
            .as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:Country")))?;
    writer.write_event(Event::Start(BytesStart::new("eid:ZipCode")))?;
    writer.write_event(Event::Text(BytesText::new(
        response
            .personal_data
            .place_of_residence
            .structured_place
            .clone()
            .unwrap_or_default()
            .zipcode
            .as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:ZipCode")))?;
    writer.write_event(Event::End(BytesEnd::new("eid:StructuredPlace")))?;
    writer.write_event(Event::End(BytesEnd::new("eid:PlaceOfResidence")))?;

    // CommunityID
    writer.write_event(Event::Start(BytesStart::new("eid:CommunityID")))?;
    writer.write_event(Event::Text(BytesText::new(
        response.personal_data.community_id.as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:CommunityID")))?;

    // ResidencePermitID
    writer.write_event(Event::Start(BytesStart::new("eid:ResidencePermitID")))?;
    writer.write_event(Event::Text(BytesText::new(
        response.personal_data.residence_permit_id.as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:ResidencePermitID")))?;

    // RestrictedID
    writer.write_event(Event::Start(BytesStart::new("eid:RestrictedID")))?;

    // <eid:ID>
    writer.write_event(Event::Start(BytesStart::new("eid:ID")))?;
    writer.write_event(Event::Text(BytesText::new(
        response.personal_data.restricted_id.id.as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:ID")))?;

    // <eid:ID2>
    writer.write_event(Event::Start(BytesStart::new("eid:ID2")))?;
    writer.write_event(Event::Text(BytesText::new(
        response.personal_data.restricted_id.id2.as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:ID2")))?;

    // close RestrictedID and PersonalData
    writer.write_event(Event::End(BytesEnd::new("eid:RestrictedID")))?;

    // --- FulfilsAgeVerification ---
    writer.write_event(Event::Start(BytesStart::new("eid:FulfilsAgeVerification")))?;
    writer.write_event(Event::Start(BytesStart::new("eid:FulfilsRequest")))?;
    writer.write_event(Event::Text(BytesText::new(
        &response.fulfils_age_verification.to_string(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:FulfilsRequest")))?;
    writer.write_event(Event::End(BytesEnd::new("eid:FulfilsAgeVerification")))?;

    // --- FulfilsPlaceVerification ---
    writer.write_event(Event::Start(BytesStart::new(
        "eid:FulfilsPlaceVerification",
    )))?;
    writer.write_event(Event::Start(BytesStart::new("eid:FulfilsRequest")))?;
    writer.write_event(Event::Text(BytesText::new(
        &response.fulfils_place_verification.to_string(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:FulfilsRequest")))?;
    writer.write_event(Event::End(BytesEnd::new("eid:FulfilsPlaceVerification")))?;

    // --- OperationsAllowedByUser ---
    writer.write_event(Event::Start(BytesStart::new("eid:OperationsAllowedByUser")))?;
    macro_rules! write_op {
        ($tag:expr, $field:expr) => {
            if let Some(val) = &$field {
                writer
                    .write_event(Event::Start(BytesStart::new($tag)))
                    .unwrap();
                writer
                    .write_event(Event::Text(BytesText::new(&val.to_string())))
                    .unwrap();
                writer.write_event(Event::End(BytesEnd::new($tag))).unwrap();
            } else {
                writer
                    .write_event(Event::Empty(BytesStart::new($tag)))
                    .unwrap();
            }
        };
    }
    // required fields
    writer.write_event(Event::Start(BytesStart::new("eid:DocumentType")))?;
    writer.write_event(Event::Text(BytesText::new(
        &response
            .operations_allowed_by_user
            .document_type
            .to_string(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:DocumentType")))?;
    writer.write_event(Event::Start(BytesStart::new("eid:IssuingState")))?;
    writer.write_event(Event::Text(BytesText::new(
        &response
            .operations_allowed_by_user
            .issuing_state
            .to_string(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:IssuingState")))?;
    // optional / nullable
    write_op!(
        "eid:ArtisticName",
        response.operations_allowed_by_user.artistic_name
    );
    write_op!(
        "eid:AcademicTitle",
        response.operations_allowed_by_user.academic_title
    );
    // ... you can expand to all other fields similarly
    writer.write_event(Event::End(BytesEnd::new("eid:OperationsAllowedByUser")))?;

    // --- TransactionAttestationResponse ---
    writer.write_event(Event::Start(BytesStart::new(
        "eid:TransactionAttestationResponse",
    )))?;
    writer.write_event(Event::Start(BytesStart::new(
        "eid:TransactionAttestationFormat",
    )))?;
    writer.write_event(Event::Text(BytesText::new(
        response
            .transaction_attestation_response
            .transaction_attestation_format
            .as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new(
        "eid:TransactionAttestationFormat",
    )))?;
    writer.write_event(Event::Start(BytesStart::new(
        "eid:TransactionAttestationData",
    )))?;
    writer.write_event(Event::Text(BytesText::new(
        response
            .transaction_attestation_response
            .transaction_attestation_data
            .as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:TransactionAttestationData")))?;
    writer.write_event(Event::End(BytesEnd::new(
        "eid:TransactionAttestationResponse",
    )))?;

    // --- LevelOfAssuranceResponse ---
    writer.write_event(Event::Start(BytesStart::new(
        "eid:LevelOfAssuranceResponse",
    )))?;
    writer.write_event(Event::Text(BytesText::new(
        &response.level_of_assurance.to_string(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:LevelOfAssuranceResponse")))?;

    // --- EIDTypeResponse ---
    writer.write_event(Event::Start(BytesStart::new("eid:EIDTypeResponse")))?;
    writer.write_event(Event::Start(BytesStart::new("eid:CardCertified")))?;
    writer.write_event(Event::Text(BytesText::new(
        response.eid_type_response.card_certified.as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("eid:CardCertified")))?;
    writer.write_event(Event::End(BytesEnd::new("eid:EIDTypeResponse")))?;

    // --- Result ---
    writer.write_event(Event::Start(BytesStart::new("dss:Result")))?;
    writer.write_event(Event::Start(BytesStart::new("ResultMajor")))?;
    writer.write_event(Event::Text(BytesText::new(&response.result.to_string())))?;
    writer.write_event(Event::End(BytesEnd::new("ResultMajor")))?;
    writer.write_event(Event::End(BytesEnd::new("dss:Result")))?;

    // close getResultResponse, Body, Envelope
    writer.write_event(Event::End(BytesEnd::new("eid:getResultResponse")))?;
    writer.write_event(Event::End(BytesEnd::new("soapenv:Body")))?;
    writer.write_event(Event::End(BytesEnd::new("soapenv:Envelope")))?;

    let xml = writer.into_inner().into_inner();
    Ok(String::from_utf8(xml).expect("UTF-8"))
}

#[cfg(test)]
mod tests {
    use crate::eid::common::models::{
        AttributeRequest, EIDTypeResponse, GeneralDateType, GeneralPlaceType, LevelOfAssurance,
        Operations, PersonalData, PlaceType, RestrictedID, ResultCode,
        TransactionAttestationResponse,
    };

    use super::*;

    #[test]
    fn test_build_get_result_response_complete() {
        let response = GetResultResponse {
            personal_data: PersonalData {
                document_type: "ID".to_string(),
                issuing_state: "D".to_string(),
                date_of_expiry: "2029-10-31".to_string(),
                given_names: "ERIKA".to_string(),
                family_names: "MUSTERMANN".to_string(),
                artistic_name: "".to_string(),
                academic_title: "".to_string(),
                date_of_birth: GeneralDateType {
                    date_string: "19640812".to_string(),
                    date_value: Some("1964-08-12".to_string()),
                },
                place_of_birth: GeneralPlaceType {
                    structured_place: None,
                    freetextplace: Some("BERLIN".to_string()),
                    noplaceinfo: None,
                },
                nationality: "D".to_string(),
                birth_name: "".to_string(),
                place_of_residence: GeneralPlaceType {
                    structured_place: Some(PlaceType {
                        street: "HEIDESTRASSE 17".to_string(),
                        city: "KÖLN".to_string(),
                        state: "NRW".to_string(),
                        country: "D".to_string(),
                        zipcode: "51147".to_string(),
                    }),
                    freetextplace: Some("".to_string()),
                    noplaceinfo: Some("".to_string()),
                },
                community_id: "".to_string(),
                residence_permit_id: "".to_string(),
                restricted_id: RestrictedID {
                    id: "01A4FB509CEBC6595151A4FB5F9C75C6FE01A4FB59CB655A4FB5F9C75C6FEE"
                        .to_string(),
                    id2: "5C6FE01A4FB59CB655A4FB5F9C75C6FEE01A4FB509CEBC6595151A4FB5F9C7"
                        .to_string(),
                },
            },
            fulfils_age_verification: true,
            fulfils_place_verification: true,
            operations_allowed_by_user: Operations {
                document_type: AttributeRequest::ALLOWED,
                issuing_state: AttributeRequest::ALLOWED,
                date_of_expiry: AttributeRequest::ALLOWED,
                given_names: AttributeRequest::ALLOWED,
                family_names: AttributeRequest::ALLOWED,
                artistic_name: None,
                academic_title: None,
                date_of_birth: AttributeRequest::ALLOWED,
                place_of_birth: AttributeRequest::ALLOWED,
                nationality: AttributeRequest::ALLOWED,
                birth_name: AttributeRequest::PROHIBITED,
                place_of_residence: AttributeRequest::ALLOWED,
                community_id: None,
                residence_permit_id: None,
                restricted_id: AttributeRequest::ALLOWED,
                age_verification: None,
                place_verification: None,
            },
            transaction_attestation_response: TransactionAttestationResponse {
                transaction_attestation_format: "format1".to_string(),
                transaction_attestation_data: "attestationdata".to_string(),
            },
            level_of_assurance: LevelOfAssurance::High,
            eid_type_response: EIDTypeResponse {
                card_certified: "USED".to_string(),
                hw_keystore: "ENABLED".to_string(),
                se_certified: "CERTIFIED".to_string(),
                se_endorsed: "ENDORSED".to_string(),
            },
            result: ResultCode::Ok,
        };

        let xml = build_get_result_response(&response).expect("Failed to build XML");

        // PersonalData
        assert!(xml.contains("<eid:DocumentType>ID</eid:DocumentType>"));
        assert!(xml.contains("<eid:IssuingState>D</eid:IssuingState>"));
        assert!(xml.contains("<eid:DateOfExpiry>2029-10-31</eid:DateOfExpiry>"));
        assert!(xml.contains("<eid:GivenNames>ERIKA</eid:GivenNames>"));
        assert!(xml.contains("<eid:FamilyNames>MUSTERMANN</eid:FamilyNames>"));

        // Dates
        assert!(xml.contains("<eid:DateString>19640812</eid:DateString>"));
        assert!(xml.contains("<eid:DateValue>1964-08-12</eid:DateValue>"));

        // PlaceOfResidence
        assert!(xml.contains("<eid:Street>HEIDESTRASSE 17</eid:Street>"));
        assert!(xml.contains("<eid:City>KÖLN</eid:City>"));
        assert!(xml.contains("<eid:State>NRW</eid:State>"));
        assert!(xml.contains("<eid:ZipCode>51147</eid:ZipCode>"));
        assert!(xml.contains("<eid:FreetextPlace>BERLIN</eid:FreetextPlace>"));
        assert!(xml.contains("<eid:Nationality>D</eid:Nationality>"));
        assert!(xml.contains(
            "<eid:ID>01A4FB509CEBC6595151A4FB5F9C75C6FE01A4FB59CB655A4FB5F9C75C6FEE</eid:ID>"
        ));
        assert!(xml.contains(
            "<eid:ID2>5C6FE01A4FB59CB655A4FB5F9C75C6FEE01A4FB509CEBC6595151A4FB5F9C7</eid:ID2>"
        ));
        // Fulfils*
        assert!(xml.contains("<eid:FulfilsRequest>true</eid:FulfilsRequest>"));

        // OperationsAllowedByUser document_type and issuing_state
        assert!(xml.contains("<eid:DocumentType>ALLOWED</eid:DocumentType>"));
        assert!(xml.contains("<eid:IssuingState>ALLOWED</eid:IssuingState>"));

        // TransactionAttestationResponse
        assert!(xml.contains(
            "<eid:TransactionAttestationFormat>format1</eid:TransactionAttestationFormat>"
        ));
        assert!(xml.contains(
            "<eid:TransactionAttestationData>attestationdata</eid:TransactionAttestationData>"
        ));

        // LevelOfAssurance & EIDTypeResponse & Result
        assert!(xml.contains("<eid:LevelOfAssuranceResponse>High</eid:LevelOfAssuranceResponse>"));
        assert!(xml.contains("<eid:CardCertified>USED</eid:CardCertified>"));
        assert!(xml.contains(
            "<ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</ResultMajor>"
        ));
    }
}
