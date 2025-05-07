use quick_xml::se::to_string;

use super::{
    error::GetResultError,
    model::{GetResultResponse, GetResultResponseBody, GetResultResponseEnvelope},
};

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
/// * `Err(GetResultError)` - If an error occurs during writing to the underlying buffer.
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
pub fn build_get_result_response(response: GetResultResponse) -> Result<String, GetResultError> {
    let envelope = GetResultResponseEnvelope {
        soapenv: "http://schemas.xmlsoap.org/soap/envelope/",
        eid: "http://bsi.bund.de/eID/",
        dss: "urn:oasis:names:tc:dss:1.0:core:schema",
        body: GetResultResponseBody {
            get_result_response: response,
        },
    };

    Ok(to_string(&envelope).map_err(|_| {
        GetResultError::GenericError("{failed to build GetResultResponse}".to_string())
    })?)
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
                    freetextplace: None,
                    noplaceinfo: None,
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

        let xml = build_get_result_response(response).expect("Failed to build XML");
        println!("{}", xml);

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
