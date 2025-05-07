use quick_xml::se::to_string;

use super::{
    error::GetResultError,
    model::{GetResultResponse, GetResultResponseBody, GetResultResponseEnvelope, SoapHeader},
};

/// Serializes a `GetResultResponse` into a fully namespaced SOAP XML envelope.
///
/// Uses `serde` and `quick-xml` to serialize the provided response data into XML,
/// injects the required `xmlns:` namespace attributes onto the `<soapenv:Envelope>` element,
/// and prepends the standard XML declaration, producing a valid SOAP message compliant
/// with the eID service schema (`soapenv`, `eid`, `dss`).
///
/// # Arguments
/// * `response` - A `GetResultResponse` value containing all payload fields.
///
/// # Returns
/// * `Ok(String)` containing the UTF-8 encoded SOAP XML document.
/// * `Err(GetResultError::GenericError)` if serialization via Serde fails.
///
/// # Example
/// ```rust
/// let response = GetResultResponse { /* ... */ };
/// let xml_string = build_get_result_response(response)?;
/// println!("{}", xml_string);
/// ```
pub fn build_get_result_response(response: GetResultResponse) -> Result<String, GetResultError> {
    let envelope = GetResultResponseEnvelope {
        header: SoapHeader::default(),
        body: GetResultResponseBody {
            get_result_response: response,
        },
    };
    let xml = to_string(&envelope).map_err(|e| GetResultError::GenericError(e.to_string()))?;

    let xml_with_ns = xml.replacen(
                    "<soapenv:Envelope",
                        "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:eid=\"http://bsi.bund.de/eID/\" xmlns:dss=\"urn:oasis:names:tc:dss:1.0:core:schema\"",
                    1,
                );

    // 3) Prepend standard XML declaration
    Ok(format!(r#"<?xml version="1.0" encoding="UTF-8"?>"#) + &xml_with_ns)
}

#[cfg(test)]
mod tests {

    use crate::eid::{
        common::models::{
            AttributeResponder, EIDTypeResponse, GeneralDateType, GeneralPlaceType,
            LevelOfAssurance, OperationsResponder, PersonalData, PlaceType, RestrictedID,
            ResultMajor, TransactionAttestationResponse,
        },
        get_result::model::FulfilsRequest,
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
                birth_name: "NOTONCHIP".to_string(),
                place_of_residence: GeneralPlaceType {
                    structured_place: Some(PlaceType {
                        street: "HEIDESTRASSE 17".to_string(),
                        city: "KÖLN".to_string(),
                        state: "".to_string(), 
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
            fulfils_age_verification: FulfilsRequest {
                fulfils_request: true,
            },
            fulfils_place_verification: FulfilsRequest {
                fulfils_request: true,
            },
            operations_allowed_by_user: OperationsResponder {
                document_type: AttributeResponder::ALLOWED,
                issuing_state: AttributeResponder::ALLOWED,
                date_of_expiry: AttributeResponder::ALLOWED,
                given_names: AttributeResponder::ALLOWED,
                family_names: AttributeResponder::ALLOWED,
                artistic_name: None,
                academic_title: None,
                date_of_birth: AttributeResponder::ALLOWED,
                place_of_birth: AttributeResponder::ALLOWED,
                nationality: AttributeResponder::ALLOWED,
                birth_name: AttributeResponder::PROHIBITED,
                place_of_residence: AttributeResponder::ALLOWED,
                community_id: Some(AttributeResponder::ALLOWED),
                residence_permit_id: Some(AttributeResponder::ALLOWED),
                restricted_id: AttributeResponder::ALLOWED,
                age_verification: Some(AttributeResponder::ALLOWED),
                place_verification: Some(AttributeResponder::ALLOWED),
            },
            transaction_attestation_response: TransactionAttestationResponse {
                transaction_attestation_format: "http://bsi.bund.de/eID/ExampleAttestationFormat"
                    .to_string(),
                transaction_attestation_data: "V6INOOUsHouL9nYaRwR6RpX5WzccQXv51bIvvpY4Lsbp/VOPvG1ozxQCjo6JOi4xAv9/6b8G2PxaVv8bwdpFR/CN05xsnzxijzfemooKwve3Fl3005OX6dwkVyNQlZxXaWb3eUcYPA\\MEwHSkhzP25ZM/J+CQHHaqLih6JW6wxSvUbuD307sjzkeaMkjJr9tXI9QcUmGmpHBWEWwon56HkWKGL1Dl0XH4\\YuYhKMsTj2yjUJNlLH8OAm9cEX0ptQJlVTMRvNGRk53eUESnfhtQrVSm9bS63v+A9sGPrRlUIquCpcusX1nZe6\\omAzs2tY0S04+s1fNvgHXKmQi24wIdhhbtFPbB2n2j9dAB8xjfGgEcsG3wPMliP6d"
                    .to_string(),
            },
            level_of_assurance: LevelOfAssurance::Hoch.to_string(),
            eid_type_response: EIDTypeResponse {
                card_certified: "USED".to_string(),
                hw_keystore: "".to_string(),   
                se_certified: "".to_string(),  
                se_endorsed: "".to_string(),    
            },
            result: ResultMajor {
                result_major: "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok".to_string(),
            },
        };

        let xml = build_get_result_response(response).expect("Failed to build XML");

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
        assert!(xml.contains("<eid:State/>"));
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
            "<eid:TransactionAttestationFormat>http://bsi.bund.de/eID/ExampleAttestationFormat</eid:TransactionAttestationFormat>"
        ));
        assert!(xml.contains(
            "<eid:TransactionAttestationData>V6INOOUsHouL9nYaRwR6RpX5WzccQXv51bIvvpY4Lsbp/VOPvG1ozxQCjo6JOi4xAv9/6b8G2PxaVv8bwdpFR/CN05xsnzxijzfemooKwve3Fl3005OX6dwkVyNQlZxXaWb3eUcYPA\\MEwHSkhzP25ZM/J+CQHHaqLih6JW6wxSvUbuD307sjzkeaMkjJr9tXI9QcUmGmpHBWEWwon56HkWKGL1Dl0XH4\\YuYhKMsTj2yjUJNlLH8OAm9cEX0ptQJlVTMRvNGRk53eUESnfhtQrVSm9bS63v+A9sGPrRlUIquCpcusX1nZe6\\omAzs2tY0S04+s1fNvgHXKmQi24wIdhhbtFPbB2n2j9dAB8xjfGgEcsG3wPMliP6d</eid:TransactionAttestationData>"
        ));

        // Check all ALLOWED/PROHIBITED entries in OperationsAllowedByUser
        assert!(xml.contains("<eid:DateOfExpiry>ALLOWED</eid:DateOfExpiry>"));
        assert!(xml.contains("<eid:GivenNames>ALLOWED</eid:GivenNames>"));
        assert!(xml.contains("<eid:FamilyNames>ALLOWED</eid:FamilyNames>"));
        assert!(xml.contains("<eid:DateOfBirth>ALLOWED</eid:DateOfBirth>"));
        assert!(xml.contains("<eid:PlaceOfBirth>ALLOWED</eid:PlaceOfBirth>"));
        assert!(xml.contains("<eid:Nationality>ALLOWED</eid:Nationality>"));
        assert!(xml.contains("<eid:BirthName>NOTONCHIP</eid:BirthName>"));
        assert!(xml.contains("<eid:PlaceOfResidence>ALLOWED</eid:PlaceOfResidence>"));
        assert!(xml.contains("<eid:RestrictedID>ALLOWED</eid:RestrictedID>"));
        assert!(xml.contains("<eid:AgeVerification>ALLOWED</eid:AgeVerification>"));
        assert!(xml.contains("<eid:PlaceVerification>ALLOWED</eid:PlaceVerification>"));

        // LevelOfAssurance & EIDTypeResponse & Result
        assert!(xml.contains("<eid:LevelOfAssuranceResponse>http://bsi.bund.de/eID/LoA/hoch</eid:LevelOfAssuranceResponse>"));
        assert!(xml.contains("<eid:CardCertified>USED</eid:CardCertified>"));
        assert!(xml.contains(
            "<ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</ResultMajor>"
        ));
    }
}
