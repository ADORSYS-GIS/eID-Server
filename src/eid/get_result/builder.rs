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
        header: SoapHeader,
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

    Ok(r#"<?xml version="1.0" encoding="UTF-8"?>"#.to_string() + &xml_with_ns)
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
                community_id: AttributeResponder::ALLOWED,
                residence_permit_id: AttributeResponder::ALLOWED,
                restricted_id: AttributeResponder::ALLOWED,
                age_verification: AttributeResponder::ALLOWED,
                place_verification: AttributeResponder::ALLOWED,
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

        // Normalize whitespace for comparison
        let normalize = |s: &str| s.split_whitespace().collect::<String>();

        let xml = build_get_result_response(response).expect("Failed to build XML");
        let xml_file = std::fs::read_to_string("test_data/get_result_response.xml").unwrap();

        assert_eq!(normalize(&xml), normalize(&xml_file));
    }
}
