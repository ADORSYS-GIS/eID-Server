use crate::eid::{
    common::models::AttributeRequester,
    soap::{error::SoapError, helpers::deserialize_soap_request},
    use_id::{error::UseIdError, model::UseIDRequest},
};

/// Parses a `useIDRequest` SOAP XML message into a structured `UseIDRequest`.
///
/// # Arguments
/// * `xml` - A string slice containing the raw SOAP envelope XML.
///
/// # Returns
/// * `Ok(UseIDRequest)` on successful parsing.
/// * `Err(UseIdError)` if the XML is malformed or required fields are invalid.
///
/// # Example
/// ```rust
/// let xml = include_str!("use_id_request.xml");
/// let parsed = parse_use_id_request(xml)?;
/// assert_eq!(parsed._age_verification._age, 18);
/// ```
pub fn parse_use_id_request(xml: &str) -> Result<UseIDRequest, UseIdError> {
    #[derive(serde::Deserialize)]
    struct RawRequest {
        #[serde(rename = "eid:useIDRequest")]
        use_id_request: UseIDRequest,
    }

    let raw: RawRequest = deserialize_soap_request(xml).map_err(|e| match e {
        SoapError::DeserializationError { path, message, .. } => {
            UseIdError::GenericError(format!("Failed to parse XML at {path}: {message}"))
        }
        _ => UseIdError::GenericError(e.to_string()),
    })?;

    let req = raw.use_id_request;
    if req._use_operations.document_type == AttributeRequester::REQUIRED
        && req._use_operations.issuing_state == AttributeRequester::REQUIRED
        && req._age_verification._age == 0
    {
        return Err(UseIdError::GenericError(
            "Invalid request: required fields missing or invalid".to_string(),
        ));
    }
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_use_id_request() {
        let xml = std::fs::read_to_string("test_data/use_id_request.xml").unwrap();

        let parsed = parse_use_id_request(&xml);

        assert!(
            parsed.is_ok(),
            "Expected successful parse, got error: {:?}",
            parsed.unwrap()
        );

        let req = parsed.unwrap();

        assert_eq!(req._age_verification._age, 18, "Expected age to be 18");

        assert_eq!(req._place_verification._community_id, "027605".to_string());

        assert_eq!(
            req._transaction_attestation_request
                .as_ref()
                .unwrap()
                .transaction_context
                .clone()
                .unwrap(),
            "id599456-df"
        );
    }

    #[test]
    fn test_parse_invalid_use_id_request() {
        let xml = r#"
        <?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/">
            <soapenv:Body>
                <eid:useIDRequest>
                    <eid:UseOperations>
                        <eid:DocumentType>REQUIRED</eid:DocumentType>
                        <eid:IssuingState>REQUIRED</eid:IssuingState>
                    </eid:UseOperations>
                    <eid:AgeVerificationRequest>
                        <eid:Age>0</eid:Age>
                    </eid:AgeVerificationRequest>
                    <eid:PlaceVerificationRequest>
                        <eid:CommunityID>027605</eid:CommunityID>
                    </eid:PlaceVerificationRequest>
                </eid:useIDRequest>
            </soapenv:Body>
        </soapenv:Envelope>
        "#;

        let result = parse_use_id_request(xml);
        assert!(matches!(result, Err(UseIdError::GenericError(_))));
    }
}
