use crate::eid::use_id::{error::UseIdError, model::{UseIDRequest, UseIDRequestEnvelope}};
use quick_xml::de::from_str;

/// Parses a `useIDRequest` SOAP XML message into a structured `UseIDRequest`.
///
/// This function extracts and maps the following data fields:
/// - `UseOperations`: list of data group operations with required/allowed levels.
/// - `AgeVerificationRequest`: minimum age for verification.
/// - `PlaceVerificationRequest`: community ID for location verification.
/// - `TransactionInfo`: optional transaction string for EAC1.
/// - `TransactionAttestationRequest`: includes attestation format and optional context.
/// - `LevelOfAssuranceRequest`: expected assurance level as URI.
/// - `EIDTypeRequest`: allowed or denied types of eID tokens (e.g., SECertified).
/// - `PSK`: pre-shared key for the TLS-bound session.
///
/// # Arguments
/// * `xml` - A string slice containing the raw SOAP envelope XML.
///
/// # Returns
/// * `Ok(UseIDRequest)` on successful parsing and validation.
/// * `Err(UseIdError)` if the XML is malformed or required fields are invalid.
/// * `Ok(UseIDRequest)` on successful parsing
/// * `Err(UseIdError)` if the XML is malformed or required values are invalid
///
/// # Errors
/// This function may return an error if:
/// - Required XML tags are malformed or missing
/// - Unexpected data is encountered in known fields
///
/// # Example
/// ```rust
/// let xml = include_str!("test_data/use_id_request.xml");
/// let parsed = parse_use_id_request(xml)?;
/// assert_eq!(parsed.age_verification, Some(18));
/// ```
#[allow(dead_code)]
pub fn parse_use_id_request(xml: &str) -> Result<UseIDRequest, UseIdError> {
    let env: UseIDRequestEnvelope = from_str(xml)
        .map_err(|e| UseIdError::GenericError(format!("XML deserialization failed: {e}")))?;

    let req = env._body;
    let result = UseIDRequest {
        _use_operations: req._use_id_request._use_operations,
        _age_verification: req._use_id_request._age_verification,
        _place_verification: req._use_id_request._place_verification,
        _transaction_info: req._use_id_request._transaction_info,
        _transaction_attestation_request: req._use_id_request._transaction_attestation_request,
        _level_of_assurance: req._use_id_request._level_of_assurance,
        _eid_type_request: req._use_id_request._eid_type_request,
        _psk: req._use_id_request._psk,
    };
    Ok(result)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse_valid_use_id_request() {
        let xml = r#"
        <?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/">
            <soapenv:Header/>
            <soapenv:Body>
                <eid:useIDRequest>
                    <eid:AgeVerification>
                        <eid:Age>18</eid:Age>
                    </eid:AgeVerification>
                    <eid:PlaceVerification>
                        <eid:CommunityID>027605</eid:CommunityID>
                    </eid:PlaceVerification>
                    <eid:TransactionAttestationRequest>
                        <eid:TransactionContext>id599456-df</eid:TransactionContext>
                    </eid:TransactionAttestationRequest>
                </eid:useIDRequest>
            </soapenv:Body>
        </soapenv:Envelope>
        "#;

        let parsed = parse_use_id_request(xml);
        assert!(
            parsed.is_ok(),
            "Expected successful parse, got error: {:?}",
            parsed
        );

        let req = parsed.unwrap();
        assert_eq!(req._age_verification._age, 18, "Expected age to be 18");
        assert_eq!(req._place_verification._community_id, "027605");
        assert_eq!(
            req._transaction_attestation_request
                .as_ref()
                .unwrap()
                .transaction_context
                .as_ref()
                .unwrap(),
            "id599456-df"
        );
    }
}
