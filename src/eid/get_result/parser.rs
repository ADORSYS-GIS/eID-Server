use crate::eid::common::models::Session;

use super::{
    error::GetResultError,
    model::{GetResultRequest, GetResultRequestEnvelope},
};
use quick_xml::de::from_str;

/// Parses a SOAP `getResultRequest` XML into a `GetResultRequest` using serde deserialization.
///
/// Uses `quick-xml`’s `de` feature to map the `<Body><getResultRequest>` element (ignoring
/// namespace prefixes) directly into Rust structs. If `<Session>` or `<RequestCounter>` are
/// omitted, they default to an empty `Session.id` and `0`, respectively.
///
/// # Arguments
///
/// * `xml` – The complete SOAP envelope as a `&str`.
///
/// # Returns
///
/// * `Ok(GetResultRequest)` containing:
///   * `session: Session { id: String }`
///   * `request_counter: u8`
/// * `Err(GetResultError)` if deserialization fails (e.g., malformed XML).
///
/// # Errors
///
/// Returns `GetResultError::GenericError` if the underlying `quick_xml::de::from_str` call
/// cannot parse the document or misses required elements.
///
/// # Example
///
/// ```rust
/// let xml = r#"
/// <?xml version="1.0" encoding="UTF-8"?>
/// <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/">
///   <soapenv:Body>
///     <eid:getResultRequest>
///       <eid:Session><eid:ID>abcdef1234567890</eid:ID></eid:Session>
///       <eid:RequestCounter>5</eid:RequestCounter>
///     </eid:getResultRequest>
///   </soapenv:Body>
/// </soapenv:Envelope>
/// "#;
///
/// let req = parse_get_result_request(xml).unwrap();
/// assert_eq!(req.session.id, "abcdef1234567890");
/// assert_eq!(req.request_counter, 5);
/// ```
pub fn parse_get_result_request(xml: &str) -> Result<GetResultRequest, GetResultError> {
    let env: GetResultRequestEnvelope = from_str(xml)
        .map_err(|e| GetResultError::GenericError(format!("XML deserialization failed: {}", e)))?;

    let req = env.body.request;
    Ok(GetResultRequest {
        session: Session { id: req.session.id },
        request_counter: req.request_counter,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_get_result_request_valid() {
        let xml_data = r#"
        <?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/">
            <soapenv:Header />
            <soapenv:Body>
                <eid:getResultRequest>
                    <eid:Session>
                        <eid:ID>1234567890abcdef1234567890abcdef</eid:ID>
                    </eid:Session>
                    <eid:RequestCounter>1</eid:RequestCounter>
                </eid:getResultRequest>
            </soapenv:Body>
        </soapenv:Envelope>
        "#;

        let result = parse_get_result_request(xml_data);

        assert!(
            result.is_ok(),
            "Parsing failed with error: {:?}",
            result.err()
        );
        let request = result.unwrap();
        assert_eq!(
            request.session.id, "1234567890abcdef1234567890abcdef",
            "Session ID mismatch"
        );
        assert_eq!(request.request_counter, 1, "Request counter mismatch");
    }

    #[test]
    fn test_parse_get_result_request_missing_request_counter() {
        let xml_data = r#"
        <?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/">
            <soapenv:Header />
            <soapenv:Body>
                <eid:getResultRequest>
                    <eid:Session>
                        <eid:ID>1234567890abcdef1234567890abcdef</eid:ID>
                    </eid:Session>
                </eid:getResultRequest>
            </soapenv:Body>
        </soapenv:Envelope>
        "#;

        let result = parse_get_result_request(xml_data);

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_get_result_request_missing_session() {
        let xml_data = r#"
        <?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/">
            <soapenv:Header />
            <soapenv:Body>
                <eid:getResultRequest>
                    <eid:RequestCounter>1</eid:RequestCounter>
                </eid:getResultRequest>
            </soapenv:Body>
        </soapenv:Envelope>
        "#;

        let result = parse_get_result_request(xml_data);

        assert!(
            result.is_err(),
            "Parsing should fail due to missing session"
        );
    }
}
