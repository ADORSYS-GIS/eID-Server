use crate::eid::{
    common::models::Session,
    get_result::{error::GetResultError, model::GetResultRequest},
    soap::{error::SoapError, helpers::deserialize_soap_request},
};

/// Parses a SOAP `getResultRequest` XML into a `GetResultRequest`.
///
/// # Arguments
/// * `xml` – The complete SOAP envelope as a `&str`.
///
/// # Returns
/// * `Ok(GetResultRequest)` containing `session` and `request_counter`.
/// * `Err(GetResultError)` if deserialization fails or required fields are missing.
///
/// # Example
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
    #[derive(serde::Deserialize)]
    #[serde(rename = "{http://bsi.bund.de/eID/}getResultRequest")]
    struct RawRequest {
        #[serde(rename = "{http://bsi.bund.de/eID/}Session")]
        session: Session,
        #[serde(rename = "{http://bsi.bund.de/eID/}RequestCounter")]
        request_counter: u8,
    }

    let raw: crate::eid::soap::envelope::SoapRequestEnvelope<RawRequest> =
        deserialize_soap_request(xml).map_err(|e| match e {
            SoapError::DeserializationError { path, message, .. } => {
                GetResultError::GenericError(format!("Failed to parse XML at {path}: {message}"))
            }
            _ => GetResultError::GenericError(e.to_string()),
        })?;

    let req = raw.body.request;
    if req.session.id.is_empty() {
        return Err(GetResultError::GenericError(
            "Missing or empty Session ID".to_string(),
        ));
    }
    Ok(GetResultRequest {
        session: req.session,
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
            <soapenv:Header/>
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
    fn test_parse_get_result_request_missing_session() {
        let xml_data = r#"
        <?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bs.i.bund.de/eID/">
            <soapenv:Header/>
            <soapenv:Body>
                <eid:getResultRequest>
                    <eid:RequestCounter>1</eid:RequestCounter>
                </eid:getResultRequest>
            </soapenv:Body>
        </soapenv:Envelope>
        "#;

        let result = parse_get_result_request(xml_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_get_result_request_empty_session_id() {
        let xml_data = r#"
        <?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/">
            <soapenv:Header/>
            <soapenv:Body>
                <eid:getResultRequest>
                    <eid:Session>
                        <eid:ID></eid:ID>
                    </eid:Session>
                    <eid:RequestCounter>1</eid:RequestCounter>
                </eid:getResultRequest>
            </soapenv:Body>
        </soapenv:Envelope>
        "#;

        let result = parse_get_result_request(xml_data);
        assert!(matches!(result, Err(GetResultError::GenericError(_))));
    }
}
