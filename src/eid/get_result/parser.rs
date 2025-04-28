use super::{error::GetResultError, model::GetResultRequest};
use quick_xml::{Reader, events::Event};

/// Parses the XML string representing a `getResultRequest` and extracts the relevant data.
///
/// This function reads an XML input in the expected format, validates its structure, and
/// extracts the `session_id` and `request_counter` from the request. If the `RequestCounter`
/// tag is missing, the counter will default to `0`. If the `Session` tag is missing, the
/// session ID will be an empty string.
///
/// # Arguments
///
/// * `xml` - A string slice containing the XML data to be parsed.
///
/// # Returns
///
/// Returns a `Result<GetResultRequest, GetResultError>`. On success, it returns a `GetResultRequest`
/// struct containing the `session_id` and `request_counter`. On failure, it returns an error indicating
/// what went wrong during parsing.
///
/// # Errors
///
/// This function can return an error if the XML does not follow the expected structure, such as:
///
/// - Invalid tags or attributes.
/// - Missing required elements like `Session` or `RequestCounter`.
///
/// # Example
///
/// ```rust
/// let xml_data = r#"
/// <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/">
///     <soapenv:Body>
///         <eid:getResultRequest>
///             <eid:Session>
///                 <eid:ID>1234567890abcdef1234567890abcdef</eid:ID>
///             </eid:Session>
///             <eid:RequestCounter>1</eid:RequestCounter>
///         </eid:getResultRequest>
///     </soapenv:Body>
/// </soapenv:Envelope>
/// "#;
///
/// let result = parse_get_result_request(xml_data);
/// assert!(result.is_ok(), "Parsing failed");
/// let request = result.unwrap();
/// assert_eq!(request.session_id, "1234567890abcdef1234567890abcdef");
/// assert_eq!(request.request_counter, 1);
/// ```
///
/// This function is used to extract and validate the key elements in the `getResultRequest`
/// XML format, which is typically used for handling eID-based requests.
pub fn parse_get_result_request(xml: &str) -> Result<GetResultRequest, GetResultError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut get_result_request = GetResultRequest::default();

    while let Ok(event) = reader.read_event_into(&mut buf) {
        match event {
            Event::Start(ref e) => match e.name().as_ref() {
                b"eid:getResultRequest" => loop {
                    match reader.read_event_into(&mut buf) {
                        Ok(Event::Start(ref e)) if e.name().as_ref() == b"eid:Session" => loop {
                            match reader.read_event_into(&mut buf) {
                                Ok(Event::Start(ref e)) if e.name().as_ref() == b"eid:ID" => {
                                    if let Ok(Event::Text(text)) = reader.read_event_into(&mut buf)
                                    {
                                        get_result_request.session =
                                            text.unescape().ok().unwrap_or_default().to_string();
                                    }
                                }
                                Ok(Event::End(ref e)) if e.name().as_ref() == b"eid:Session" => {
                                    break;
                                }
                                _ => (),
                            }
                        },
                        Ok(Event::Start(ref e)) if e.name().as_ref() == b"eid:RequestCounter" => {
                            if let Ok(Event::Text(text)) = reader.read_event_into(&mut buf) {
                                get_result_request.request_counter = text
                                    .unescape()
                                    .ok()
                                    .and_then(|s| s.parse::<u8>().ok())
                                    .unwrap_or(0);
                            }
                        }
                        Ok(Event::End(ref e)) if e.name().as_ref() == b"eid:getResultRequest" => {
                            break;
                        }
                        Ok(_) => (),
                        Err(e) => {
                            return Err(GetResultError::GenericError(format!(
                                "Error parsing getResultRequest: {}",
                                e
                            )));
                        }
                    }
                    buf.clear();
                },
                _ => (),
            },
            Event::Eof => break,
            _ => (),
        }
        buf.clear();
    }

    Ok(get_result_request)
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
            request.session, "1234567890abcdef1234567890abcdef",
            "Session ID mismatch"
        );
        assert_eq!(request.request_counter, 1, "Request counter mismatch");
    }

    #[test]
    fn test_parse_get_result_request_missing_data() {
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

        assert!(
            result.is_ok(),
            "Parsing failed with error: {:?}",
            result.err()
        );

        let request = result.unwrap();
        assert_eq!(
            request.session, "1234567890abcdef1234567890abcdef",
            "Session ID mismatch"
        );
        assert_eq!(
            request.request_counter, 0,
            "Request counter should be 0 when missing"
        );
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
            result.is_ok(),
            "Parsing failed with error: {:?}",
            result.err()
        );

        let request = result.unwrap();
        assert_eq!(
            request.session, "",
            "Session ID should be empty when missing"
        );
        assert_eq!(request.request_counter, 1, "Request counter mismatch");
    }
}
