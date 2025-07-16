use super::error::GetResultError;
use super::model::GetResultRequest;
use crate::eid::soap::parser::deserialize_soap;

pub fn parse_get_result_request(xml: &str) -> Result<GetResultRequest, GetResultError> {
    let request: GetResultRequest = deserialize_soap(xml, "eid:getResultRequest")?;
    if request.session.id.is_empty() {
        return Err(GetResultError::GenericError(
            "Session ID cannot be empty".to_string(),
        ));
    }
    if request.request_counter == 0 {
        return Err(GetResultError::InvalidRequestCounter);
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_get_result_request_missing_request_counter() {
        let xml_data = r#"
        <?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/">
            <soapenv:Header/>
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
            <soapenv:Header/>
            <soapenv:Body>
                <eid:getResultRequest>
                    <eid:Request Tarier>1</eid:RequestCounter>
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
