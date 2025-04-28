use quick_xml::Writer;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use std::io::Cursor;

use super::model::UseIDResponse;

/// Builds a SOAP XML envelope for the `useIDResponse` using `quick-xml` library.
///
/// This function constructs a well-formed SOAP XML response for the `UseIDResponse` struct, which includes
/// the necessary envelope, header, body, and session data required for eID authentication. It uses the
/// `quick-xml` library for efficient XML generation and writes the XML to a `Writer`, which is then converted
/// into a UTF-8 string for easy consumption.
///
/// ## Parameters
/// - `response`: The `UseIDResponse` struct containing the data to be included in the XML response. This struct
///   holds the session data, optional eCard server address, PSK (Pre-Shared Key), and result status for the response.
///
/// ## Returns
/// - `Result<String, std::io::Error>`: A result containing the generated SOAP XML response as a `String` on success,
///   or an `io::Error` if an error occurs during the XML generation.
///
/// ## XML Structure
/// The resulting SOAP XML will have the following structure:
///
/// ```xml
/// <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/" xmlns:dss="urn:oasis:names:tc:dss:1.0:core:schema">
///     <soapenv:Header/>
///     <soapenv:Body>
///         <eid:useIDResponse>
///             <eid:Session>
///                 <eid:ID>...</eid:ID>
///             </eid:Session>
///             <eid:eCardServerAddress>...</eid:eCardServerAddress> <!-- optional -->
///             <eid:PSK>
///                 <eid:ID>...</eid:ID>
///                 <eid:Key>...</eid:Key>
///             </eid:PSK>
///             <dss:Result>
///                 <ResultMajor>...</ResultMajor>
///             </dss:Result>
///         </eid:useIDResponse>
///     </soapenv:Body>
/// </soapenv:Envelope>
/// ```
///
/// ## Details
/// - **Envelope**: The `soapenv:Envelope` element is the root of the SOAP message and contains namespaces for
///   `soapenv`, `eid`, and `dss`.
/// - **Header**: The header is empty (`<soapenv:Header/>`), as required by the protocol.
/// - **Body**: The body contains the main response content under the `eid:useIDResponse` tag. It includes:
///   - `eid:Session`: Contains the `eid:ID` (Session ID).
///   - `eid:eCardServerAddress`: An optional element representing the address of the eCard server, if provided.
///   - `eid:PSK`: Contains the Pre-Shared Key information with `eid:ID` and `eid:Key`.
///   - `dss:Result`: Contains the result major code for the response status.
///
/// ## Usage Example
/// Here's an example of how to use this function to generate a SOAP XML response:
///
/// ```rust
/// let response = UseIDResponse {
///     session: "session123".to_string(),
///     ecard_server_address: Some("http://ecard.server.com".to_string()),
///     psk: PSK { id: "psk123".to_string(), key: "secretkey".to_string() },
///     result: 0,
/// };
/// let soap_response = build_use_id_response(&response)?;
/// println!("{}", soap_response);
/// ```
///
/// ## Error Handling
/// This function may return an `std::io::Error` if any of the `write_event` operations fail.
/// Ensure that the `response` data is properly formatted and valid for the SOAP structure.
///
#[allow(dead_code)]
pub fn build_use_id_response(response: &UseIDResponse) -> Result<String, std::io::Error> {
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;

    // Envelope start
    let mut envelope = BytesStart::new("soapenv:Envelope");
    envelope.push_attribute(("xmlns:soapenv", "http://schemas.xmlsoap.org/soap/envelope/"));
    envelope.push_attribute(("xmlns:eid", "http://bsi.bund.de/eID/"));
    envelope.push_attribute(("xmlns:dss", "urn:oasis:names:tc:dss:1.0:core:schema"));
    writer.write_event(Event::Start(envelope))?;

    // Header
    writer.write_event(Event::Empty(BytesStart::new("soapenv:Header")))?;

    // Body
    writer.write_event(Event::Start(BytesStart::new("soapenv:Body")))?;

    writer.write_event(Event::Start(BytesStart::new("eid:useIDResponse")))?;

    // Session
    writer.write_event(Event::Start(BytesStart::new("eid:Session")))?;
    writer.write_event(Event::Start(BytesStart::new("eid:ID")))?;
    writer.write_event(Event::Text(BytesText::new(response.session.as_str())))?;
    writer.write_event(Event::End(BytesEnd::new("eid:ID")))?;
    writer.write_event(Event::End(BytesEnd::new("eid:Session")))?;

    // eCardServerAddress (optional)
    if let Some(address) = &response.ecard_server_address {
        writer.write_event(Event::Start(BytesStart::new("eid:eCardServerAddress")))?;
        writer.write_event(Event::Text(BytesText::new(address.as_str())))?;
        writer.write_event(Event::End(BytesEnd::new("eid:eCardServerAddress")))?;
    }

    // PSK
    writer.write_event(Event::Start(BytesStart::new("eid:PSK")))?;
    writer.write_event(Event::Start(BytesStart::new("eid:ID")))?;
    writer.write_event(Event::Text(BytesText::new(response.psk.id.as_str())))?;
    writer.write_event(Event::End(BytesEnd::new("eid:ID")))?;
    writer.write_event(Event::Start(BytesStart::new("eid:Key")))?;
    writer.write_event(Event::Text(BytesText::new(response.psk.key.as_str())))?;
    writer.write_event(Event::End(BytesEnd::new("eid:Key")))?;
    writer.write_event(Event::End(BytesEnd::new("eid:PSK")))?;

    // Result
    writer.write_event(Event::Start(BytesStart::new("dss:Result")))?;
    writer.write_event(Event::Start(BytesStart::new("ResultMajor")))?;
    writer.write_event(Event::Text(BytesText::new(
        format!("{}", response.result).as_str(),
    )))?;
    writer.write_event(Event::End(BytesEnd::new("ResultMajor")))?;
    writer.write_event(Event::End(BytesEnd::new("dss:Result")))?;

    writer.write_event(Event::End(BytesEnd::new("eid:useIDResponse")))?;

    writer.write_event(Event::End(BytesEnd::new("soapenv:Body")))?;
    writer.write_event(Event::End(BytesEnd::new("soapenv:Envelope")))?;

    let result = writer.into_inner().into_inner();
    Ok(String::from_utf8(result).expect("XML should be UTF-8"))
}

#[cfg(test)]
mod tests {

    use crate::eid::{common::models::ResultCode, use_id::model::PSK};

    use super::*;

    #[test]
    fn test_build_use_id_response_basic() {
        // Arrange
        let response = UseIDResponse {
            session: "1234567890abcdef1234567890abcdef".to_string(),
            psk: PSK {
                id: "0987654321abcdef1234567890abcdef".to_string(),
                key: "fedcba0987654321fedcba0987654321".to_string(),
            },
            result: ResultCode::Ok,
            ecard_server_address: None,
        };

        let generated_xml = build_use_id_response(&response).expect("Failed to build XML");

        let expected_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:eid="http://bsi.bund.de/eID/"
                  xmlns:dss="urn:oasis:names:tc:dss:1.0:core:schema">
    <soapenv:Header />
    <soapenv:Body>
        <eid:useIDResponse>
            <eid:Session>
                <eid:ID>1234567890abcdef1234567890abcdef</eid:ID>
            </eid:Session>
            <eid:PSK>
                <eid:ID>0987654321abcdef1234567890abcdef</eid:ID>
                <eid:Key>fedcba0987654321fedcba0987654321</eid:Key>
            </eid:PSK>
            <dss:Result>
                <ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</ResultMajor>
            </dss:Result>
        </eid:useIDResponse>
    </soapenv:Body>
</soapenv:Envelope>"#;

        // Normalize whitespace for comparison (optional but safer)
        let normalize = |s: &str| s.split_whitespace().collect::<String>();

        // Assert
        assert_eq!(normalize(&generated_xml), normalize(expected_xml));
    }
}
