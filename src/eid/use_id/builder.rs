use std::io;

use quick_xml::se::to_string;

use crate::eid::common::models::Header;

use super::model::{UseIDResponse, UseIdBody, UseIdEnvelope};

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
pub fn build_use_id_response(response: &UseIDResponse) -> Result<String, std::io::Error> {
    let envelope = UseIdEnvelope {
        header: Header::default(),
        body: UseIdBody { response },
    };

    // 2) Serialize with serde/quick_xml (no XML declaration)
    let xml_inner = to_string(&envelope).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // 3) Inject the three xmlns attributes in one go
    let xml_with_ns = xml_inner.replacen(
        "<soapenv:Envelope",
        "<soapenv:Envelope \
         xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         xmlns:eid=\"http://bsi.bund.de/eID/\" \
         xmlns:dss=\"urn:oasis:names:tc:dss:1.0:core:schema\"",
        1,
    );

    // 4) Prepend XML declaration and return
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>{}",
        xml_with_ns
    ))
}

#[cfg(test)]
mod tests {

    use crate::eid::{
        common::models::{ResultCode, ResultMajor, Session},
        use_id::model::Psk,
    };

    use super::*;

    #[test]
    fn test_build_use_id_response_basic() {
        // Arrange
        let response = UseIDResponse {
            session: Session {
                id: "1234567890abcdef1234567890abcdef".to_string(),
            },
            psk: Psk {
                id: "0987654321abcdef1234567890abcdef".to_string(),
                key: "fedcba0987654321fedcba0987654321".to_string(),
            },
            result: ResultMajor {
                result_major: ResultCode::Ok.to_string(),
            },
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
            <eid:eCardServerAddress/>
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
