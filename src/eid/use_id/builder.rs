use quick_xml::se::to_string;

use crate::eid::common::models::Header;

use super::{
    error::UseIdError,
    model::{UseIDResponse, UseIdBody, UseIdEnvelope},
};

/// Serializes a `UseIDResponse` into a complete SOAP XML envelope using `quick-xml`’s
/// Serde-based serializer, injecting the required namespaces and XML declaration.
///
/// # Parameters
/// - `response`: Reference to a [`UseIDResponse`] struct containing:
///   - `session`: the session ID to echo back.
///   - `ecard_server_address`: optional eCard server address URL.
///   - `psk`: pre-shared key (`id` and `key`) for the session.
///   - `result`: numeric result code.
///
/// # Returns
/// - `Ok(String)`: A UTF-8 XML document string starting with
///   `<?xml version="1.0" encoding="UTF-8"?>` and containing the SOAP envelope,
///   header, body, and `<eid:useIDResponse>` element with all nested fields.
/// - `Err(UseIdError)`: If serialization with `quick-xml` fails or if the final
///   namespace injection step encounters an error.
///
/// # XML Structure
///
/// ```xml
/// <?xml version="1.0" encoding="UTF-8"?>
/// <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
///                   xmlns:eid="http://bsi.bund.de/eID/"
///                   xmlns:dss="urn:oasis:names:tc:dss:1.0:core:schema">
///   <soapenv:Header/>
///   <soapenv:Body>
///     <eid:useIDResponse>
///       <eid:Session><eid:ID>…</eid:ID></eid:Session>
///       <eid:eCardServerAddress>…</eid:eCardServerAddress>  <!-- optional -->
///       <eid:PSK>
///         <eid:ID>…</eid:ID>
///         <eid:Key>…</eid:Key>
///       </eid:PSK>
///       <dss:Result><ResultMajor>…</ResultMajor></dss:Result>
///     </eid:useIDResponse>
///   </soapenv:Body>
/// </soapenv:Envelope>
/// ```
///
/// # Example
///
/// ```rust
/// let response = UseIDResponse {
///     session: "session123".to_string(),
///     ecard_server_address: Some("http://ecard.server.com".to_string()),
///     psk: PSK { id: "psk123".to_string(), key: "secretkey".to_string() },
///     result: 0,
/// };
/// let xml = build_use_id_response(&response)?;
/// println!("{}", xml);
/// ```
///
/// # Errors
/// Returns `UseIdError::GenericError` if the underlying `to_string()`
/// call fails or if namespace injection cannot be applied.
#[allow(dead_code)]
pub fn build_use_id_response(response: &UseIDResponse) -> Result<String, UseIdError> {
    let envelope = UseIdEnvelope {
        header: Header::default(),
        body: UseIdBody { response },
    };

    let xml_inner = to_string(&envelope)
        .map_err(|e| UseIdError::GenericError(format!("Failed to build XML message: {e}")))?;

    let xml_with_ns = xml_inner.replacen(
        "<soapenv:Envelope",
        "<soapenv:Envelope \
         xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         xmlns:eid=\"http://bsi.bund.de/eID/\" \
         xmlns:dss=\"urn:oasis:names:tc:dss:1.0:core:schema\"",
        1,
    );

    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>{xml_with_ns}"
    ))
}

#[cfg(test)]
mod tests {

    use crate::{
        eid::common::models::{ResultCode, ResultMajor, SessionResponse},
        eid::use_id::model::Psk,
    };

    use super::*;

    #[test]
    fn test_build_use_id_response_basic() {
        // Arrange
        let response = UseIDResponse {
            session: SessionResponse {
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

        let expected_xml = std::fs::read_to_string("test_data/use_id_response.xml")
            .expect("Failed to read expected XML file");

        // Normalize whitespace for comparison (optional but safer)
        let normalize = |s: &str| s.split_whitespace().collect::<String>();

        // Assert
        assert_eq!(normalize(&generated_xml), normalize(&expected_xml));
    }
}
