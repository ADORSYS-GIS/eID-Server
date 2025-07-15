use crate::eid::{
    soap::helpers::serialize_soap_response,
    use_id::{error::UseIdError, model::UseIDResponse},
};

/// Serializes a `UseIDResponse` into a complete SOAP XML envelope.
///
/// # Parameters
/// - `response`: Reference to a [`UseIDResponse`] struct containing session, ecard_server_address, psk, and result.
///
/// # Returns
/// - `Ok(String)`: A UTF-8 XML document string.
/// - `Err(UseIdError)`: If serialization fails.
///
/// # Example
/// ```rust
/// let response = UseIDResponse { /* ... */ };
/// let xml = build_use_id_response(&response)?;
/// println!("{}", xml);
/// ```
pub fn build_use_id_response(response: &UseIDResponse) -> Result<String, UseIdError> {
    serialize_soap_response(response).map_err(|e| UseIdError::GenericError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        eid::common::models::{ResultCode, ResultMajor, SessionResponse},
        eid::use_id::model::Psk,
    };

    #[test]
    fn test_build_use_id_response_basic() {
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

        let normalize = |s: &str| s.split_whitespace().collect::<String>();
        assert_eq!(normalize(&generated_xml), normalize(&expected_xml));
    }
}
