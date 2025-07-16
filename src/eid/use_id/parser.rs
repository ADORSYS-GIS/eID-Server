use crate::eid::{
    soap::{ parser::deserialize_soap},
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
    let request: UseIDRequest = deserialize_soap(xml, "eid:useIDRequest")?;
    Ok(request)
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
}
