use std::str::FromStr;

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::eid::common::models::{
    AttributeRequester, EIDTypeRequest, EIDTypeSelection, LevelOfAssurance,
    TransactionAttestationRequest, UseOperations,
};

use super::error::UseIdError;
use super::model::{Psk, UseIDRequest};

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
/// let xml = include_str!("use_id_request.xml");
/// let parsed = parse_use_id_request(xml)?;
/// assert_eq!(parsed.age_verification, Some(18));
/// ```
#[allow(dead_code)]
pub fn parse_use_id_request(xml: &str) -> Result<UseIDRequest, UseIdError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut useid_request = UseIDRequest::new();

    while let Ok(event) = reader.read_event_into(&mut buf) {
        match event {
            Event::Start(ref e) => match e.name().as_ref() {
                b"eid:UseOperations" => loop {
                    match reader.read_event_into(&mut buf) {
                        Ok(Event::Start(e)) => {
                            let name = reader
                                .decoder()
                                .decode(e.name().as_ref())
                                .map(|s| s.to_string())
                                .unwrap_or_default()
                                .replace("eid:", "");

                            let value = match reader.read_event_into(&mut buf) {
                                Ok(Event::Text(text)) => {
                                    text.unescape().ok().map(|s| s.to_string())
                                }
                                Ok(Event::End(_)) => continue,
                                Ok(_) => continue,
                                Err(e) => {
                                    return Err(UseIdError::GenericError(format!(
                                        "Error reading UseOperations value: {e}"
                                    )));
                                }
                            };

                            let requirement = match value.unwrap_or_default().as_str() {
                                "REQUIRED" => AttributeRequester::REQUIRED,
                                "ALLOWED" => AttributeRequester::ALLOWED,
                                "PROHIBITED" => AttributeRequester::PROHIBITED,
                                _ => continue,
                            };

                            useid_request
                                .use_operations
                                .push(UseOperations { name, requirement });
                        }
                        Ok(Event::End(e)) if e.name().as_ref() == b"eid:UseOperations" => break,
                        Ok(_) => (),
                        Err(e) => {
                            return Err(UseIdError::GenericError(format!(
                                "Error reading UseOperations: {e}"
                            )));
                        }
                    }
                    buf.clear();
                },
                b"eid:AgeVerificationRequest" => {
                    if let Ok(Event::Start(_)) = reader.read_event_into(&mut buf) {
                        if let Ok(Event::Text(text)) = reader.read_event_into(&mut buf) {
                            useid_request.age_verification =
                                text.unescape().ok().and_then(|v| v.parse::<u8>().ok());
                        }
                    }
                }
                b"eid:PlaceVerificationRequest" => {
                    if let Ok(Event::Start(_)) = reader.read_event_into(&mut buf) {
                        if let Ok(Event::Text(text)) = reader.read_event_into(&mut buf) {
                            useid_request.place_verification =
                                text.unescape().ok().map(|s| s.to_string());
                        }
                    }
                }
                b"eid:TransactionInfo" => {
                    if let Ok(Event::Text(text)) = reader.read_event_into(&mut buf) {
                        useid_request.transaction_info =
                            text.unescape().ok().map(|s| s.to_string());
                    }
                }
                b"eid:TransactionAttestationRequest" => {
                    let mut format = None;
                    let mut context = None;

                    loop {
                        match reader.read_event_into(&mut buf) {
                            Ok(Event::Start(ref e))
                                if e.name().as_ref() == b"eid:TransactionAttestationFormat" =>
                            {
                                if let Ok(Event::Text(text)) = reader.read_event_into(&mut buf) {
                                    format = text.unescape().ok().map(|s| s.to_string());
                                }
                            }
                            Ok(Event::Start(ref e))
                                if e.name().as_ref() == b"eid:TransactionContext" =>
                            {
                                if let Ok(Event::Text(text)) = reader.read_event_into(&mut buf) {
                                    context = text.unescape().ok().map(|s| s.to_string());
                                }
                            }
                            Ok(Event::End(ref e))
                                if e.name().as_ref() == b"eid:TransactionAttestationRequest" =>
                            {
                                break;
                            }
                            Ok(_) => continue,
                            Err(e) => {
                                return Err(UseIdError::GenericError(format!(
                                    "Failed to parse TransactionAttestationRequest: {}",
                                    e
                                )));
                            }
                        }
                        buf.clear();
                    }

                    if let Some(format) = format {
                        useid_request.transaction_attestation_uri =
                            Some(TransactionAttestationRequest {
                                transaction_attestation_format: format,
                                transaction_context: context,
                            });
                    }
                }
                b"eid:LevelOfAssuranceRequest" => {
                    if let Ok(Event::Text(text)) = reader.read_event_into(&mut buf) {
                        let loa = text
                            .unescape()
                            .ok()
                            .map(|s| s.to_string())
                            .unwrap_or_default();
                        let loa = LevelOfAssurance::from_str(&loa).ok();
                        if let Some(loa) = loa {
                            useid_request.level_of_assurance = Some(loa)
                        }
                    }
                }
                b"eid:EIDTypeRequest" => {
                    let mut eid_type_request = EIDTypeRequest::default();

                    loop {
                        match reader.read_event_into(&mut buf) {
                            Ok(Event::Start(e)) => {
                                let name = reader
                                    .decoder()
                                    .decode(e.name().as_ref())
                                    .map(|s| s.to_string())
                                    .unwrap_or_default()
                                    .replace("eid:", "");

                                let value = match reader.read_event_into(&mut buf) {
                                    Ok(Event::Text(text)) => {
                                        text.unescape().ok().map(|s| s.to_string())
                                    }
                                    Ok(Event::End(_)) => continue,
                                    _ => continue,
                                };

                                let permission = match value.unwrap_or_default().as_str() {
                                    "ALLOWED" => Some(EIDTypeSelection::ALLOWED),
                                    "DENIED" => Some(EIDTypeSelection::DENIED),
                                    _ => None,
                                };

                                match name.as_str() {
                                    "SECertified" => eid_type_request.se_certified = permission,
                                    "SEEndorsed" => eid_type_request.se_endorsed = permission,
                                    "CardCertified" => eid_type_request.card_certified = permission,
                                    _ => (),
                                }
                            }
                            Ok(Event::End(e)) if e.name().as_ref() == b"eid:EIDTypeRequest" => {
                                break;
                            }
                            Ok(_) => (),
                            Err(e) => {
                                return Err(UseIdError::GenericError(format!(
                                    "Error reading EIDTypeRequest: {}",
                                    e
                                )));
                            }
                        }
                        buf.clear();
                    }

                    useid_request.eid_type_request = Some(eid_type_request);
                }
                b"eid:PSK" => {
                    let mut id = None;
                    let mut key = None;

                    loop {
                        match reader.read_event_into(&mut buf) {
                            Ok(Event::Start(e)) if e.name().as_ref() == b"eid:ID" => {
                                if let Ok(Event::Text(text)) = reader.read_event_into(&mut buf) {
                                    id = text.unescape().ok().map(|s| s.to_string());
                                }
                            }
                            Ok(Event::Start(e)) if e.name().as_ref() == b"eid:Key" => {
                                if let Ok(Event::Text(text)) = reader.read_event_into(&mut buf) {
                                    key = text.unescape().ok().map(|s| s.to_string());
                                }
                            }
                            Ok(Event::End(e)) if e.name().as_ref() == b"eid:PSK" => break,
                            Ok(_) => continue,
                            Err(e) => {
                                return Err(UseIdError::GenericError(format!("error: {}", e)));
                            }
                        }
                        buf.clear();
                    }

                    if let (Some(id), Some(key)) = (id, key) {
                        useid_request.psk = Some(Psk { id, key });
                    }
                }

                _ => (),
            },
            Event::Eof => break,
            _ => (),
        }
        buf.clear();
    }

    Ok(useid_request)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse_valid_use_id_request() {
        let xml = include_str!("../../../test_data/use_id_request.xml");

        let result = parse_use_id_request(xml).expect("Failed to parse XML");
        assert_eq!(result.age_verification, Some(18));
        assert_eq!(result.place_verification.as_deref(), Some("027605"));

        // Transaction Attestation
        let expected_transaction = TransactionAttestationRequest {
            transaction_attestation_format: "http://bsi.bund.de/eID/ExampleAttestationFormat"
                .into(),
            transaction_context: Some("id599456-df".into()),
        };
        assert_eq!(
            result.transaction_attestation_uri,
            Some(expected_transaction)
        );

        // Level of Assurance
        let loa = LevelOfAssurance::from_str("http://bsi.bund.de/eID/LoA/hoch").unwrap();
        assert_eq!(result.level_of_assurance, Some(loa));

        // UseOperations assertions (based on Vec<UseOperation>)
        let ops = &result.use_operations;

        assert!(ops.iter().any(|op| op.name == "DocumentType"
            && op.requirement == AttributeRequester::REQUIRED));
        assert!(ops.iter().any(|op| op.name == "IssuingState"
            && op.requirement== AttributeRequester::REQUIRED));
        assert!(ops.iter().any(|op| op.name == "DateOfExpiry"
            && op.requirement == AttributeRequester::REQUIRED));
        assert!(
            ops.iter()
                .any(|op| op.name == "GivenNames" && op.requirement == AttributeRequester::REQUIRED)
        );
        assert!(
            ops.iter()
                .any(|op| op.name == "FamilyNames" && op.requirement == AttributeRequester::REQUIRED)
        );
        assert!(
            ops.iter()
                .any(|op| op.name == "ArtisticName" && op.requirement == AttributeRequester::ALLOWED)
        );
        assert!(ops.iter().any(|op| op.name == "AcademicTitle"
            && op.requirement == AttributeRequester::ALLOWED));
        assert!(
            ops.iter()
                .any(|op| op.name == "DateOfBirth" && op.requirement == AttributeRequester::REQUIRED)
        );
        assert!(ops.iter().any(|op| op.name == "PlaceOfBirth"
            && op.requirement == AttributeRequester::REQUIRED));
        assert!(
            ops.iter()
                .any(|op| op.name == "Nationality" && op.requirement == AttributeRequester::REQUIRED)
        );
        assert!(
            ops.iter()
                .any(|op| op.name == "BirthName" && op.requirement == AttributeRequester::REQUIRED)
        );
        assert!(ops.iter().any(
            |op| op.name == "PlaceOfResidence" && op.requirement == AttributeRequester::REQUIRED
        ));
        assert!(ops.iter().any(|op| op.name == "RestrictedID"
            && op.requirement == AttributeRequester::REQUIRED));
        assert!(
            ops.iter()
                .any(|op| op.name == "AgeVerification"
                    && op.requirement == AttributeRequester::REQUIRED)
        );
        assert!(ops.iter().any(
            |op| op.name == "PlaceVerification" && op.requirement == AttributeRequester::REQUIRED
        ));

        assert!(!ops.iter().any(|op| op.name == "CommunityID"));
        assert!(!ops.iter().any(|op| op.name == "ResidencePermitI"));

        // EIDTypeRequest
        let eid_type = result
            .eid_type_request
            .as_ref()
            .expect("Missing EIDTypeRequest");
        assert_eq!(eid_type.se_certified, Some(EIDTypeSelection::ALLOWED));
        assert_eq!(eid_type.se_endorsed, Some(EIDTypeSelection::ALLOWED));
        assert!(result.psk.is_none())
    }
}
