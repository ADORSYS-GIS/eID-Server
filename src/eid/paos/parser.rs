use quick_xml::de::from_str;

use super::model::{Envelope, StartPAOS};

pub fn parse_start_paos(xml: &str) -> Result<StartPAOS, quick_xml::DeError> {
    let envelope: Envelope = from_str(xml)?;
    Ok(envelope.body.start_paos)
}

#[cfg(test)]
mod tests {
    use crate::eid::paos::{
        model::{SupportedAPIVersions, SupportedDIDProtocols, UserAgent},
        parser::parse_start_paos,
    };

    #[test]
    fn test_parse_start_paos() {
        let xml = std::fs::read_to_string("./test_data/startpaos.xml").unwrap();

        let parsed = parse_start_paos(&xml).expect("Failed to parse");
        assert_eq!(
            parsed.session_identifier,
            "faf7554cf8a24e51a4dbfa9881121905"
        );
        assert_eq!(
            parsed.connection_handle.card_application,
            "e80704007f00070302"
        );
        assert_eq!(parsed.connection_handle.slot_handle, "00");
        assert_eq!(
            parsed.user_agent,
            Some(UserAgent {
                name: Some("Client eID Exemple".to_string()),
                version_major: Some(2),
                version_minor: Some(0),
                version_subminor: Some(0),
            })
        );
        assert_eq!(
            parsed.supported_api_versions,
            Some(SupportedAPIVersions {
                major: 1,
                minor: Some(1),
                subminor: Some(0),
            })
        );
        assert_eq!(
            parsed.supported_did_protocols,
            Some(SupportedDIDProtocols {
                protocols: vec!["urn:oid:1.3.162.15480.3.0.14".to_string()],
            })
        );
    }
}
