use quick_xml::de::from_str;

use super::model::{Envelope, StartPAOS};

pub fn parse_start_paos(xml: &str) -> Result<StartPAOS, quick_xml::de::DeError> {
    let envelope: Envelope = from_str(xml)?;
    Ok(envelope.body.start_paos)
}

#[cfg(test)]
mod tests {
    use crate::sal::paos::{
        model::{SupportedAPIVersions, SupportedDIDProtocols, UserAgent},
        parser::parse_start_paos,
    };

    #[test]
    fn test_parse_start_paos() {
        let xml = std::fs::read_to_string("./test_data/startpaos.xml").unwrap();

        let parsed = parse_start_paos(&xml).expect("Failed to parse");
        assert_eq!(parsed.session_identifier, "unIdentifiantDeSessionExemple");
        assert_eq!(
            parsed.connection_handles,
            vec!["unGestionnaireDeConnexionExemple"]
        );
        assert_eq!(
            parsed.user_agent,
            Some(UserAgent {
                name: "Client eID Exemple".to_string(),
                version_major: 2,
                version_minor: 0,
                version_subminor: 0,
            })
        );
        assert_eq!(
            parsed.supported_api_versions,
            Some(SupportedAPIVersions {
                major: 1,
                minor: 1,
                subminor: 0,
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
