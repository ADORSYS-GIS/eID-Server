use super::error::TransmitError;
use reqwest::Client;
use std::env;
use base64::{engine::general_purpose, Engine as _};

/// Generic channel for forwarding APDU commands to any eID-Client implementing the eCard-API
pub struct TransmitChannel {
    client: Client,
    eid_client_endpoint: String,
}

impl TransmitChannel {
    pub fn new() -> Self {
        let endpoint = env::var("EID_CLIENT_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:24727/".to_string());
        TransmitChannel {
            client: Client::new(),
            eid_client_endpoint: endpoint,
        }
    }

    /// Transmit an APDU command and return the response.
    /// Optionally include session_id for stateful flows.
    pub async fn transmit_apdu(
        &self,
        apdu: &[u8],
        session_id: Option<&str>,
    ) -> Result<Vec<u8>, TransmitError> {
        // Build a generic eCard-API SOAP request
        let apdu_b64 = general_purpose::STANDARD.encode(apdu);
        let session_xml = session_id
            .map(|sid| format!("<SessionID>{}</SessionID>", sid))
            .unwrap_or_default();
        let soap = format!(
            r#"<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">
  <soapenv:Header/>
  <soapenv:Body>
    <TransmitRequest>{session_xml}<APDU>{apdu_b64}</APDU></TransmitRequest>
  </soapenv:Body>
</soapenv:Envelope>"#,
            session_xml = session_xml,
            apdu_b64 = apdu_b64
        );
        let resp = self
            .client
            .post(&self.eid_client_endpoint)
            .header("Content-Type", "text/xml; charset=utf-8")
            .body(soap)
            .send()
            .await
            .map_err(|e| TransmitError::TransmissionFailed(e.to_string()))?;
        let text = resp
            .text()
            .await
            .map_err(|e| TransmitError::TransmissionFailed(e.to_string()))?;
        // Parse APDUResponse from SOAP
        let start = text
            .find("<APDUResponse>")
            .ok_or(TransmitError::ProtocolViolation(
                "No APDUResponse tag".to_string(),
            ))?
            + 14;
        let end = text
            .find("</APDUResponse>")
            .ok_or(TransmitError::ProtocolViolation(
                "No closing APDUResponse tag".to_string(),
            ))?;
        let b64 = &text[start..end];
        let data = general_purpose::STANDARD.decode(b64).map_err(|_| {
            TransmitError::ProtocolViolation("Invalid base64 in APDUResponse".to_string())
        })?;
        Ok(data)
    }
}
