use super::channel::TransmitChannel;
use super::error::TransmitError;
use super::session::TransmitSessionStore;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event, BytesDecl};
use quick_xml::{Reader, Writer};
use base64::{engine::general_purpose, Engine as _};

pub struct ProtocolHandler {
    channel: TransmitChannel,
    session_store: TransmitSessionStore,
}

impl ProtocolHandler {
    pub fn new() -> Self {
        ProtocolHandler {
            channel: TransmitChannel::new(),
            session_store: TransmitSessionStore::new(),
        }
    }

    /// Handle a generic eCard-API transmit request in XML, return XML response (async)
    pub async fn handle_transmit(&self, xml: &str) -> Result<String, TransmitError> {
        // Parse APDU and SessionID from XML
        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);
        let mut buf = Vec::new();
        let mut apdu_data = None;
        let mut session_id = None;
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) if e.name().as_ref() == b"APDU" => {
                    if let Ok(Event::Text(t)) = reader.read_event_into(&mut buf) {
                        apdu_data = Some(
                            general_purpose::STANDARD.decode(t.unescape().unwrap().as_ref())
                                .map_err(|_| TransmitError::InvalidApdu)?,
                        );
                    } 
                }
                Ok(Event::Start(ref e)) if e.name().as_ref() == b"SessionID" => {
                    if let Ok(Event::Text(t)) = reader.read_event_into(&mut buf) {
                        session_id = Some(t.unescape().unwrap().to_string());
                    }
                }
                Ok(Event::Eof) => break,
                Err(_) => return Err(TransmitError::InvalidApdu),
                _ => {}
            }
            buf.clear();
        }
        let apdu = match apdu_data {
            Some(a) => a,
            None => return Ok(Self::xml_error_response("InvalidApdu", session_id.as_deref().unwrap_or(""))),
        };
        // Session check: require session_id for stateful flows
        if let Some(ref sid) = session_id {
            if self.session_store.get_session(sid).is_none() {
                return Ok(Self::xml_error_response("SessionNotFound", sid));
            }
        }
        // Forward APDU to the eID-Client, passing session_id if present
        let response = match self.channel.transmit_apdu(&apdu, session_id.as_deref()).await {
            Ok(r) => r,
            Err(TransmitError::InvalidApdu) => return Ok(Self::xml_error_response("InvalidApdu", session_id.as_deref().unwrap_or(""))),
            Err(TransmitError::SessionNotFound) => return Ok(Self::xml_error_response("SessionNotFound", session_id.as_deref().unwrap_or(""))),
            Err(TransmitError::TransmissionFailed(e)) => return Ok(Self::xml_error_response(&format!("TransmissionFailed: {e}"), session_id.as_deref().unwrap_or(""))),
            Err(TransmitError::ProtocolViolation(e)) => return Ok(Self::xml_error_response(&format!("ProtocolViolation: {e}"), session_id.as_deref().unwrap_or(""))),
        };
        // Build generic eCard-API XML response
        let mut writer = Writer::new(Vec::new());
        writer
            .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
            .unwrap();
        let root = BytesStart::new("TransmitResponse");
        writer.write_event(Event::Start(root)).unwrap();
        if let Some(sid) = session_id {
            writer
                .write_event(Event::Start(BytesStart::new("SessionID")))
                .unwrap();
            writer
                .write_event(Event::Text(BytesText::new(&sid)))
                .unwrap();
            writer
                .write_event(Event::End(BytesEnd::new("SessionID")))
                .unwrap();
        }
        writer
            .write_event(Event::Start(BytesStart::new("APDUResponse")))
            .unwrap();
        let encoded = general_purpose::STANDARD.encode(&response);
        writer
            .write_event(Event::Text(BytesText::new(&encoded)))
            .unwrap();
        writer
            .write_event(Event::End(BytesEnd::new("APDUResponse")))
            .unwrap();
        writer
            .write_event(Event::End(BytesEnd::new("TransmitResponse")))
            .unwrap();
        Ok(String::from_utf8(writer.into_inner()).unwrap())
    }

    /// Helper to build an XML error response
    fn xml_error_response(error_code: &str, session_id: &str) -> String {
        let mut writer = Writer::new(Vec::new());
        writer
            .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
            .unwrap();
        let root = BytesStart::new("TransmitError");
        writer.write_event(Event::Start(root)).unwrap();
        writer
            .write_event(Event::Start(BytesStart::new("SessionID")))
            .unwrap();
        writer
            .write_event(Event::Text(BytesText::new(session_id)))
            .unwrap();
        writer
            .write_event(Event::End(BytesEnd::new("SessionID")))
            .unwrap();
        writer
            .write_event(Event::Start(BytesStart::new("ErrorCode")))
            .unwrap();
        writer
            .write_event(Event::Text(BytesText::new(error_code)))
            .unwrap();
        writer
            .write_event(Event::End(BytesEnd::new("ErrorCode")))
            .unwrap();
        writer
            .write_event(Event::End(BytesEnd::new("TransmitError")))
            .unwrap();
        String::from_utf8(writer.into_inner()).unwrap()
    }
}
