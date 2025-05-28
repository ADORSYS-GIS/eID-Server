use axum::{extract::State, response::IntoResponse, http::StatusCode};
use quick_xml::{Reader, Writer, events::{Event, BytesStart, BytesText, BytesEnd}};
use serde::Deserialize;
use color_eyre::Result;
use crate::server::AppState;
use crate::domain::eid::{
    models::{AuthError, ConnectionHandle, DIDAuthenticateRequest, DIDAuthenticateResponse, SoapResponse},
    ports::{DIDAuthenticate, EIDService, EidService},
};

// Request structure for DIDAuthenticate
#[derive(Debug, Deserialize)]
struct SoapDIDAuthenticateRequest {
    connection_handle: ConnectionHandle,
    did_name: String,
    authentication_protocol_data: AuthenticationProtocolData,
}

#[derive(Debug, Deserialize)]
struct AuthenticationProtocolData {
    certificate_description: String,
    required_chat: String,
    optional_chat: Option<String>,
    transaction_info: Option<String>,
}


// Handler for DIDAuthenticate requests
pub struct DIDAuthenticateHandler<T: DIDAuthenticate> {
    eid_service: T,
}

impl<T: DIDAuthenticate + Send + Sync> DIDAuthenticateHandler<T> {
    pub fn new(eid_service: T) -> Self {
        DIDAuthenticateHandler { eid_service }
    }

    // Parse incoming SOAP XML request using quick-xml
    fn parse_request(&self, body: &str) -> Result<SoapDIDAuthenticateRequest, AuthError> {
        let mut reader = Reader::from_str(body);
        reader.config_mut().trim_text(true);

        let mut request = SoapDIDAuthenticateRequest {
            connection_handle: ConnectionHandle {
                channel_handle: String::new(),
                ifd_name: String::new(),
                slot_index: 0,
            },
            did_name: String::new(),
            authentication_protocol_data: AuthenticationProtocolData {
                certificate_description: String::new(),
                required_chat: String::new(),
                optional_chat: None,
                transaction_info: None,
            },
        };

        let mut buf = Vec::new();
        let mut current_element = String::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    current_element = String::from_utf8(e.name().as_ref().to_vec())
                        .map_err(|_| AuthError::InvalidConnection)?;
                }
                Ok(Event::Text(e)) => {
                    let text = e.unescape()
                        .map_err(|_| AuthError::InvalidConnection)?
                        .to_string();
                    match current_element.as_str() {
                        "ChannelHandle" => request.connection_handle.channel_handle = text,
                        "IFDName" => request.connection_handle.ifd_name = text,
                        "SlotIndex" => request.connection_handle.slot_index = text.parse().unwrap_or(0),
                        "DIDName" => request.did_name = text,
                        "CertificateDescription" => {
                            request.authentication_protocol_data.certificate_description = text;
                        }
                        "RequiredCHAT" => {
                            request.authentication_protocol_data.required_chat = text;
                        }
                        "OptionalCHAT" => {
                            request.authentication_protocol_data.optional_chat = Some(text);
                        }
                        "TransactionInfo" => {
                            request.authentication_protocol_data.transaction_info = Some(text);
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(_)) => {
                    current_element.clear();
                }
                Ok(Event::Eof) => break,
                Err(_) => return Err(AuthError::InvalidConnection),
                _ => {}
            }
            buf.clear();
        }

        Ok(request)
    }

    // Convert domain response to SOAP XML response using quick-xml
    fn to_soap_response(&self, response: DIDAuthenticateResponse) -> Result<String, AuthError> {
        let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);

        // Start DIDAuthenticateResponse
        writer.write_event(Event::Start(BytesStart::new("DIDAuthenticateResponse")))
            .map_err(|_| AuthError::InvalidConnection)?;

        // Write Result
        writer.write_event(Event::Start(BytesStart::new("Result")))
            .map_err(|_| AuthError::InvalidConnection)?;
        writer.write_event(Event::Start(BytesStart::new("ResultMajor")))
            .map_err(|_| AuthError::InvalidConnection)?;
        writer.write_event(Event::Text(BytesText::new(&response.result_major)))
            .map_err(|_| AuthError::InvalidConnection)?;
        writer.write_event(Event::End(BytesEnd::new("ResultMajor")))
            .map_err(|_| AuthError::InvalidConnection)?;

        if let Some(minor) = &response.result_minor {
            writer.write_event(Event::Start(BytesStart::new("ResultMinor")))
                .map_err(|_| AuthError::InvalidConnection)?;
            writer.write_event(Event::Text(BytesText::new(minor)))
                .map_err(|_| AuthError::InvalidConnection)?;
            writer.write_event(Event::End(BytesEnd::new("ResultMinor")))
                .map_err(|_| AuthError::InvalidConnection)?;
        }
        writer.write_event(Event::End(BytesEnd::new("Result")))
            .map_err(|_| AuthError::InvalidConnection)?;

        // Write AuthenticationProtocolData
        writer.write_event(Event::Start(BytesStart::new("AuthenticationProtocolData")))
            .map_err(|_| AuthError::InvalidConnection)?;

        if let Some(challenge) = &response.authentication_protocol_data.challenge {
            writer.write_event(Event::Start(BytesStart::new("Challenge")))
                .map_err(|_| AuthError::InvalidConnection)?;
            writer.write_event(Event::Text(BytesText::new(challenge)))
                .map_err(|_| AuthError::InvalidConnection)?;
            writer.write_event(Event::End(BytesEnd::new("Challenge")))
                .map_err(|_| AuthError::InvalidConnection)?;
        }

        if let Some(certificate) = &response.authentication_protocol_data.certificate {
            writer.write_event(Event::Start(BytesStart::new("Certificate")))
                .map_err(|_| AuthError::InvalidConnection)?;
            writer.write_event(Event::Text(BytesText::new(certificate)))
                .map_err(|_| AuthError::InvalidConnection)?;
            writer.write_event(Event::End(BytesEnd::new("Certificate")))
                .map_err(|_| AuthError::InvalidConnection)?;
        }

        if let Some(personal_data) = &response.authentication_protocol_data.personal_data {
            writer.write_event(Event::Start(BytesStart::new("PersonalData")))
                .map_err(|_| AuthError::InvalidConnection)?;
            writer.write_event(Event::Text(BytesText::new(personal_data)))
                .map_err(|_| AuthError::InvalidConnection)?;
            writer.write_event(Event::End(BytesEnd::new("PersonalData")))
                .map_err(|_| AuthError::InvalidConnection)?;
        }

        writer.write_event(Event::End(BytesEnd::new("AuthenticationProtocolData")))
            .map_err(|_| AuthError::InvalidConnection)?;
        writer.write_event(Event::End(BytesEnd::new("DIDAuthenticateResponse")))
            .map_err(|_| AuthError::InvalidConnection)?;

        let result = String::from_utf8(writer.into_inner())
            .map_err(|_| AuthError::InvalidConnection)?;
        Ok(result)
    }

    // Handle the DIDAuthenticate request
    pub async fn handle(&self, body: &str) -> Result<SoapResponse, AuthError> {
        // Parse SOAP request
        let soap_request = self.parse_request(body)?;

        // Convert to domain request
        let domain_request = DIDAuthenticateRequest {
            connection_handle: soap_request.connection_handle,
            did_name: soap_request.did_name,
            authentication_protocol_data: crate::domain::eid::models::AuthenticationProtocolData {
                certificate_description: soap_request.authentication_protocol_data.certificate_description,
                required_chat: soap_request.authentication_protocol_data.required_chat,
                optional_chat: soap_request.authentication_protocol_data.optional_chat,
                transaction_info: soap_request.authentication_protocol_data.transaction_info,
            },
        };

        // Process request using domain service
        let response = self.eid_service.handle_did_authenticate(domain_request)?;

        // Convert to SOAP response
        let soap_response = self.to_soap_response(response)?;

        Ok(SoapResponse {
            body: soap_response,
            status: 200,
        })
    }
}

pub async fn did_authenticate<S: DIDAuthenticate + EIDService + EidService + Send + Sync + 'static>(
    State(state): State<AppState<S>>,
    body: String,
) -> Result<impl IntoResponse, StatusCode> {
    let handler = DIDAuthenticateHandler::new((*state.eid_service).clone());

    // Process the request using the body directly
    let response = handler
        .handle(&body)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Return the SOAP response with the appropriate status code
    // Convert the numeric status to StatusCode properly
    let status_code = StatusCode::from_u16(response.status as u16)
        .unwrap_or(StatusCode::OK);

    Ok((status_code, response.body))
}