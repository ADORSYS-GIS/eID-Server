use crate::domain::eid::{
    models::{
        AuthError, AuthenticationProtocolData, ConnectionHandle, DIDAuthenticateRequest,
        DIDAuthenticateResponse, SoapResponse,
    },
    ports::{DIDAuthenticate, EIDService, EidService},
};
use crate::server::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse};
use color_eyre::Result;
use quick_xml::{
    Reader, Writer,
    events::{BytesEnd, BytesStart, BytesText, Event},
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct SoapDIDAuthenticateRequest {
    connection_handle: ConnectionHandle,
    did_name: String,
    authentication_protocol_data: AuthenticationProtocolData,
}

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
                channel_handle: Some(String::new()),
                ifd_name: Some(String::new()),
                slot_index: Some(0),
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
                    let name = e.local_name().as_ref().to_vec();
                    current_element =
                        String::from_utf8(name).map_err(|_| AuthError::InvalidConnection {
                            reason: "Invalid UTF-8 in element name".to_string(),
                        })?;
                    tracing::debug!("Processing element: {}", current_element);
                }
                Ok(Event::Text(e)) => {
                    let text = e
                        .unescape()
                        .map_err(|_| AuthError::InvalidConnection {
                            reason: "Failed to unescape text content".to_string(),
                        })?
                        .to_string();
                    tracing::debug!("Text content for {}: {}", current_element, text);
                    match current_element.as_str() {
                        "ChannelHandle" => request.connection_handle.channel_handle = Some(text),
                        "IFDName" => request.connection_handle.ifd_name = Some(text),
                        "SlotIndex" => {
                            request.connection_handle.slot_index = Some(text.parse().unwrap_or(0));
                        }
                        "DIDName" => request.did_name = text,
                        "Certificate" => {
                            request.authentication_protocol_data.certificate_description = text;
                        }
                        "RequiredCHAT" => {
                            request.authentication_protocol_data.required_chat = text;
                        }
                        "OptionalCHAT" => {
                            request.authentication_protocol_data.optional_chat = Some(text);
                        }
                        "AuthenticatedAuxiliaryData" => {
                            request.authentication_protocol_data.transaction_info = Some(text);
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(_)) => {
                    current_element.clear();
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(AuthError::InvalidConnection {
                        reason: format!("Failed to parse XML request: {}", e),
                    });
                }
                _ => {}
            }
            buf.clear();
        }

        tracing::debug!("Parsed request: {:?}", request);
        Ok(request)
    }

    // Convert domain response to SOAP XML response using quick-xml
    fn to_soap_response(&self, response: DIDAuthenticateResponse) -> Result<String, AuthError> {
        let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);

        let mut envelope = BytesStart::new("soapenv:Envelope");
        envelope.push_attribute(("xmlns:soapenv", "http://schemas.xmlsoap.org/soap/envelope/"));
        envelope.push_attribute(("xmlns:ecard", "http://www.bsi.bund.de/ecard/api/1.1"));
        writer
            .write_event(Event::Start(envelope))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write SOAP Envelope".to_string(),
            })?;

        writer
            .write_event(Event::Start(BytesStart::new("soapenv:Header")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write SOAP Header".to_string(),
            })?;
        writer
            .write_event(Event::End(BytesEnd::new("soapenv:Header")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close SOAP Header".to_string(),
            })?;

        writer
            .write_event(Event::Start(BytesStart::new("soapenv:Body")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write SOAP Body".to_string(),
            })?;

        writer
            .write_event(Event::Start(BytesStart::new(
                "ecard:DIDAuthenticateResponse",
            )))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write DIDAuthenticateResponse".to_string(),
            })?;

        writer
            .write_event(Event::Start(BytesStart::new("ecard:Result")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write Result".to_string(),
            })?;
        writer
            .write_event(Event::Start(BytesStart::new("ecard:ResultMajor")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write ResultMajor".to_string(),
            })?;
        writer
            .write_event(Event::Text(BytesText::new(&response.result_major)))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write ResultMajor text".to_string(),
            })?;
        writer
            .write_event(Event::End(BytesEnd::new("ecard:ResultMajor")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close ResultMajor".to_string(),
            })?;

        if let Some(minor) = &response.result_minor {
            writer
                .write_event(Event::Start(BytesStart::new("ecard:ResultMinor")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write ResultMinor".to_string(),
                })?;
            writer
                .write_event(Event::Text(BytesText::new(minor)))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write ResultMinor text".to_string(),
                })?;
            writer
                .write_event(Event::End(BytesEnd::new("ecard:ResultMinor")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to close ResultMinor".to_string(),
                })?;
        }
        writer
            .write_event(Event::End(BytesEnd::new("ecard:Result")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close Result".to_string(),
            })?;

        writer
            .write_event(Event::Start(BytesStart::new(
                "ecard:AuthenticationProtocolData",
            )))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write AuthenticationProtocolData".to_string(),
            })?;

        if let Some(certificate) = &response.authentication_protocol_data.certificate {
            writer
                .write_event(Event::Start(BytesStart::new("ecard:Certificate")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write Certificate".to_string(),
                })?;
            writer
                .write_event(Event::Text(BytesText::new(certificate)))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write Certificate text".to_string(),
                })?;
            writer
                .write_event(Event::End(BytesEnd::new("ecard:Certificate")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to close Certificate".to_string(),
                })?;
        }

        if let Some(personal_data) = &response.authentication_protocol_data.personal_data {
            writer
                .write_event(Event::Start(BytesStart::new("ecard:PersonalData")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write PersonalData".to_string(),
                })?;
            writer
                .write_event(Event::Text(BytesText::new(personal_data)))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write PersonalData text".to_string(),
                })?;
            writer
                .write_event(Event::End(BytesEnd::new("ecard:PersonalData")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to close PersonalData".to_string(),
                })?;
        }

        if let Some(auth_token) = &response.authentication_protocol_data.authentication_token {
            writer
                .write_event(Event::Start(BytesStart::new("ecard:AuthenticationToken")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write AuthenticationToken".to_string(),
                })?;
            writer
                .write_event(Event::Text(BytesText::new(auth_token)))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write AuthenticationToken text".to_string(),
                })?;
            writer
                .write_event(Event::End(BytesEnd::new("ecard:AuthenticationToken")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to close AuthenticationToken".to_string(),
                })?;
        }

        writer
            .write_event(Event::End(BytesEnd::new(
                "ecard:AuthenticationProtocolData",
            )))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close AuthenticationProtocolData".to_string(),
            })?;
        writer
            .write_event(Event::End(BytesEnd::new("ecard:DIDAuthenticateResponse")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close DIDAuthenticateResponse".to_string(),
            })?;
        writer
            .write_event(Event::End(BytesEnd::new("soapenv:Body")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close SOAP Body".to_string(),
            })?;
        writer
            .write_event(Event::End(BytesEnd::new("soapenv:Envelope")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close SOAP Envelope".to_string(),
            })?;

        let result =
            String::from_utf8(writer.into_inner()).map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to convert response to UTF-8".to_string(),
            })?;
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
                certificate_description: soap_request
                    .authentication_protocol_data
                    .certificate_description,
                required_chat: soap_request.authentication_protocol_data.required_chat,
                optional_chat: soap_request.authentication_protocol_data.optional_chat,
                transaction_info: soap_request.authentication_protocol_data.transaction_info,
            },
        };

        let response = self
            .eid_service
            .handle_did_authenticate(domain_request)
            .await?;

        let soap_response = self.to_soap_response(response)?;

        Ok(SoapResponse {
            body: soap_response,
            status: 200,
        })
    }
}

pub async fn did_authenticate<
    S: DIDAuthenticate + EIDService + EidService + Send + Sync + 'static,
>(
    State(state): State<AppState<S>>,
    body: String,
) -> Result<impl IntoResponse, StatusCode> {
    let handler = DIDAuthenticateHandler::new((*state.eid_service).clone());

    let response = handler
        .handle(&body)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let status_code = StatusCode::from_u16(response.status as u16).unwrap_or(StatusCode::OK);
    Ok((status_code, response.body))
}
