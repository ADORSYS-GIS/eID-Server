use crate::apdu::{APDUDecryptParams, DecryptedAPDU};
use crate::apdu::{APDUResponse, ProtectedAPDU, SecureMessaging, SessionKeys, StatusCode};
use crate::domain::models::State;
use crate::domain::models::paos::TransmitResponse;
use crate::pki::truststore::TrustStore;
use crate::server::handlers::StartPaosResp;
use crate::server::{
    AppState,
    errors::{AppError, PaosError},
    handlers::{SESSION_TRACKER, handle_paos_error},
};
use crate::session::SessionData;
use crate::soap::{Envelope, Header};

pub async fn handle_transmit<T: TrustStore>(
    state: AppState<T>,
    envelope: Envelope<TransmitResponse>,
) -> Result<String, AppError> {
    let session_mgr = &state.service.session_manager;
    let (session_id, _, _) = get_ids(&envelope)?;

    match handle_inner(&state, envelope).await {
        Ok(result) => Ok(result),
        Err(e) => handle_paos_error(session_mgr, &session_id, e).await,
    }
}

async fn handle_inner<T: TrustStore>(
    state: &AppState<T>,
    envelope: Envelope<TransmitResponse>,
) -> Result<String, AppError> {
    let session_mgr = &state.service.session_manager;
    let (session_id, mapped_session_id, relates_to) = get_ids(&envelope)?;

    let mut session_data: SessionData = session_mgr
        .get(&*session_id)
        .await?
        .ok_or(PaosError::Timeout)?;

    let State::Transmit {
        apdu_cmds,
        cmds_len,
        decrypt_params,
        mobile_eid_type,
    } = session_data.state
    else {
        return Err(PaosError::Parameter("Expected state TransmitResponse".into()).into());
    };

    // Validate request body
    let data = validate_transmit_body(envelope.into_body())?;

    // Process the APDU responses
    let decrypted_apdu = process_responses(&data, &apdu_cmds, cmds_len, &decrypt_params)?;

    // Clean up the session tracker
    SESSION_TRACKER.invalidate(&mapped_session_id);

    let header = Header {
        relates_to: Some(relates_to),
        message_id: None,
    };

    // Update session state with decrypted APDU responses
    session_data.state = State::TransmitResponse {
        responses: decrypted_apdu,
        mobile_eid_type,
    };
    session_mgr.insert(session_id, &session_data).await?;

    let result = Envelope::new(StartPaosResp::ok())
        .with_header(header)
        .serialize_paos(true);
    result.map_err(AppError::paos_internal)
}

fn get_ids(envelope: &Envelope<TransmitResponse>) -> Result<(String, String, String), AppError> {
    let mapped_id = envelope
        .header()
        .as_ref()
        .and_then(|h| h.relates_to.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().urn().to_string());
    let session_id = SESSION_TRACKER
        .get(&mapped_id)
        .ok_or(PaosError::MissingPermissions)?;

    let relates_to = envelope
        .header()
        .as_ref()
        .and_then(|h| h.message_id.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().urn().to_string());

    Ok((session_id, mapped_id, relates_to))
}

fn validate_transmit_body(body: TransmitResponse) -> Result<TransmitResponse, AppError> {
    // Check for client errors
    if body.result.is_error() {
        return Err(AppError::paos_internal(PaosError::Parameter(format!(
            "Client respond with error: {:?}\nAborting session",
            body.result
        ))));
    }

    // Ensure required data are present
    if body.output_apdus.is_none() {
        return Err(AppError::Paos(PaosError::Parameter(
            "Missing OutputAPDU fields in TransmitResponse".into(),
        )));
    }
    Ok(body)
}

/// Process APDU responses from the card
fn process_responses(
    data: &TransmitResponse,
    sent_commands: &[ProtectedAPDU],
    expected_count: usize,
    params: &APDUDecryptParams,
) -> Result<Vec<DecryptedAPDU>, AppError> {
    let output_apdus = data.output_apdus.as_ref().unwrap();

    // Check if we received exactly the same number of responses as sent commands
    if output_apdus.len() != expected_count {
        return Err(AppError::Paos(PaosError::NodeNotReachable));
    }

    let mut processed_responses = vec![];
    let mut sm = SecureMessaging::new(SessionKeys {
        k_enc: params.k_enc.clone().into(),
        k_mac: params.k_mac.clone().into(),
        cipher: params.cipher(),
    });

    for (response_hex, sent_cmd) in output_apdus.iter().zip(sent_commands.iter()) {
        let response_bytes = hex::decode(response_hex)?;
        let apdu_response = APDUResponse::from_bytes(&response_bytes)?;

        // Batch processing, increment SSC twice
        sm.update_ssc();
        sm.update_ssc();

        let decrypted_response = sm
            .process_secure_response(&apdu_response)
            .map_err(|e| AppError::paos_internal(format!("Failed to decrypt response: {e}")))?;

        let status = decrypted_response.status();
        let status_code = status.0;
        let is_success = status == StatusCode::SUCCESS;

        let processed_response = DecryptedAPDU {
            response_data: decrypted_response.data,
            cmd_type: sent_cmd.cmd_type.clone(),
            status_code,
            is_success,
        };
        processed_responses.push(processed_response);
    }
    Ok(processed_responses)
}
