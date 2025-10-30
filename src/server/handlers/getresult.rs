use std::collections::HashSet;

use rasn::der::decode as der_decode;
use serde::Serialize;
use tracing::instrument;
use validator::Validate;

use crate::apdu::{CmdType, DataGroup, DecryptedAPDU, StatusCode};
use crate::asn1::{perso_data::*, utils::MobileEIDType};
use crate::domain::models::eid::{
    AttrResponse, AttributeResp, EIDTypeResp, EIDTypeSelection, EIDTypeUsed, GeneralDate,
    GeneralPlace as ResultGeneralPlace, GetResultRequest, GetResultResponse, LevelOfAssurance,
    Operations, PersonalData, Place as ResultPlace, VerificationResult, useid::UseIDRequest,
};
use crate::domain::models::{ResultType, State};
use crate::pki::truststore::TrustStore;
use crate::server::handlers::sign_config;
use crate::server::{
    AppState,
    errors::{AppError, EidError},
};
use crate::session::SessionData;
use crate::soap::{Envelope, sign_envelope};

#[derive(Debug, Serialize, Validate)]
struct GetResultResp {
    #[serde(rename = "eid:getResultResponse")]
    #[validate(nested)]
    value: GetResultResponse,
}

#[instrument(skip(state, envelope))]
pub async fn handle_get_result<T: TrustStore>(
    state: AppState<T>,
    envelope: Envelope<GetResultRequest>,
) -> Result<String, AppError> {
    let body = envelope.into_body();
    let session_mgr = &state.service.session_manager;

    // Validate the request body
    body.validate().map_err(EidError::from)?;

    let mut session_data: SessionData = session_mgr
        .get(&*body.session.id)
        .await?
        .ok_or(EidError::InvalidSession)?;

    if session_data.request_counter + 1 != body.request_counter {
        return Err(AppError::Eid(EidError::InvalidCounter));
    }

    let State::TransmitResponse {
        responses,
        mobile_eid_type,
    } = session_data.state
    else {
        session_data.request_counter = body.request_counter;
        session_mgr.insert(&*body.session.id, session_data).await?;
        return Err(AppError::Eid(EidError::NoResultYet));
    };

    let resp = build_response(session_data.request_data, responses, mobile_eid_type).await?;

    // Clear the session after successful response
    session_mgr.remove(&*body.session.id).await?;

    resp.validate().map_err(AppError::soap_internal)?;
    let env = Envelope::new(resp);
    let result = sign_envelope(env, sign_config(&state).await?);
    result.map_err(AppError::soap_internal)
}

/// EID type determination per TR-03110 Amendment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EIDType {
    CardCertified,
    SECertified,
    SEEndorsed,
    HWKeyStore,
}

impl EIDType {
    fn level_of_assurance(self) -> LevelOfAssurance {
        match self {
            Self::CardCertified => LevelOfAssurance::BsiHoch,
            Self::SECertified | Self::SEEndorsed => LevelOfAssurance::BsiSubstantiell,
            Self::HWKeyStore => LevelOfAssurance::BsiNormal,
        }
    }

    fn from_mobile_type(mobile_type: MobileEIDType) -> Self {
        match mobile_type {
            MobileEIDType::SECertified => Self::SECertified,
            MobileEIDType::SEEndorsed => Self::SEEndorsed,
            MobileEIDType::HWKeyStore => Self::HWKeyStore,
        }
    }
}

async fn build_response(
    request_data: UseIDRequest,
    responses: Vec<DecryptedAPDU>,
    mobile_eid_type: Option<MobileEIDType>,
) -> Result<GetResultResp, AppError> {
    let eid_type = mobile_eid_type
        .map(EIDType::from_mobile_type)
        .unwrap_or(EIDType::CardCertified);

    // Validate eID type selection
    validate_eid_type(&request_data, eid_type)?;

    // Validate Level of Assurance requirements
    let level_of_assurance = request_data
        .level_of_assurance
        .map(|_| validate_and_get_loa(eid_type, &request_data))
        .transpose()?;

    // Extract data from responses
    let (personal_data, ops_allowed, fulfils_age, fulfils_place) =
        extract_response_data(&responses)?;

    let eid_type_resp = request_data
        .eid_type
        .as_ref()
        .map(|_| build_eid_type_resp(eid_type));

    let resp = GetResultResponse {
        personal_data: Some(personal_data),
        fulfils_age,
        fulfils_place,
        ops_allowed: Some(ops_allowed),
        trans_attest_resp: None,
        level_of_assurance,
        eid_type_resp,
        result: ResultType::ok(),
    };
    Ok(GetResultResp { value: resp })
}

fn validate_eid_type(request_data: &UseIDRequest, eid_type: EIDType) -> Result<(), AppError> {
    let Some(req) = &request_data.eid_type else {
        return Ok(());
    };

    let is_denied = match eid_type {
        EIDType::CardCertified => req.card_certified == Some(EIDTypeSelection::DENIED),
        EIDType::SECertified => req.se_certified == Some(EIDTypeSelection::DENIED),
        EIDType::SEEndorsed => req.se_endorsed == Some(EIDTypeSelection::DENIED),
        EIDType::HWKeyStore => req.hw_key_store == Some(EIDTypeSelection::DENIED),
    };

    if is_denied {
        return Err(AppError::Eid(EidError::DeniedDocument));
    }
    Ok(())
}

fn validate_and_get_loa(
    eid_type: EIDType,
    request_data: &UseIDRequest,
) -> Result<LevelOfAssurance, AppError> {
    let actual_loa = eid_type.level_of_assurance();

    let Some(requested_loa) = request_data.level_of_assurance else {
        return Ok(actual_loa);
    };
    // Check if actual LoA meets or exceeds requested
    if (actual_loa as u8) >= (requested_loa as u8) {
        return Ok(actual_loa);
    }
    // Lower LoA: only acceptable if eID type is explicitly allowed
    if is_eid_type_allowed(request_data, eid_type) {
        return Ok(actual_loa);
    }
    Err(AppError::Eid(EidError::DeniedDocument))
}

fn is_eid_type_allowed(request_data: &UseIDRequest, eid_type: EIDType) -> bool {
    let Some(req) = &request_data.eid_type else {
        return false;
    };

    match eid_type {
        EIDType::CardCertified => req.card_certified == Some(EIDTypeSelection::ALLOWED),
        EIDType::SECertified => req.se_certified == Some(EIDTypeSelection::ALLOWED),
        EIDType::SEEndorsed => req.se_endorsed == Some(EIDTypeSelection::ALLOWED),
        EIDType::HWKeyStore => req.hw_key_store == Some(EIDTypeSelection::ALLOWED),
    }
}

type ResultData = (
    PersonalData,
    Operations<AttributeResp>,
    Option<VerificationResult>,
    Option<VerificationResult>,
);

fn extract_response_data(responses: &Vec<DecryptedAPDU>) -> Result<ResultData, AppError> {
    let mut personal_data = PersonalData::default();
    let mut ops_allowed = Operations::default();
    let mut age_verification_result = None;
    let mut place_verification_result = None;
    let mut failed_selects = HashSet::new();

    for response in responses {
        process_response(
            response,
            &mut personal_data,
            &mut ops_allowed,
            &mut age_verification_result,
            &mut place_verification_result,
            &mut failed_selects,
        )?;
    }
    Ok((
        personal_data,
        ops_allowed,
        age_verification_result,
        place_verification_result,
    ))
}

fn process_response(
    response: &DecryptedAPDU,
    personal_data: &mut PersonalData,
    ops_allowed: &mut Operations<AttributeResp>,
    age_result: &mut Option<VerificationResult>,
    place_result: &mut Option<VerificationResult>,
    failed_selects: &mut HashSet<DataGroup>,
) -> Result<(), AppError> {
    let status = compute_response_status(response);

    match response.cmd_type {
        CmdType::VerifyAge => {
            *age_result = Some(VerificationResult {
                fulfils_request: response.is_success,
            });
            ops_allowed.age_verification = Some(AttributeResp { value: status });
            return Ok(());
        }
        CmdType::VerifyPlace => {
            *place_result = Some(VerificationResult {
                fulfils_request: response.is_success,
            });
            ops_allowed.place_verification = Some(AttributeResp { value: status });
            return Ok(());
        }
        CmdType::SelectFile(dg) => {
            // Track failed selects and update ops_allowed
            if !response.is_success {
                failed_selects.insert(dg);
                update_ops_allowed(ops_allowed, dg, status);
            }
            return Ok(());
        }
        CmdType::ReadBinary(dg) => {
            if failed_selects.contains(&dg) {
                return Ok(());
            }
            update_ops_allowed(ops_allowed, dg, status);

            if response.is_success
                && let Err(e) = store_datagroup(dg, &response.response_data, personal_data)
            {
                tracing::warn!("Failed to parse {dg:?}: {e:?}");
            }
        }
        _ => {}
    }
    Ok(())
}

fn compute_response_status(response: &DecryptedAPDU) -> AttrResponse {
    if response.is_success {
        AttrResponse::ALLOWED
    } else if response.status_code == StatusCode::FILE_NOT_FOUND.0 {
        AttrResponse::NOTONCHIP
    } else {
        AttrResponse::PROHIBITED
    }
}

fn update_ops_allowed(ops: &mut Operations<AttributeResp>, dg: DataGroup, status: AttrResponse) {
    let attr = match dg {
        DataGroup::DG1 => Some(&mut ops.document_type),
        DataGroup::DG2 => Some(&mut ops.issuing_state),
        DataGroup::DG3 => Some(&mut ops.date_of_expiry),
        DataGroup::DG4 => Some(&mut ops.given_names),
        DataGroup::DG5 => Some(&mut ops.family_names),
        DataGroup::DG6 => Some(&mut ops.artistic_name),
        DataGroup::DG7 => Some(&mut ops.academic_title),
        DataGroup::DG8 => Some(&mut ops.date_of_birth),
        DataGroup::DG9 => Some(&mut ops.place_of_birth),
        DataGroup::DG10 => Some(&mut ops.nationality),
        DataGroup::DG13 => Some(&mut ops.birth_name),
        DataGroup::DG17 => Some(&mut ops.place_of_residence),
        DataGroup::DG18 => Some(&mut ops.community_id),
        DataGroup::DG19 => Some(&mut ops.residence_permit_i),
        _ => None,
    };

    if let Some(attr) = attr {
        *attr = Some(AttributeResp { value: status });
    }
}

fn store_datagroup(
    dg: DataGroup,
    data: &[u8],
    perso_data: &mut PersonalData,
) -> Result<(), AppError> {
    match dg {
        DataGroup::DG1 => {
            let doc_type = der_decode::<DocumentType>(data)?;
            perso_data.document_type = Some(String::from_utf8_lossy(&doc_type.0).to_string());
        }
        DataGroup::DG2 => {
            let issuing = der_decode::<IssuingEntity>(data)?;
            if let IssuingEntityChoice::IssuingState(country) = issuing.0 {
                perso_data.issuing_state = Some(String::from_utf8_lossy(&country).to_string());
            }
        }
        DataGroup::DG3 => {
            let expiry = der_decode::<DateOfExpiry>(data)?;
            perso_data.date_of_expiry = Some(String::from_utf8_lossy(&expiry.0).to_string());
        }
        DataGroup::DG4 => {
            let names = der_decode::<GivenNames>(data)?;
            perso_data.given_names = Some(names.0);
        }
        DataGroup::DG5 => {
            let names = der_decode::<FamilyNames>(data)?;
            perso_data.family_names = Some(names.0);
        }
        DataGroup::DG6 => {
            let plume = der_decode::<NomDePlume>(data)?;
            perso_data.artistic_name = Some(plume.0);
        }
        DataGroup::DG7 => {
            let title = der_decode::<AcademicTitle>(data)?;
            perso_data.academic_title = Some(title.0);
        }
        DataGroup::DG8 => {
            let dob = der_decode::<DateOfBirth>(data)?;
            let date_string = String::from_utf8_lossy(&dob.0).to_string();
            perso_data.date_of_birth = Some(GeneralDate {
                date_value: Some(convert_date_format(&date_string)),
                date_string,
            });
        }
        DataGroup::DG9 => {
            let pob = der_decode::<PlaceOfBirth>(data)?;
            perso_data.place_of_birth = Some(convert_general_place(pob.0));
        }
        DataGroup::DG10 => {
            let nat = der_decode::<Nationality>(data)?;
            perso_data.nationality = Some(String::from_utf8_lossy(&nat.0).to_string());
        }
        DataGroup::DG13 => {
            let name = der_decode::<BirthName>(data)?;
            perso_data.birth_name = Some(name.0);
        }
        DataGroup::DG17 => {
            let residence = der_decode::<PlaceOfResidence>(data)?;
            perso_data.place_of_residence = Some(convert_place_of_residence(residence));
        }
        DataGroup::DG18 => {
            let mun_id = der_decode::<MunicipalityID>(data)?;
            perso_data.community_id = Some(hex::encode_upper(&mun_id.0));
        }
        DataGroup::DG19 => {
            let permit = der_decode::<ResidencePermitI>(data)?;
            if let Text::Uncompressed(text) = permit.0 {
                perso_data.residence_permit_i = Some(text);
            }
        }
        _ => {}
    }
    Ok(())
}

fn build_eid_type_resp(eid_type: EIDType) -> EIDTypeResp {
    let mut resp = EIDTypeResp::default();
    match eid_type {
        EIDType::CardCertified => resp.card_certified = Some(EIDTypeUsed::USED),
        EIDType::SECertified => resp.se_certified = Some(EIDTypeUsed::USED),
        EIDType::SEEndorsed => resp.se_endorsed = Some(EIDTypeUsed::USED),
        EIDType::HWKeyStore => resp.hw_key_store = Some(EIDTypeUsed::USED),
    }
    resp
}

fn convert_date_format(date_str: &str) -> String {
    if date_str.len() == 8 {
        format!(
            "{}-{}-{}",
            &date_str[0..4],
            &date_str[4..6],
            &date_str[6..8]
        )
    } else {
        date_str.to_string()
    }
}

fn convert_general_place(general_place: GeneralPlace) -> ResultGeneralPlace {
    match general_place {
        GeneralPlace::StructuredPlace(p) => ResultGeneralPlace {
            structured_place: Some(ResultPlace {
                street: p.street,
                city: p.city,
                state: p.state,
                country: String::from_utf8_lossy(&p.country).to_string(),
                zip_code: p.zipcode.map(|s| String::from_utf8_lossy(&s).to_string()),
            }),
            freetext_place: None,
            no_place_info: None,
        },
        GeneralPlace::FreetextPlace(s) => ResultGeneralPlace {
            structured_place: None,
            freetext_place: Some(s),
            no_place_info: None,
        },
        GeneralPlace::NoPlaceInfo(s) => ResultGeneralPlace {
            structured_place: None,
            freetext_place: None,
            no_place_info: Some(s),
        },
    }
}

fn convert_place_of_residence(place: PlaceOfResidence) -> ResultGeneralPlace {
    match place.0 {
        PlaceOfResidenceChoice::Residence(gp) => convert_general_place(gp),
        _ => ResultGeneralPlace {
            structured_place: None,
            freetext_place: None,
            no_place_info: None,
        },
    }
}
