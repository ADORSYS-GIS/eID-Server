use serde::Serialize;
use tracing::instrument;

use crate::cvcert::{AccessRight, AccessRights, CvCertificate};
use crate::domain::models::eid::{Operations, info::*};
use crate::pki::identity::Material;
use crate::pki::truststore::TrustStore;
use crate::server::{AppState, errors::AppError};
use crate::soap::Envelope;

const MAJOR: u8 = 2;
const MINOR: u8 = 4;
const BUGFIX: u8 = 0;
const DATE: &str = "02.08.2021";

#[derive(Debug, Serialize)]
struct GetServerInfoResp {
    #[serde(rename = "eid:getServerInfoResponse")]
    value: GetServerInfoResponse,
}

#[instrument(skip(state, _envelope))]
pub async fn handle_get_server_info<T: TrustStore>(
    state: AppState<T>,
    _envelope: Envelope<GetServerInfoRequest>,
) -> Result<String, AppError> {
    let identity = state.service.identity;
    let term_cvc_data = identity
        .get(Material::TermCvc)
        .await
        .map_err(AppError::soap_internal)?;
    let term_cvc = CvCertificate::from_der(&term_cvc_data).map_err(AppError::soap_internal)?;

    let access_rights = term_cvc.access_rights();
    let verif_rights = process_access_rights(access_rights);
    let version_string = format!("Version {MAJOR}.{MINOR}.{BUGFIX} {DATE}");

    let resp = GetServerInfoResp {
        value: GetServerInfoResponse {
            version: Version {
                version_string,
                major: MAJOR as i32,
                minor: MINOR as i32,
                bugfix: Some(BUGFIX as i32),
            },
            verif_rights,
        },
    };

    let result = Envelope::new(resp).serialize_soap(true);
    result.map_err(AppError::soap_internal)
}

fn process_access_rights(access_rights: AccessRights) -> Operations<AttributeSelect> {
    let mut verif_rights = Operations::default();

    for right in access_rights.rights() {
        match right {
            AccessRight::ReadDG01 => {
                verif_rights.document_type = Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                });
            }
            AccessRight::ReadDG02 => {
                verif_rights.issuing_state = Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                });
            }
            AccessRight::ReadDG03 => {
                verif_rights.date_of_expiry = Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                });
            }
            AccessRight::ReadDG04 => {
                verif_rights.given_names = Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                });
            }
            AccessRight::ReadDG05 => {
                verif_rights.family_names = Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                });
            }
            AccessRight::ReadDG06 => {
                verif_rights.artistic_name = Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                });
            }
            AccessRight::ReadDG07 => {
                verif_rights.academic_title = Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                });
            }
            AccessRight::ReadDG08 => {
                verif_rights.date_of_birth = Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                });
            }
            AccessRight::ReadDG09 => {
                verif_rights.place_of_birth = Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                });
            }
            AccessRight::ReadDG10 => {
                verif_rights.nationality = Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                });
            }
            AccessRight::ReadDG13 => {
                verif_rights.birth_name = Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                });
            }
            AccessRight::ReadDG17 => {
                verif_rights.place_of_residence = Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                });
            }
            AccessRight::ReadDG18 => {
                verif_rights.community_id = Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                });
            }
            AccessRight::ReadDG19 => {
                verif_rights.residence_permit_i = Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                });
            }
            AccessRight::RestrictedIdentification => {
                verif_rights.restricted_id = Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                });
            }
            AccessRight::AgeVerification => {
                verif_rights.age_verification = Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                });
            }
            AccessRight::CommunityIdVerification => {
                verif_rights.place_verification = Some(AttributeSelect {
                    value: AttrSelect::ALLOWED,
                });
            }
            _ => {}
        }
    }
    verif_rights
}
