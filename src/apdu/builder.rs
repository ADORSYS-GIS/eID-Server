use bincode::{Decode, Encode};
use rasn::types::ObjectIdentifier;

use super::Result;
use crate::apdu::{self, APDUCommand, DataGroup, SecureMessaging};
use crate::asn1::oid::{DATE_OF_BIRTH_OID, MUNICIPALITY_ID_OID};
use crate::cvcert::{AccessRight, AccessRights};

/// APDU command type
#[derive(Debug, Clone, Encode, Decode)]
pub enum CmdType {
    SelectEidApp,
    SelectFile(u16),
    ReadBinary(u16, u8),
    VerifyAge,
    VerifyPlace,
}

/// Protected APDU command
#[derive(Debug, Clone, Encode, Decode)]
pub struct ProtectedAPDU {
    pub cmd: APDUCommand,
    pub cmd_type: CmdType,
    pub ssc_before_cmd: u32,
    pub ssc_before_resp: u32,
}

/// Build protected APDU commands based on access rights
pub fn build_protected_cmds(
    access_rights: &AccessRights,
    sm: &mut SecureMessaging,
) -> Result<Vec<ProtectedAPDU>> {
    let mut commands = Vec::new();

    // Advance SSC for command
    sm.update_ssc();
    let select_eid_cmd = apdu::select_eid_application();
    let secured_select_eid = sm.create_secure_command(&select_eid_cmd)?;

    commands.push(ProtectedAPDU {
        cmd: secured_select_eid,
        cmd_type: CmdType::SelectEidApp,
        ssc_before_cmd: sm.ssc() - 1,
        ssc_before_resp: sm.ssc(),
    });
    // Advance SSC again to account for the card's response
    sm.update_ssc();

    // Build commands based on access rights
    for right in access_rights.rights() {
        match right {
            AccessRight::ReadDG01 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG1)?);
            }
            AccessRight::ReadDG02 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG2)?);
            }
            AccessRight::ReadDG03 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG3)?);
            }
            AccessRight::ReadDG04 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG4)?);
            }
            AccessRight::ReadDG05 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG5)?);
            }
            AccessRight::ReadDG06 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG6)?);
            }
            AccessRight::ReadDG07 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG7)?);
            }
            AccessRight::ReadDG08 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG8)?);
            }
            AccessRight::ReadDG09 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG9)?);
            }
            AccessRight::ReadDG10 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG10)?);
            }
            AccessRight::ReadDG11 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG11)?);
            }
            AccessRight::ReadDG12 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG12)?);
            }
            AccessRight::ReadDG13 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG13)?);
            }
            AccessRight::ReadDG14 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG14)?);
            }
            AccessRight::ReadDG15 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG15)?);
            }
            AccessRight::ReadDG17 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG17)?);
            }
            AccessRight::ReadDG18 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG18)?);
            }
            AccessRight::ReadDG19 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG19)?);
            }
            AccessRight::ReadDG20 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG20)?);
            }
            AccessRight::ReadDG21 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG21)?);
            }
            AccessRight::ReadDG22 => {
                commands.extend(build_group_cmds(sm, DataGroup::DG22)?);
            }
            AccessRight::AgeVerification => {
                commands.extend(build_verif_cmds(sm, CmdType::VerifyAge, DATE_OF_BIRTH_OID)?);
            }
            AccessRight::CommunityIdVerification => {
                commands.extend(build_verif_cmds(
                    sm,
                    CmdType::VerifyPlace,
                    MUNICIPALITY_ID_OID,
                )?);
            }
            _ => {}
        }
    }
    Ok(commands)
}

fn build_group_cmds(
    sm: &mut SecureMessaging,
    data_group: crate::apdu::commands::DataGroup,
) -> Result<Vec<ProtectedAPDU>> {
    let mut commands = vec![];

    // First select the file
    sm.update_ssc();
    let select_cmd = apdu::select_file(data_group.fid());
    let secured_select = sm.create_secure_command(&select_cmd)?;

    commands.push(ProtectedAPDU {
        cmd: secured_select,
        cmd_type: CmdType::SelectFile(data_group.fid()),
        ssc_before_cmd: sm.ssc() - 1,
        ssc_before_resp: sm.ssc(),
    });
    // Advance SSC again to account for the card's response
    sm.update_ssc();

    // Then read the data
    sm.update_ssc();
    let read_cmd = apdu::read_binary(0, 0);
    let secured_read = sm.create_secure_command(&read_cmd)?;

    commands.push(ProtectedAPDU {
        cmd: secured_read,
        cmd_type: CmdType::ReadBinary(0, 0),
        ssc_before_cmd: sm.ssc() - 1,
        ssc_before_resp: sm.ssc(),
    });
    // Advance SSC again to account for the card's response
    sm.update_ssc();
    Ok(commands)
}

fn build_verif_cmds(
    sm: &mut SecureMessaging,
    command_type: CmdType,
    oid: &'static [u32],
) -> Result<Vec<ProtectedAPDU>> {
    let mut commands = vec![];

    sm.update_ssc();
    // Create verify command with CLA=0x8C (proprietary class)
    let oid = ObjectIdentifier::new_unchecked(oid.into());
    let mut verify_cmd = apdu::verify(rasn::der::encode(&oid)?);
    verify_cmd.cla = 0x8C;

    let secured_verify = sm.create_secure_command(&verify_cmd)?;
    commands.push(ProtectedAPDU {
        cmd: secured_verify,
        cmd_type: command_type,
        ssc_before_cmd: sm.ssc() - 1,
        ssc_before_resp: sm.ssc(),
    });
    sm.update_ssc();
    Ok(commands)
}
