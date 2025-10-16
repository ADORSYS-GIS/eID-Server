use bincode::{Decode, Encode};
use rasn::types::ObjectIdentifier;

use super::Result;
use crate::apdu::{self, APDUCommand, DataGroup, SecureMessaging};
use crate::asn1::oid::{DATE_OF_BIRTH_OID, MUNICIPALITY_ID_OID};
use crate::crypto::sym::Cipher;
use crate::cvcert::{AccessRight, AccessRights};

/// Secure messaging parameters for decrypting received APDU responses
#[derive(Debug, Clone, Decode, Encode)]
pub struct APDUDecryptParams {
    pub k_enc: Vec<u8>,
    pub k_mac: Vec<u8>,
    pub cipher_type: u8,
}

impl APDUDecryptParams {
    pub fn new(k_enc: impl Into<Vec<u8>>, k_mac: impl Into<Vec<u8>>, cipher: Cipher) -> Self {
        let cipher_type = match cipher {
            Cipher::Aes128Cbc => 1,
            Cipher::Aes192Cbc => 2,
            Cipher::Aes256Cbc => 3,
        };
        Self {
            k_enc: k_enc.into(),
            k_mac: k_mac.into(),
            cipher_type,
        }
    }

    pub fn cipher(&self) -> Cipher {
        match self.cipher_type {
            1 => Cipher::Aes128Cbc,
            2 => Cipher::Aes192Cbc,
            3 => Cipher::Aes256Cbc,
            _ => Cipher::Aes128Cbc,
        }
    }
}

/// Uniquely identifies a command and its context
#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub enum CmdType {
    SelectEidApp,
    SelectFile(DataGroup),
    ReadBinary(DataGroup),
    VerifyAge,
    VerifyPlace,
}

/// Protected APDU command that pairs the command with its decodable type
#[derive(Debug, Clone, Encode, Decode)]
pub struct ProtectedAPDU {
    pub cmd: APDUCommand,
    pub cmd_type: CmdType,
}

/// Decrypted APDU response with metadata
#[derive(Debug, Clone, Decode, Encode)]
pub struct DecryptedAPDU {
    pub response_data: Vec<u8>,
    pub cmd_type: CmdType,
    pub status_code: u16,
    pub is_success: bool,
}

/// Build protected APDU commands based on access rights
pub fn build_protected_cmds(
    access_rights: &AccessRights,
    sm: &mut SecureMessaging,
) -> Result<Vec<ProtectedAPDU>> {
    let mut commands = vec![];

    // Advance SSC for the command
    sm.update_ssc();
    let select_eid_cmd = apdu::select_eid_application();
    let secured_select_eid = sm.create_secure_command(&select_eid_cmd)?;

    commands.push(ProtectedAPDU {
        cmd: secured_select_eid,
        cmd_type: CmdType::SelectEidApp,
    });
    // Advance again to account for the card's response
    sm.update_ssc();

    for right in access_rights.rights() {
        match right {
            AccessRight::ReadDG01 => add_data_group_cmds(&mut commands, sm, DataGroup::DG1)?,
            AccessRight::ReadDG02 => add_data_group_cmds(&mut commands, sm, DataGroup::DG2)?,
            AccessRight::ReadDG03 => add_data_group_cmds(&mut commands, sm, DataGroup::DG3)?,
            AccessRight::ReadDG04 => add_data_group_cmds(&mut commands, sm, DataGroup::DG4)?,
            AccessRight::ReadDG05 => add_data_group_cmds(&mut commands, sm, DataGroup::DG5)?,
            AccessRight::ReadDG06 => add_data_group_cmds(&mut commands, sm, DataGroup::DG6)?,
            AccessRight::ReadDG07 => add_data_group_cmds(&mut commands, sm, DataGroup::DG7)?,
            AccessRight::ReadDG08 => add_data_group_cmds(&mut commands, sm, DataGroup::DG8)?,
            AccessRight::ReadDG09 => add_data_group_cmds(&mut commands, sm, DataGroup::DG9)?,
            AccessRight::ReadDG10 => add_data_group_cmds(&mut commands, sm, DataGroup::DG10)?,
            AccessRight::ReadDG11 => add_data_group_cmds(&mut commands, sm, DataGroup::DG11)?,
            AccessRight::ReadDG12 => add_data_group_cmds(&mut commands, sm, DataGroup::DG12)?,
            AccessRight::ReadDG13 => add_data_group_cmds(&mut commands, sm, DataGroup::DG13)?,
            AccessRight::ReadDG14 => add_data_group_cmds(&mut commands, sm, DataGroup::DG14)?,
            AccessRight::ReadDG15 => add_data_group_cmds(&mut commands, sm, DataGroup::DG15)?,
            AccessRight::ReadDG17 => add_data_group_cmds(&mut commands, sm, DataGroup::DG17)?,
            AccessRight::ReadDG18 => add_data_group_cmds(&mut commands, sm, DataGroup::DG18)?,
            AccessRight::ReadDG19 => add_data_group_cmds(&mut commands, sm, DataGroup::DG19)?,
            AccessRight::ReadDG20 => add_data_group_cmds(&mut commands, sm, DataGroup::DG20)?,
            AccessRight::ReadDG21 => add_data_group_cmds(&mut commands, sm, DataGroup::DG21)?,
            AccessRight::ReadDG22 => add_data_group_cmds(&mut commands, sm, DataGroup::DG22)?,
            AccessRight::AgeVerification => {
                add_verify_cmds(&mut commands, sm, CmdType::VerifyAge, DATE_OF_BIRTH_OID)?
            }
            AccessRight::CommunityIdVerification => {
                add_verify_cmds(&mut commands, sm, CmdType::VerifyPlace, MUNICIPALITY_ID_OID)?
            }
            _ => {}
        }
    }
    Ok(commands)
}

fn add_data_group_cmds(
    commands: &mut Vec<ProtectedAPDU>,
    sm: &mut SecureMessaging,
    data_group: DataGroup,
) -> Result<()> {
    let fid = data_group.fid();

    // First select file
    sm.update_ssc();
    let select_cmd = apdu::select_file(fid);
    let secured_select = sm.create_secure_command(&select_cmd)?;
    commands.push(ProtectedAPDU {
        cmd: secured_select,
        cmd_type: CmdType::SelectFile(data_group),
    });
    sm.update_ssc();

    // Then read binary
    sm.update_ssc();
    let read_cmd = apdu::read_binary(0, 0);
    let secured_read = sm.create_secure_command(&read_cmd)?;
    commands.push(ProtectedAPDU {
        cmd: secured_read,
        cmd_type: CmdType::ReadBinary(data_group),
    });
    sm.update_ssc();
    Ok(())
}

fn add_verify_cmds(
    commands: &mut Vec<ProtectedAPDU>,
    sm: &mut SecureMessaging,
    cmd_type: CmdType,
    oid: &'static [u32],
) -> Result<()> {
    sm.update_ssc();
    let oid = ObjectIdentifier::new_unchecked(oid.into());
    let mut verify_cmd = apdu::verify(rasn::der::encode(&oid)?);
    verify_cmd.cla = 0x8C;

    let secured_verify = sm.create_secure_command(&verify_cmd)?;
    commands.push(ProtectedAPDU {
        cmd: secured_verify,
        cmd_type,
    });
    sm.update_ssc();
    Ok(())
}
