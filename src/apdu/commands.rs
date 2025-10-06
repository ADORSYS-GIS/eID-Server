use crate::apdu::{APDUCommand, Ins};
use hex_literal::hex;

// Data Group definitions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataGroup {
    /// Document Type
    DG1 = 0x01,
    /// Issuing State
    DG2 = 0x02,
    /// Date of Expiry
    DG3 = 0x03,
    /// Given Names
    DG4 = 0x04,
    /// Family Names
    DG5 = 0x05,
    /// Nom de Plume
    DG6 = 0x06,
    /// Academic Title
    DG7 = 0x07,
    /// Date of Birth
    DG8 = 0x08,
    /// Place of Birth
    DG9 = 0x09,
    /// Nationality
    DG10 = 0x0A,
    /// Sex
    DG11 = 0x0B,
    /// Optional Data
    DG12 = 0x0C,
    /// Birth Name
    DG13 = 0x0D,
    /// Written Signature
    DG14 = 0x0E,
    /// Date of Issuance
    DG15 = 0x0F,
    /// Reserved for Future Use
    DG16 = 0x10,
    /// Normal Place of Residence
    DG17 = 0x11,
    /// Municipality ID
    DG18 = 0x12,
    /// Residence Permit I
    DG19 = 0x13,
    /// Residence Permit II
    DG20 = 0x14,
    /// Phone Number
    DG21 = 0x15,
    /// Email Address
    DG22 = 0x16,
}

impl DataGroup {
    pub fn fid(&self) -> u16 {
        match self {
            DataGroup::DG1 => 0x0101,
            DataGroup::DG2 => 0x0102,
            DataGroup::DG3 => 0x0103,
            DataGroup::DG4 => 0x0104,
            DataGroup::DG5 => 0x0105,
            DataGroup::DG6 => 0x0106,
            DataGroup::DG7 => 0x0107,
            DataGroup::DG8 => 0x0108,
            DataGroup::DG9 => 0x0109,
            DataGroup::DG10 => 0x010A,
            DataGroup::DG11 => 0x010B,
            DataGroup::DG12 => 0x010C,
            DataGroup::DG13 => 0x010D,
            DataGroup::DG14 => 0x010E,
            DataGroup::DG15 => 0x010F,
            DataGroup::DG16 => 0x0110,
            DataGroup::DG17 => 0x0111,
            DataGroup::DG18 => 0x0112,
            DataGroup::DG19 => 0x0113,
            DataGroup::DG20 => 0x0114,
            DataGroup::DG21 => 0x0115,
            DataGroup::DG22 => 0x0116,
        }
    }

    pub fn sfid(&self) -> u8 {
        *self as u8
    }
}

/// Command to select a file by FID
pub fn select_file(fid: u16) -> APDUCommand {
    let fid_bytes = fid.to_be_bytes();
    APDUCommand::new(Ins::Select, 0x02, 0x0C, fid_bytes, 0)
}

/// Command to select the eID application
pub fn select_eid_application() -> APDUCommand {
    let eid_app_id = hex!("E80704007F00070302");
    APDUCommand::new(Ins::Select, 0x04, 0x0C, eid_app_id, 0)
}

// Read binary data
pub fn read_binary(offset: u16, length: u8) -> APDUCommand {
    let p1 = ((offset >> 8) & 0xFF) as u8;
    let p2 = (offset & 0xFF) as u8;

    APDUCommand::new(Ins::ReadBinary, p1, p2, Vec::new(), length as u16)
}

// Read data group
pub fn read_data_group(data_group: DataGroup) -> Vec<APDUCommand> {
    vec![select_file(data_group.fid()), read_binary(0, 0)]
}
