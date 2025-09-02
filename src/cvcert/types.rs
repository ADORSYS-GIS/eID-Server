use std::collections::HashSet;
use std::ops::RangeInclusive;
use time::{PrimitiveDateTime, UtcDateTime};

use super::errors::Error;

pub(crate) type CvcResult<T> = Result<T, Error>;

/// Access roles for CV certificates according to TR-03110-3
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessRole {
    /// Authentication Terminal
    AT = 0,
    /// Document Verifier (non-official/foreign)
    DVNoF = 1,
    /// Document Verifier (official domestic)
    DVOD = 2,
    /// Card Verifiable Certificate Authority
    CVCA = 3,
    /// Unknown role
    Unknown = -1,
}

impl AccessRole {
    /// Get the bit pattern for the role in CHAT template
    pub fn bit_pattern(&self) -> u8 {
        match self {
            AccessRole::AT => 0b00,
            AccessRole::DVNoF => 0b01,
            AccessRole::DVOD => 0b10,
            AccessRole::CVCA => 0b11,
            AccessRole::Unknown => 0b00,
        }
    }

    /// Create from bit pattern
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b00 => AccessRole::AT,
            0b01 => AccessRole::DVNoF,
            0b10 => AccessRole::DVOD,
            0b11 => AccessRole::CVCA,
            _ => AccessRole::Unknown,
        }
    }
}

/// Access rights for CV certificates
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessRight {
    // Special Functions
    AgeVerification = 0,
    CommunityIdVerification = 1,
    RestrictedIdentification = 2,
    PrivilegedTerminal = 3,
    CanAllowed = 4,
    PinManagement = 5,
    InstallCert = 6,
    InstallQualifiedCert = 7,

    // Read Access
    ReadDG01 = 8,
    ReadDG02 = 9,
    ReadDG03 = 10,
    ReadDG04 = 11,
    ReadDG05 = 12,
    ReadDG06 = 13,
    ReadDG07 = 14,
    ReadDG08 = 15,
    ReadDG09 = 16,
    ReadDG10 = 17,
    ReadDG11 = 18,
    ReadDG12 = 19,
    ReadDG13 = 20,
    ReadDG14 = 21,
    ReadDG15 = 22,
    ReadDG16 = 23,
    ReadDG17 = 24,
    ReadDG18 = 25,
    ReadDG19 = 26,
    ReadDG20 = 27,
    ReadDG21 = 28,
    ReadDG22 = 29,

    // Reserved for Future Use
    Psa = 30,
    Rfu = 31,

    // Write Access
    WriteDG22 = 32,
    WriteDG21 = 33,
    WriteDG20 = 34,
    WriteDG19 = 35,
    WriteDG18 = 36,
    WriteDG17 = 37,
}

impl AccessRight {
    /// Get the bit position for this access right
    pub fn bit_position(&self) -> u8 {
        *self as u8
    }

    /// Check if this is a read access right
    pub fn is_read_access(&self) -> bool {
        self.bit_position() >= 8 && self.bit_position() <= 29
    }

    /// Check if this is a write access right
    pub fn is_write_access(&self) -> bool {
        self.bit_position() >= 32 && self.bit_position() <= 37
    }

    /// Check if this is a special function
    pub fn is_special_function(&self) -> bool {
        self.bit_position() < 8
    }
}

/// Collection of access rights
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRights {
    rights: HashSet<AccessRight>,
}

impl AccessRights {
    /// Create new empty access rights
    pub fn new() -> Self {
        Self {
            rights: HashSet::new(),
        }
    }

    /// Add an access right
    pub fn add(&mut self, right: AccessRight) -> &mut Self {
        // ReadDG16 is reserved for future use
        if right != AccessRight::ReadDG16 {
            self.rights.insert(right);
        }
        self
    }

    /// Remove an access right
    pub fn remove(&mut self, right: AccessRight) -> &mut Self {
        self.rights.remove(&right);
        self
    }

    /// Check if an access right is present
    pub fn has(&self, right: AccessRight) -> bool {
        self.rights.contains(&right)
    }

    /// Add read access for specific data group numbers.
    ///
    /// Read access range is 1 to 22
    pub fn with_read_access(mut self, dg_range: RangeInclusive<u8>) -> Self {
        for dg in dg_range {
            if (1..=22).contains(&dg) {
                let right = match dg {
                    1 => AccessRight::ReadDG01,
                    2 => AccessRight::ReadDG02,
                    3 => AccessRight::ReadDG03,
                    4 => AccessRight::ReadDG04,
                    5 => AccessRight::ReadDG05,
                    6 => AccessRight::ReadDG06,
                    7 => AccessRight::ReadDG07,
                    8 => AccessRight::ReadDG08,
                    9 => AccessRight::ReadDG09,
                    10 => AccessRight::ReadDG10,
                    11 => AccessRight::ReadDG11,
                    12 => AccessRight::ReadDG12,
                    13 => AccessRight::ReadDG13,
                    14 => AccessRight::ReadDG14,
                    15 => AccessRight::ReadDG15,
                    // ReadDG16 is reserved for future use
                    17 => AccessRight::ReadDG17,
                    18 => AccessRight::ReadDG18,
                    19 => AccessRight::ReadDG19,
                    20 => AccessRight::ReadDG20,
                    21 => AccessRight::ReadDG21,
                    22 => AccessRight::ReadDG22,
                    _ => continue,
                };
                self.rights.insert(right);
            }
        }
        self
    }

    /// Add write access for specific data group numbers.
    ///
    /// Write access range is 17 to 22
    pub fn with_write_access(mut self, dg_range: RangeInclusive<u8>) -> Self {
        for dg in dg_range {
            if (17..=22).contains(&dg) {
                let right = match dg {
                    17 => AccessRight::WriteDG17,
                    18 => AccessRight::WriteDG18,
                    19 => AccessRight::WriteDG19,
                    20 => AccessRight::WriteDG20,
                    21 => AccessRight::WriteDG21,
                    22 => AccessRight::WriteDG22,
                    _ => continue,
                };
                self.rights.insert(right);
            }
        }
        self
    }

    /// Add special functions.
    ///
    /// Special functions range is 0 to 7
    pub fn with_special_functions(mut self, function_range: RangeInclusive<u8>) -> Self {
        for func in function_range {
            if func <= 7 {
                let right = match func {
                    0 => AccessRight::AgeVerification,
                    1 => AccessRight::CommunityIdVerification,
                    2 => AccessRight::RestrictedIdentification,
                    3 => AccessRight::PrivilegedTerminal,
                    4 => AccessRight::CanAllowed,
                    5 => AccessRight::PinManagement,
                    6 => AccessRight::InstallCert,
                    7 => AccessRight::InstallQualifiedCert,
                    _ => continue,
                };
                self.rights.insert(right);
            }
        }
        self
    }

    /// Convert to 5-byte CHAT template according to TR-03110-3
    pub fn to_chat_template(&self, role: AccessRole) -> [u8; 5] {
        let mut template = [0u8; 5];
        // Set role bits (bits 38-39, highest bits of template[0])
        template[0] |= role.bit_pattern() << 6;
        // Set access rights
        for right in &self.rights {
            let bit_pos = right.bit_position();
            if bit_pos > 39 {
                continue;
            }
            let byte_index = 4 - (bit_pos / 8) as usize;
            let bit_index = bit_pos % 8;
            if byte_index < 5 {
                template[byte_index] |= 1 << bit_index;
            }
        }
        template
    }

    /// Create from 5-byte CHAT template
    pub fn from_chat_template(template: [u8; 5]) -> (AccessRole, Self) {
        let mut rights = Self::new();
        // Extract role (bits 38-39, highest bits of template[0])
        let role = AccessRole::from_bits((template[0] >> 6) & 0b11);
        // Extract access rights
        for (byte_index, byte) in template.iter().enumerate() {
            for bit_index in 0..8 {
                if byte & (1 << bit_index) != 0 {
                    let bit_pos = (4 - byte_index) * 8 + bit_index;
                    if let Some(right) = Self::bit_pos_to_right(bit_pos as u8) {
                        rights.rights.insert(right);
                    }
                }
            }
        }
        (role, rights)
    }

    /// Convert bit position to access right
    fn bit_pos_to_right(bit_pos: u8) -> Option<AccessRight> {
        match bit_pos {
            0 => Some(AccessRight::AgeVerification),
            1 => Some(AccessRight::CommunityIdVerification),
            2 => Some(AccessRight::RestrictedIdentification),
            3 => Some(AccessRight::PrivilegedTerminal),
            4 => Some(AccessRight::CanAllowed),
            5 => Some(AccessRight::PinManagement),
            6 => Some(AccessRight::InstallCert),
            7 => Some(AccessRight::InstallQualifiedCert),
            8 => Some(AccessRight::ReadDG01),
            9 => Some(AccessRight::ReadDG02),
            10 => Some(AccessRight::ReadDG03),
            11 => Some(AccessRight::ReadDG04),
            12 => Some(AccessRight::ReadDG05),
            13 => Some(AccessRight::ReadDG06),
            14 => Some(AccessRight::ReadDG07),
            15 => Some(AccessRight::ReadDG08),
            16 => Some(AccessRight::ReadDG09),
            17 => Some(AccessRight::ReadDG10),
            18 => Some(AccessRight::ReadDG11),
            19 => Some(AccessRight::ReadDG12),
            20 => Some(AccessRight::ReadDG13),
            21 => Some(AccessRight::ReadDG14),
            22 => Some(AccessRight::ReadDG15),
            23 => Some(AccessRight::ReadDG16),
            24 => Some(AccessRight::ReadDG17),
            25 => Some(AccessRight::ReadDG18),
            26 => Some(AccessRight::ReadDG19),
            27 => Some(AccessRight::ReadDG20),
            28 => Some(AccessRight::ReadDG21),
            29 => Some(AccessRight::ReadDG22),
            30 => Some(AccessRight::Rfu),
            31 => Some(AccessRight::Psa),
            32 => Some(AccessRight::WriteDG22),
            33 => Some(AccessRight::WriteDG21),
            34 => Some(AccessRight::WriteDG20),
            35 => Some(AccessRight::WriteDG19),
            36 => Some(AccessRight::WriteDG18),
            37 => Some(AccessRight::WriteDG17),
            _ => None,
        }
    }

    /// Get all rights as a set
    pub fn rights(&self) -> &HashSet<AccessRight> {
        &self.rights
    }
}

impl Default for AccessRights {
    fn default() -> Self {
        Self::new()
    }
}

/// Date representation for CV certificates (BCD format)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    year: u16,
    month: u8,
    day: u8,
}

impl Date {
    /// Create a new date.
    ///
    /// Year must be in range 2000-2099.
    /// Month must be in range 1-12.
    /// Day must be in range 1-31.
    pub fn new(year: u16, month: u8, day: u8) -> Result<Self, Error> {
        if !(2000..=2099).contains(&year) {
            return Err(Error::InvalidData(format!(
                "Year out of range [2000-2099]: {year}",
            )));
        }
        if !(1..=12).contains(&month) {
            return Err(Error::InvalidData(format!("Invalid month: {month}")));
        }
        if !(1..=31).contains(&day) {
            return Err(Error::InvalidData(format!("Invalid day: {day}")));
        }
        let max_days = match month {
            2 => {
                if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                    29 // Leap year
                } else {
                    28
                }
            }
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        if day > max_days {
            return Err(Error::InvalidData(format!(
                "Invalid day for month {month}: {day}",
            )));
        }

        Ok(Self { year, month, day })
    }

    /// Create from chrono DateTime
    pub fn from_datetime(dt: UtcDateTime) -> Self {
        Self {
            year: dt.year() as u16,
            month: dt.month() as u8,
            day: dt.day(),
        }
    }

    /// Create from chrono NaiveDate
    pub fn from_primitive_date(date: PrimitiveDateTime) -> Self {
        Self {
            year: date.year() as u16,
            month: date.month() as u8,
            day: date.day(),
        }
    }

    /// Create from current date and time
    pub fn now() -> Self {
        Self::from_datetime(UtcDateTime::now())
    }

    /// Convert to unpacked BCD format (YYMMDD, 6 bytes)
    pub fn to_bcd(&self) -> [u8; 6] {
        let yy = (self.year % 100) as u8;
        let mm = self.month;
        let dd = self.day;

        [
            (yy / 10) & 0x0F,
            (yy % 10) & 0x0F,
            (mm / 10) & 0x0F,
            (mm % 10) & 0x0F,
            (dd / 10) & 0x0F,
            (dd % 10) & 0x0F,
        ]
    }

    /// Create from unpacked BCD format (YYMMDD, 6 bytes)
    pub fn from_bcd(bcd: &[u8]) -> Result<Self, Error> {
        if bcd.len() != 6 {
            return Err(Error::InvalidData(format!(
                "Invalid BCD date length: {}. Expected 6.",
                bcd.len(),
            )));
        }

        // low nibble holds the digit; high nibble must be zero per "unpacked BCD"
        let digits: [u8; 6] = {
            let mut digits = [0u8; 6];
            for (i, byte) in bcd.iter().enumerate() {
                let d = byte & 0x0F;
                if byte >> 4 != 0 || d > 9 {
                    return Err(Error::InvalidData(format!(
                        "Invalid unpacked BCD at position {i}: 0x{byte:02x}"
                    )));
                }
                digits[i] = d;
            }
            digits
        };

        let year = 2000 + (digits[0] as u16) * 10 + digits[1] as u16;
        let month = digits[2] * 10 + digits[3];
        let day = digits[4] * 10 + digits[5];

        Date::new(year, month, day)
    }

    /// Get year
    pub fn year(&self) -> u16 {
        self.year
    }

    /// Get month
    pub fn month(&self) -> u8 {
        self.month
    }

    /// Get day
    pub fn day(&self) -> u8 {
        self.day
    }

    /// Convert to chrono PrimitiveDateTime
    pub fn to_primitive_date(&self) -> PrimitiveDateTime {
        use time::{Date, Month, Time};

        // Safety: this is safe because the constructor ensures that the month is in range 1-12.
        let month = Month::try_from(self.month).unwrap();
        let date = Date::from_calendar_date(self.year as i32, month, self.day).unwrap();
        let time = Time::from_hms(0, 0, 0).unwrap();
        PrimitiveDateTime::new(date, time)
    }
}

impl std::fmt::Display for Date {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}
