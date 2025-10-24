mod commands;
mod tlv;
mod utils;

pub use commands::*;
pub use tlv::APDUTlv;
pub use utils::*;

use crate::asn1::utils::ChipAuthAlg;
use crate::crypto::kdf::KdfParams;
use crate::crypto::{
    PrivateKey, PublicKey, SecureBytes, iso_7816_pad, iso_7816_unpad,
    sym::{AesEncryptor, Cipher},
};
use bincode::{Decode, Encode};

type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Cryptographic error: {0}")]
    Crypto(#[from] crate::crypto::Error),

    #[error("ASN.1 error: {0}")]
    Asn1(#[from] rasn::error::EncodeError),
}

/// ISO7816 instructions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum Ins {
    Unknown = 0x00,
    Verify = 0x20,
    Select = 0xA4,
    ReadBinary = 0xB0,
    MseSet = 0x22,
    GeneralAuth = 0x86,
}

impl From<u8> for Ins {
    fn from(value: u8) -> Self {
        match value {
            0x20 => Self::Verify,
            0xA4 => Self::Select,
            0xB0 => Self::ReadBinary,
            0x22 => Self::MseSet,
            0x86 => Self::GeneralAuth,
            _ => Self::Unknown,
        }
    }
}

/// APDU structure using iso7816 crate concepts
#[derive(Debug, Clone, Encode, Decode)]
pub struct APDUCommand {
    pub cla: u8,
    pub ins: Ins,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    pub le: Option<u16>,
}

impl APDUCommand {
    const SHORT_MAX_LC: usize = 0xFF;
    const SHORT_MAX_LE: u16 = 0x0100;
    const EXTENDED_MAX_LE: u32 = 0x010000;

    pub fn new(ins: Ins, p1: u8, p2: u8, data: impl Into<Vec<u8>>, le: Option<u16>) -> Self {
        Self {
            cla: 0x00,
            ins,
            p1,
            p2,
            data: data.into(),
            le,
        }
    }

    pub fn from_components(header: [u8; 4], data: impl Into<Vec<u8>>, le: Option<u16>) -> Self {
        Self {
            cla: header[0],
            ins: header[1].into(),
            p1: header[2],
            p2: header[3],
            data: data.into(),
            le,
        }
    }

    pub fn set_secure_messaging(&mut self, enabled: bool) {
        if enabled {
            self.cla |= 0x0C;
        } else {
            self.cla &= !0x0C;
        }
    }

    pub fn is_secure_messaging(&self) -> bool {
        (self.cla & 0x0C) == 0x0C
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.cla, self.ins as u8, self.p1, self.p2];

        // Add data length and data if present
        if !self.data.is_empty() {
            if self.data.len() <= Self::SHORT_MAX_LC {
                bytes.push(self.data.len() as u8);
            } else {
                bytes.push(0x00);
                bytes.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
            }
            bytes.extend_from_slice(&self.data);
        }
        // Compute expected response length
        if let Some(le) = self.le {
            if le == 0 {
                bytes.push(0x00);
            } else if le > 0 {
                if le > Self::SHORT_MAX_LE || self.data.len() > Self::SHORT_MAX_LC {
                    bytes.extend_from_slice(&(le).to_be_bytes());
                } else {
                    bytes.push(if le == 0x100 { 0x00 } else { le as u8 });
                }
            }
        }
        bytes
    }
}

/// ISO7816 status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCode(pub u16);

impl StatusCode {
    pub const SUCCESS: StatusCode = StatusCode(0x9000);
    pub const INVALID_SM_OBJECTS: StatusCode = StatusCode(0x6988);
    pub const VERIFY_FAILED: StatusCode = StatusCode(0x6300);
    pub const REF_DATA_NOT_FOUND: StatusCode = StatusCode(0x6A88);
    pub const FILE_NOT_FOUND: StatusCode = StatusCode(0x6A82);
    pub const NOT_AUTHORIZED: StatusCode = StatusCode(0x6982);
}

#[derive(Debug, Clone)]
pub struct APDUResponse {
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl APDUResponse {
    pub fn new(data: impl Into<Vec<u8>>, sw1: u8, sw2: u8) -> Self {
        Self {
            data: data.into(),
            sw1,
            sw2,
        }
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() < 2 {
            return Err(Error::InvalidData("Invalid APDU format".into()));
        }

        let len = bytes.len();
        let sw1 = bytes[len - 2];
        let sw2 = bytes[len - 1];
        let data = bytes[..len - 2].to_vec();
        Ok(Self { data, sw1, sw2 })
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn status(&self) -> StatusCode {
        StatusCode((self.sw1 as u16) << 8 | (self.sw2 as u16))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.data.clone();
        bytes.push(self.sw1);
        bytes.push(self.sw2);
        bytes
    }
}

/// Secure Messaging Keys computed from the key derivation function
#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub k_enc: SecureBytes,
    pub k_mac: SecureBytes,
    pub cipher: Cipher,
}

impl SessionKeys {
    pub fn derive(
        priv_key: &PrivateKey,
        peer_public: &PublicKey,
        algorithm: ChipAuthAlg,
        nonce: impl AsRef<[u8]>,
    ) -> Result<Self> {
        use crate::crypto::{HashAlg, ecdh, kdf};

        let cipher = algorithm.to_cipher();
        let hash_alg = match algorithm {
            ChipAuthAlg::EcdhAesCbcCmac128 => HashAlg::Sha1,
            ChipAuthAlg::EcdhAesCbcCmac192 | ChipAuthAlg::EcdhAesCbcCmac256 => HashAlg::Sha256,
        };

        let shared_secret = ecdh::key_agreement(priv_key, peer_public)?;

        let k_enc = kdf::derive_from_shared_secret(
            &shared_secret,
            &KdfParams::new(hash_alg, cipher.key_size())
                .with_nonce(nonce.as_ref())
                .with_counter(1),
        )?;

        let k_mac = kdf::derive_from_shared_secret(
            &shared_secret,
            &KdfParams::new(hash_alg, cipher.key_size())
                .with_nonce(nonce.as_ref())
                .with_counter(2),
        )?;

        Ok(Self {
            k_enc,
            k_mac,
            cipher,
        })
    }

    pub fn cipher(&self) -> Cipher {
        self.cipher
    }
}

/// ISO7816-4 Secure Messaging implementation
pub struct SecureMessaging {
    keys: SessionKeys,
    encryptor: AesEncryptor,
    ssc: u32,
}

impl SecureMessaging {
    /// Create a new Secure Messaging instance
    pub fn new(keys: SessionKeys) -> Self {
        let cipher = keys.cipher;
        Self {
            keys,
            encryptor: AesEncryptor::with_cipher(cipher),
            ssc: 0,
        }
    }

    /// Update the Send Sequence Counter
    pub fn update_ssc(&mut self) {
        self.ssc += 1;
    }

    /// Get the current Send Sequence Counter
    pub fn ssc(&self) -> u32 {
        self.ssc
    }

    /// Calculate CMAC for the given data
    pub fn calculate_mac(&self, data: impl AsRef<[u8]>) -> Result<[u8; 8]> {
        let mac_bytes = self.encryptor.calculate_mac(self.k_mac(), data)?;
        let mut mac = [0u8; 8];
        mac.copy_from_slice(&mac_bytes[..8]);
        Ok(mac)
    }

    /// Create a secure APDU command
    pub fn create_secure_command(&mut self, command: &APDUCommand) -> Result<APDUCommand> {
        let block_size = self.encryptor.cipher().block_size();
        let ssc_bytes = Self::ssc_to_bytes(self.ssc);
        let iv = self.derive_encrypted_iv(&ssc_bytes)?;
        // Set secure messaging flag
        let cla = command.cla | 0x0C;
        let header = [cla, command.ins as u8, command.p1, command.p2];

        // Encrypt and add command data if present
        let mut encrypted_data = vec![];
        if !command.data.is_empty() {
            let encrypted = self.encrypt_data(&command.data, &iv)?;
            let encrypted_tlv = APDUTlv::encrypted_data(encrypted);
            encrypted_data.extend_from_slice(&encrypted_tlv.encode());
        }

        // Add expected length if present
        let mut encoded_le = vec![];
        if let Some(le) = command.le {
            let le_tlv = APDUTlv::expected_length(le);
            encoded_le.extend_from_slice(&le_tlv.encode());
        }

        // dataToMac = padToBlock(paddedHeader) || formattedEncryptedData || securedLe
        let mut data_to_mac = vec![];
        let padded_header = iso_7816_pad(&header, block_size);
        data_to_mac.extend_from_slice(&padded_header);
        data_to_mac.extend_from_slice(&encrypted_data);
        data_to_mac.extend_from_slice(&encoded_le);

        // If any data is present, pad the dataToMac
        if !encrypted_data.is_empty() || !encoded_le.is_empty() {
            let padded_data = iso_7816_pad(&data_to_mac, block_size);
            data_to_mac = padded_data;
        }

        // Prepare MAC input: SSC || dataToMac
        let mut mac_input = ssc_bytes.to_vec();
        mac_input.extend_from_slice(&data_to_mac);
        // Calculate MAC
        let mac = self.calculate_mac(&mac_input)?;

        let mut secured_data = encrypted_data;
        secured_data.extend_from_slice(&encoded_le);
        let mac_tlv = APDUTlv::mac(mac);
        secured_data.extend_from_slice(&mac_tlv.encode());

        let new_le = if secured_data.len() > 0xFF || encoded_le.len() > 0x100 {
            APDUCommand::EXTENDED_MAX_LE as u16
        } else {
            APDUCommand::SHORT_MAX_LE
        };

        let apdu = APDUCommand::from_components(header, secured_data, Some(new_le));
        Ok(apdu)
    }

    pub fn process_secure_response(&mut self, response: &APDUResponse) -> Result<APDUResponse> {
        if response.data.is_empty() {
            return Err(Error::InvalidData("Empty response data".into()));
        }

        let block_size = self.encryptor.cipher().block_size();
        let ssc_bytes = Self::ssc_to_bytes(self.ssc);
        let tlv_objects = APDUTlv::parse_multiple(&response.data)?;

        let mut encrypted_data = None;
        let mut processing_status = None;
        let mut received_mac = None;
        let mut mac_input_data = Vec::new();

        for tlv in &tlv_objects {
            match tlv.tag {
                0x87 => {
                    // Encrypted data, first byte should be 0x01
                    if tlv.data.is_empty() || tlv.data[0] != 0x01 {
                        return Err(Error::InvalidData("Invalid encrypted data format".into()));
                    }
                    encrypted_data = Some(tlv.data[1..].to_vec());
                    mac_input_data.extend_from_slice(&tlv.encode());
                }
                0x99 => {
                    // Processing status, should be exactly 2 bytes
                    if tlv.data.len() != 2 {
                        return Err(Error::InvalidData(
                            "Invalid processing status length".into(),
                        ));
                    }
                    processing_status = Some([tlv.data[0], tlv.data[1]]);
                    mac_input_data.extend_from_slice(&tlv.encode());
                }
                0x8E => {
                    // MAC , should be exactly 8 bytes
                    if tlv.data.len() != 8 {
                        return Err(Error::InvalidData("Invalid MAC length".into()));
                    }
                    let mut mac_bytes = [0u8; 8];
                    mac_bytes.copy_from_slice(&tlv.data);
                    received_mac = Some(mac_bytes);
                }
                _ => {
                    return Err(Error::InvalidData(format!(
                        "Unknown TLV tag: 0x{:02X}",
                        tlv.tag
                    )));
                }
            }
        }

        // Verify status codes match if present
        if let Some(status) = processing_status {
            let secured_status_code = ((status[0] as u16) << 8) | (status[1] as u16);
            let response_status_code = ((response.sw1 as u16) << 8) | (response.sw2 as u16);

            if secured_status_code != response_status_code {
                return Err(Error::InvalidData("Status codes mismatch".into()));
            }
        }

        // Verify MAC
        let received_mac =
            received_mac.ok_or_else(|| Error::InvalidData("MAC not present".into()))?;
        let mut mac_input = ssc_bytes.to_vec();
        let padded_mac_data = iso_7816_pad(&mac_input_data, block_size);
        mac_input.extend_from_slice(&padded_mac_data);

        let calculated_mac = self.calculate_mac(&mac_input)?;
        if received_mac != calculated_mac {
            return Err(Error::InvalidData("MAC verification failed".into()));
        }

        // Decrypt data if present
        let mut plaintext = vec![];
        if let Some(cipher_data) = encrypted_data {
            let iv = self.derive_encrypted_iv(&ssc_bytes)?;
            let decrypted = self.decrypt_data(&cipher_data, &iv)?;
            plaintext = iso_7816_unpad(&decrypted);
        }

        let (sw1, sw2) = if let Some(status) = processing_status {
            (status[0], status[1])
        } else {
            (response.sw1, response.sw2)
        };
        Ok(APDUResponse::new(plaintext, sw1, sw2))
    }

    fn encrypt_data(&self, plaintext: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        Ok(self.encryptor.encrypt(self.k_enc(), iv, plaintext)?)
    }

    fn decrypt_data(&self, ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        Ok(self.encryptor.decrypt(self.k_enc(), iv, ciphertext)?)
    }

    fn k_enc(&self) -> &[u8] {
        self.keys.k_enc.expose_secret()
    }

    fn k_mac(&self) -> &[u8] {
        self.keys.k_mac.expose_secret()
    }

    fn ssc_to_bytes(ssc: u32) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[12..].copy_from_slice(&ssc.to_be_bytes());
        bytes
    }

    // AES-CBC encrypt a single-block SSC with IV = zeros
    // to derive the initialization vector
    fn derive_encrypted_iv(&self, ssc_block: &[u8; 16]) -> Result<Vec<u8>> {
        let zero_iv = vec![0u8; 16];
        Ok(self.encryptor.encrypt(self.k_enc(), &zero_iv, ssc_block)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_keys() -> SessionKeys {
        SessionKeys {
            k_enc: SecureBytes::from(vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ]),
            k_mac: SecureBytes::from(vec![
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
                0x1F, 0x20,
            ]),
            cipher: Cipher::Aes128Cbc,
        }
    }

    #[test]
    fn test_ssc_to_bytes() {
        let bytes = SecureMessaging::ssc_to_bytes(0x12345678);

        assert_eq!(bytes.len(), 16);
        // First 12 bytes should be zero
        assert_eq!(&bytes[..12], &[0u8; 12]);
        // Last 4 bytes should contain the SSC in big-endian
        assert_eq!(&bytes[12..], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_create_command_no_data() {
        let keys = create_test_keys();
        let mut sm = SecureMessaging::new(keys);

        let cmd = APDUCommand::new(Ins::Select, 0x04, 0x0C, vec![], Some(0x00));
        let result = sm.create_secure_command(&cmd);

        assert!(result.is_ok());
        let secured = result.unwrap();

        // Should have secure messaging enabled
        assert!(secured.is_secure_messaging());

        // Should have MAC TLV
        assert!(!secured.data.is_empty());

        // Parse TLVs to verify structure
        let tlvs = APDUTlv::parse_multiple(&secured.data).unwrap();
        // MAC TLV should be present
        assert!(tlvs.iter().any(|t| t.tag == 0x8E));
    }

    #[test]
    fn test_create_command_with_data() {
        let keys = create_test_keys();
        let mut sm = SecureMessaging::new(keys);

        let cmd = APDUCommand::new(Ins::Select, 0x04, 0x0C, vec![0x01, 0x02, 0x03], Some(0x00));
        let result = sm.create_secure_command(&cmd);

        assert!(result.is_ok());
        let secured = result.unwrap();

        assert!(secured.is_secure_messaging());

        let tlvs = APDUTlv::parse_multiple(&secured.data).unwrap();
        // Encrypted data TLV should be present
        assert!(tlvs.iter().any(|t| t.tag == 0x87));
        // MAC TLV should be present
        assert!(tlvs.iter().any(|t| t.tag == 0x8E));
    }

    #[test]
    fn test_process_response_success() {
        let keys = create_test_keys();
        let mut sm = SecureMessaging::new(keys);

        let mut response_data = Vec::new();

        // Add processing status TLV
        let status_tlv = APDUTlv::processing_status(0x90, 0x00);
        response_data.extend_from_slice(&status_tlv.encode());

        // Calculate MAC over the response data
        let ssc_bytes = SecureMessaging::ssc_to_bytes(sm.ssc);
        let mut mac_input = ssc_bytes.to_vec();
        let block_size = sm.encryptor.cipher().block_size();
        let padded_data = iso_7816_pad(&response_data, block_size);
        mac_input.extend_from_slice(&padded_data);

        let mac = sm.calculate_mac(&mac_input).unwrap();
        let mac_tlv = APDUTlv::mac(mac);
        response_data.extend_from_slice(&mac_tlv.encode());

        let response = APDUResponse::new(response_data, 0x90, 0x00);
        let result = sm.process_secure_response(&response);

        assert!(result.is_ok());
        let processed = result.unwrap();
        assert_eq!(processed.status(), StatusCode::SUCCESS);
    }

    #[test]
    fn test_process_response_mac_verification_fails() {
        let keys = create_test_keys();
        let mut sm = SecureMessaging::new(keys);

        let mut response_data = Vec::new();
        let status_tlv = APDUTlv::processing_status(0x90, 0x00);
        response_data.extend_from_slice(&status_tlv.encode());

        // Invalid MAC
        let bad_mac = [0xFF; 8];
        let mac_tlv = APDUTlv::mac(bad_mac);
        response_data.extend_from_slice(&mac_tlv.encode());

        let response = APDUResponse::new(response_data, 0x90, 0x00);
        let result = sm.process_secure_response(&response);

        assert!(result.is_err());
        if let Err(Error::InvalidData(msg)) = result {
            assert!(msg.contains("MAC verification failed"));
        } else {
            panic!("Expected MAC verification error");
        }
    }

    #[test]
    fn test_process_response_status_mismatch() {
        let keys = create_test_keys();
        let mut sm = SecureMessaging::new(keys);

        let mut response_data = Vec::new();

        // Status in TLV differs from response status
        let status_tlv = APDUTlv::processing_status(0x63, 0x00);
        response_data.extend_from_slice(&status_tlv.encode());

        let ssc_bytes = SecureMessaging::ssc_to_bytes(sm.ssc);
        let mut mac_input = ssc_bytes.to_vec();
        let block_size = sm.encryptor.cipher().block_size();
        let padded_data = iso_7816_pad(&response_data, block_size);
        mac_input.extend_from_slice(&padded_data);

        let mac = sm.calculate_mac(&mac_input).unwrap();
        let mac_tlv = APDUTlv::mac(mac);
        response_data.extend_from_slice(&mac_tlv.encode());

        let response = APDUResponse::new(response_data, 0x90, 0x00);
        let result = sm.process_secure_response(&response);

        assert!(result.is_err());
    }
}
