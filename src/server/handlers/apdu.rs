use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use cmac::{Cmac, CmacCore, Mac};
use der::{Decode, Encode, Tag};
use digest::core_api::CoreWrapper;
use digest::{Digest, FixedOutput};
use elliptic_curve::{
    CurveArithmetic, PublicKey as EcPublicKey, SecretKey as EcSecretKey,
    ecdh::diffie_hellman,
    sec1::{FromEncodedPoint, ToEncodedPoint},
};
use hmac::{Hmac, Mac as HmacMac};
use openssl::bn::BigNumContext;
use openssl::symm::{Crypter, Mode};
use openssl::{
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    error::ErrorStack,
    hash::{MessageDigest, hash},
    nid::Nid,
    pkey::{PKey, Private, Public},
    sign::Signer,
    symm::{Cipher, decrypt, encrypt},
};
use p256::{NistP256, PublicKey as P256PublicKey, SecretKey as P256SecretKey};
use sha1::Sha1;
use sha2::Sha256;
use std::collections::HashMap;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

type Result<T> = std::result::Result<T, ApduError>;

#[derive(Error, Debug)]
pub enum ApduError {
    #[error("Invalid APDU format")]
    InvalidFormat,
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    #[error("OpenSSL error: {0}")]
    OpenSsl(#[from] ErrorStack),
    #[error("ASN.1 encoding error: {0}")]
    Asn1(#[from] der::Error),
    #[error("Invalid secure messaging objects")]
    InvalidSmObjects,
    #[error("MAC verification failed")]
    MacVerificationFailed,
    #[error("Encryption/Decryption failed")]
    CryptographicFailure,
}

// Supported elliptic curves
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EllipticCurve {
    /// NIST P-256 (secp256r1)
    P256,
    /// Brainpool P-256r1
    BrainpoolP256r1,
    /// Brainpool P-384r1
    BrainpoolP384r1,
}

impl EllipticCurve {
    pub fn coordinate_size(&self) -> usize {
        match self {
            Self::P256 | Self::BrainpoolP256r1 => 32,
            Self::BrainpoolP384r1 => 48,
        }
    }

    pub fn compressed_point_size(&self) -> usize {
        self.coordinate_size() + 1 // +1 for compression prefix
    }

    pub fn uncompressed_point_size(&self) -> usize {
        2 * self.coordinate_size() + 1 // +1 for uncompressed prefix
    }

    pub fn scalar_size(&self) -> usize {
        self.coordinate_size()
    }

    pub fn to_nid(&self) -> Nid {
        match self {
            Self::P256 => Nid::X9_62_PRIME256V1,
            Self::BrainpoolP256r1 => Nid::BRAINPOOL_P256R1,
            Self::BrainpoolP384r1 => Nid::BRAINPOOL_P384R1,
        }
    }

    pub fn from_key_sizes(private_key_len: usize, public_key_len: usize) -> Option<Self> {
        match (private_key_len, public_key_len) {
            (32, 33) | (32, 65) => Some(Self::BrainpoolP256r1),
            (48, 49) | (48, 97) => Some(Self::BrainpoolP384r1),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Ins {
    Unknown = 0x00,
    Deactivate = 0x04,
    Verify = 0x20,
    MseSet = 0x22,
    Activate = 0x44,
    ExternalAuthenticate = 0x82,
    GetChallenge = 0x84,
    GeneralAuthenticate = 0x86,
    PsoVerify = 0x2A,
    PsoCompute = 0x2B,
    ResetRetryCounter = 0x2C,
    Select = 0xA4,
    ReadBinary = 0xB0,
    GetResponse = 0xC0,
    UpdateBinary = 0xD6,
}

impl From<u8> for Ins {
    fn from(value: u8) -> Self {
        match value {
            0x04 => Self::Deactivate,
            0x20 => Self::Verify,
            0x22 => Self::MseSet,
            0x44 => Self::Activate,
            0x82 => Self::ExternalAuthenticate,
            0x84 => Self::GetChallenge,
            0x86 => Self::GeneralAuthenticate,
            0x2A => Self::PsoVerify,
            0x2B => Self::PsoCompute,
            0x2C => Self::ResetRetryCounter,
            0xA4 => Self::Select,
            0xB0 => Self::ReadBinary,
            0xC0 => Self::GetResponse,
            0xD6 => Self::UpdateBinary,
            _ => Self::Unknown,
        }
    }
}

// APDU Parameters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Param {
    Implicit = 0x00,
    Change = 0x02,
    Unblock = 0x03,
    ChipAuthentication = 0x41,
    TerminalAuthentication = 0x81,
    AuthenticationTemplate = 0xA4,
    DigitalSignatureTemplate = 0xB6,
    SelfDescriptive = 0xBE,
    Pace = 0xC1,
}

// Status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCode(pub u16);

impl StatusCode {
    pub const SUCCESS: StatusCode = StatusCode(0x9000);
    pub const INVALID_SM_OBJECTS: StatusCode = StatusCode(0x6988);
    pub const SECURITY_STATUS_NOT_SATISFIED: StatusCode = StatusCode(0x6982);
    pub const WRONG_LENGTH: StatusCode = StatusCode(0x6700);
    pub const COMMAND_NOT_ALLOWED: StatusCode = StatusCode(0x6986);
}

// APDU Command structure
#[derive(Debug, Clone)]
pub struct CommandApdu {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: Vec<u8>,
    le: Option<u32>,
}

impl CommandApdu {
    const SHORT_MAX_LC: usize = 0xFF;
    const SHORT_MAX_LE: u16 = 0x0100;
    const EXTENDED_MAX_LC: usize = 0x00FFFF;
    const EXTENDED_MAX_LE: u32 = 0x010000;

    pub fn new(ins: Ins, p1: u8, p2: u8, data: Vec<u8>, le: Option<u32>) -> Self {
        Self {
            cla: 0x00,
            ins: ins as u8,
            p1,
            p2,
            data,
            le,
        }
    }

    pub fn from_components(header: [u8; 4], data: impl Into<Vec<u8>>, le: Option<u32>) -> Self {
        Self {
            cla: header[0],
            ins: header[1],
            p1: header[2],
            p2: header[3],
            data: data.into(),
            le,
        }
    }

    pub fn enable_command_chaining(&mut self) {
        self.cla |= 0x10;
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

    pub fn is_extended_length(&self) -> bool {
        self.data.len() > Self::SHORT_MAX_LC || self.le.unwrap_or(0) > Self::SHORT_MAX_LE.into()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.cla, self.ins, self.p1, self.p2];

        if self.is_extended_length() {
            bytes.push(0x00);
        }

        if !self.data.is_empty() {
            if self.is_extended_length() {
                bytes.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
            } else {
                bytes.push(self.data.len() as u8);
            }
            bytes.extend_from_slice(&self.data);
        }

        if let Some(le) = self.le {
            if le > 0 {
                if self.is_extended_length() {
                    bytes.extend_from_slice(&le.to_be_bytes());
                } else {
                    bytes.push(if le == 256 { 0x00 } else { le as u8 });
                }
            }
        }

        bytes
    }
}

// APDU Response structure
#[derive(Debug, Clone)]
pub struct ResponseApdu {
    data: Vec<u8>,
    sw1: u8,
    sw2: u8,
}

impl ResponseApdu {
    pub fn new(data: Vec<u8>, sw1: u8, sw2: u8) -> Self {
        Self { data, sw1, sw2 }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 {
            return Err(ApduError::InvalidFormat);
        }

        let len = bytes.len();
        let sw1 = bytes[len - 2];
        let sw2 = bytes[len - 1];
        let data = bytes[..len - 2].to_vec();

        Ok(Self { data, sw1, sw2 })
    }

    pub fn get_status_code(&self) -> StatusCode {
        StatusCode(((self.sw1 as u16) << 8) | (self.sw2 as u16))
    }

    pub fn get_data(&self) -> &[u8] {
        &self.data
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.data.clone();
        bytes.push(self.sw1);
        bytes.push(self.sw2);
        bytes
    }
}

// Secure Messaging Keys
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct SecureMessagingKeys {
    pub k_enc: [u8; 16],
    pub k_mac: [u8; 16],
}

impl SecureMessagingKeys {
    pub fn derive_from_shared_secret(shared_secret: &[u8], nonce: &[u8]) -> Result<Self> {
        // Key derivation as per TR-03110-3
        let mut k_enc = [0u8; 16];
        let mut k_mac = [0u8; 16];

        // Derive encryption key (counter = 1)
        let enc_input = [shared_secret, nonce, &[0x00, 0x00, 0x00, 0x01]].concat();
        let enc_hash = Sha1::digest(&enc_input);
        k_enc.copy_from_slice(&enc_hash[..16]);

        // Derive MAC key (counter = 2)
        let mac_input = [shared_secret, nonce, &[0x00, 0x00, 0x00, 0x02]].concat();
        let mac_hash = Sha1::digest(&mac_input);
        k_mac.copy_from_slice(&mac_hash[..16]);

        Ok(Self { k_enc, k_mac })
    }
}

// Secure Messaging Context
#[derive(Debug)]
pub struct SecureMessaging {
    keys: SecureMessagingKeys,
    ssc: u32,
}

impl SecureMessaging {
    pub fn new(keys: SecureMessagingKeys) -> Self {
        Self {
            keys,
            ssc: 0,
        }
    }

    fn iso7816_pad_vec(mut v: Vec<u8>, block: usize) -> Vec<u8> {
        let pad_len = block - (v.len() % block);
        v.push(0x80);
        v.extend(vec![0x00; pad_len - 1]);
        v
    }

    fn ssc_to_be_bytes(counter: u32) -> [u8; 16] {
        let mut ssc = [0u8; 16];
        let be = counter.to_be_bytes();
        ssc[12..].copy_from_slice(&be);
        ssc
    }

    // AES-CBC encrypt a single-block SSC with IV = zeros to derive the "encrypted IV"
    // This matches mCipher.setIv(zeros); mCipher.encrypt(getSendSequenceCounter());
    fn derive_encrypted_iv(kenc: &[u8], ssc_block: &[u8; 16]) -> Result<Vec<u8>> {
        let zero_iv = vec![0u8; 16];
        Self::aes_cbc_encrypt(kenc, &zero_iv, ssc_block)
    }

    /// AES-CBC encrypt data with IV
    fn aes_cbc_encrypt(kenc: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            return Ok(Vec::new());
        }

        let cipher = match kenc.len() {
            16 => Cipher::aes_128_cbc(),
            24 => Cipher::aes_192_cbc(),
            32 => Cipher::aes_256_cbc(),
            _ => return Err(ApduError::Crypto("unsupported key length".to_string())),
        };
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, kenc, Some(iv))?;
        crypter.pad(false);
        let mut out = vec![0u8; plaintext.len() + cipher.block_size()];
        let count = crypter.update(plaintext, &mut out)?;
        let rest = crypter.finalize(&mut out[count..])?;
        out.truncate(count + rest);
        Ok(out)
    }

    fn aes_cbc_decrypt(kenc: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.is_empty() {
            return Ok(Vec::new());
        }

        let cipher = match kenc.len() {
            16 => Cipher::aes_128_cbc(),
            24 => Cipher::aes_192_cbc(),
            32 => Cipher::aes_256_cbc(),
            _ => return Err(ApduError::Crypto("unsupported key length".to_string())),
        };
        let mut decrypter = Crypter::new(cipher, Mode::Decrypt, kenc, Some(iv))?;
        decrypter.pad(false);
        let mut out = vec![0u8; ciphertext.len() + cipher.block_size()];
        let count = decrypter.update(ciphertext, &mut out)?;
        let rest = decrypter.finalize(&mut out[count..])?;
        out.truncate(count + rest);
        Ok(out)
    }

    // Encrypt data using AES-128 CBC with zero IV (as per TR-03110-3)
    fn encrypt_data(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        // Pad data to AES block size
        let mut padded_data = data.to_vec();
        padded_data = Self::iso7816_pad_vec(padded_data, 16);

        let ciphertext = Self::aes_cbc_encrypt(&self.keys.k_enc, iv, &padded_data)
            .map_err(|e| ApduError::Crypto(format!("Encryption failed: {e}")))?;

        Ok(ciphertext)
    }

    // Decrypt data using AES-128 CBC with zero IV
    fn decrypt_data(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() || data.len() % 16 != 0 {
            return Err(ApduError::CryptographicFailure);
        }

        let mut decrypted = Self::aes_cbc_decrypt(&self.keys.k_enc, iv, data)
            .map_err(|e| ApduError::Crypto(format!("Decryption failed: {e}")))?;

        // Remove padding
        if let Some(pad_start) = decrypted.iter().rposition(|&b| b == 0x80) {
            decrypted.truncate(pad_start);
        }

        Ok(decrypted)
    }

    // Calculate CMAC
    pub fn calculate_mac(&self, data: &[u8]) -> Result<[u8; 8]> {
        let mut mac = <CoreWrapper<CmacCore<Aes128>> as KeyInit>::new_from_slice(&self.keys.k_mac)
            .map_err(|e| ApduError::Crypto(e.to_string()))?;
        mac.update(data);
        let result = mac.finalize().into_bytes();

        let mut mac_bytes = [0u8; 8];
        mac_bytes.copy_from_slice(&result[..8]);
        Ok(mac_bytes)
    }

    // Create secure command APDU
    pub fn create_secure_command(&mut self, command: &CommandApdu) -> Result<CommandApdu> {
        self.ssc += 1;
        let ssc_bytes = Self::ssc_to_be_bytes(self.ssc);
        let iv = Self::derive_encrypted_iv(&self.keys.k_enc, &ssc_bytes)?;
        let header = [command.cla | 0x0C, command.ins, command.p1, command.p2];

        // Encrypt command data if present
        let mut formatted_encrypted_data = Vec::new();
        if !command.data.is_empty() {
            let encrypted_data = self.encrypt_data(&command.data, &iv)?;
            let mut v = vec![0x01];
            v.extend_from_slice(&encrypted_data);
            formatted_encrypted_data.push(0x87);
            formatted_encrypted_data.push((v.len()) as u8);
            formatted_encrypted_data.extend_from_slice(&v);
        }

        // Add expected length if present
        let mut secured_le = Vec::new();
        if let Some(le) = command.le {
            if le > 0 {
                let le_bytes = if le <= 255 {
                    vec![le as u8]
                } else {
                    le.to_be_bytes().to_vec()
                };
                secured_le.push(0x97);
                secured_le.push(le_bytes.len() as u8);
                secured_le.extend_from_slice(&le_bytes);
            }
        }

        let secure_header = header;

        // dataToMac = padToBlock(securedHeader) || formattedEncryptedData || securedLe
        let mut data_to_mac = Vec::new();
        let mut padded_header = secure_header.to_vec();
        padded_header = Self::iso7816_pad_vec(padded_header, 16);
        data_to_mac.extend_from_slice(&padded_header);
        data_to_mac.extend_from_slice(&formatted_encrypted_data);
        data_to_mac.extend_from_slice(&secured_le);

        // If any formattedEncryptedData or securedLe present -> pad again
        if !formatted_encrypted_data.is_empty() || !secured_le.is_empty() {
            data_to_mac = Self::iso7816_pad_vec(data_to_mac, 16);
        }

        // Prepend SSC (16 bytes) to MAC input as in AusweisApp2
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&ssc_bytes);
        mac_input.extend_from_slice(&data_to_mac);

        let mac = self.calculate_mac(&mac_input)?;

        let mut secure_data = formatted_encrypted_data;
        secure_data.extend_from_slice(&secured_le);
        secure_data.push(0x8E);
        secure_data.push(0x08);
        secure_data.extend_from_slice(&mac);

        let apdu = CommandApdu::from_components(secure_header, &*secure_data, command.le);

        let new_le = if apdu.is_extended_length() {
            CommandApdu::EXTENDED_MAX_LE
        } else {
            CommandApdu::SHORT_MAX_LE.into()
        };

        let apdu = CommandApdu::from_components(secure_header, secure_data, Some(new_le));

        Ok(apdu)
    }

    // Process secure response APDU
    pub fn process_secure_response(&mut self, response: &ResponseApdu) -> Result<ResponseApdu> {
        if response.data.is_empty() {
            return Err(ApduError::InvalidSmObjects);
        }

        let mut data = response.data.as_slice();
        let mut decrypted_data = Vec::new();
        let mut status_bytes = None;
        let mut received_mac = None;

        self.ssc += 1;
        let ssc_bytes = Self::ssc_to_be_bytes(self.ssc);

        // Parse TLV objects
        while !data.is_empty() {
            let tag = data[0];
            let length = data[1];
            let value = &data[2..2 + length as usize];

            match tag {
                0x87 => {
                    // Encrypted data
                    let iv = Self::derive_encrypted_iv(&self.keys.k_enc, &ssc_bytes)?;
                    if value.is_empty() || value[0] != 0x01 {
                        return Err(ApduError::InvalidSmObjects);
                    }
                    decrypted_data = self.decrypt_data(&value[1..], &iv)?;
                }
                0x99 => {
                    // Processing status
                    if value.len() != 2 {
                        return Err(ApduError::InvalidSmObjects);
                    }
                    status_bytes = Some([value[0], value[1]]);
                }
                0x8E => {
                    // MAC
                    if value.len() != 8 {
                        return Err(ApduError::InvalidSmObjects);
                    }
                    let mut mac = [0u8; 8];
                    mac.copy_from_slice(value);
                    received_mac = Some(mac);
                }
                _ => {
                    // Unknown tag, skip
                }
            }

            data = &data[2 + length as usize..];
        }

        // Verify MAC
        if let Some(mac) = received_mac {
            let mut mac_input = ssc_bytes.to_vec();
            mac_input.extend_from_slice(&response.data[..response.data.len() - 10]);

            let calculated_mac = self.calculate_mac(&mac_input)?;
            if mac != calculated_mac {
                return Err(ApduError::MacVerificationFailed);
            }
        } else {
            return Err(ApduError::InvalidSmObjects);
        }

        // Use status from secure messaging or original response
        let (sw1, sw2) = if let Some(status) = status_bytes {
            (status[0], status[1])
        } else {
            (response.sw1, response.sw2)
        };

        Ok(ResponseApdu::new(decrypted_data, sw1, sw2))
    }
}

// Shared Secret Computation with curve support
pub struct SharedSecretComputer;

impl SharedSecretComputer {
    // Auto-detect curve from key size and compute shared secret
    pub fn compute_shared_secret(
        private_key: EcKey<Private>,
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>> {
        // Determine curve based on key sizes
        let curve = match peer_public_key.len() {
            33 | 65 => EllipticCurve::BrainpoolP256r1,
            49 | 96 => EllipticCurve::BrainpoolP384r1,
            _ => return Err(ApduError::Crypto("Unsupported key sizes".to_string())),
        };

        Self::compute_shared_secret_with_curve(curve, private_key, peer_public_key)
    }

    // Compute ECDH shared secret with explicit curve specification
    pub fn compute_shared_secret_with_curve(
        curve: EllipticCurve,
        private_key: EcKey<Private>,
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>> {
        // Create the EC group for the specified curve
        let group = EcGroup::from_curve_name(curve.to_nid())?;

        // Create private key
        let private_pkey = PKey::from_ec_key(private_key)?;

        // Parse public key
        let peer_public_key = Self::parse_public_key(&group, peer_public_key)?;
        let peer_pkey = PKey::from_ec_key(peer_public_key)?;

        // Perform ECDH
        let mut deriver = Deriver::new(&private_pkey)?;
        deriver.set_peer(&peer_pkey)?;
        let shared_secret = deriver.derive_to_vec()?;

        let x_coord = shared_secret[..32].to_vec();

        Ok(x_coord)
    }

    // Parse public key from various formats
    fn parse_public_key(group: &EcGroup, key_bytes: &[u8]) -> Result<EcKey<Public>> {
        let mut context = BigNumContext::new()?;
        let point = if key_bytes.len() == 33 || key_bytes.len() == 49 {
            // Compressed format (0x02 or 0x03 prefix)
            if key_bytes[0] == 0x02 || key_bytes[0] == 0x03 {
                EcPoint::from_bytes(group, key_bytes, &mut context)?
            } else {
                return Err(ApduError::Crypto(
                    "Invalid compressed public key format".to_string(),
                ));
            }
        } else if key_bytes.len() == 65 || key_bytes.len() == 97 {
            // Uncompressed format (0x04 prefix)
            if key_bytes[0] == 0x04 {
                EcPoint::from_bytes(group, key_bytes, &mut context)?
            } else {
                return Err(ApduError::Crypto(
                    "Invalid uncompressed public key format".to_string(),
                ));
            }
        } else {
            return Err(ApduError::Crypto(
                "Unsupported public key length".to_string(),
            ));
        };

        EcKey::from_public_key(group, &point).map_err(|e| ApduError::OpenSsl(e))
    }

    // Derive secure messaging keys from shared secret and nonce
    pub fn derive_keys(shared_secret: &[u8], nonce: &[u8]) -> Result<SecureMessagingKeys> {
        SecureMessagingKeys::derive_from_shared_secret(shared_secret, nonce)
    }
}

// Data Group definitions
#[derive(Debug, Clone, Copy)]
pub enum DataGroup {
    DG1 = 0x01,  // Document Type
    DG2 = 0x02,  // Issuing State, Region and Municipality
    DG3 = 0x03,  // Date of Expiry
    DG4 = 0x04,  // Given Names
    DG5 = 0x05,  // Family Names
    DG6 = 0x06,  // Nom de Plume
    DG7 = 0x07,  // Academic Title
    DG8 = 0x08,  // Date of Birth
    DG9 = 0x09,  // Place of Birth
    DG10 = 0x0A, // Nationality
    DG11 = 0x0B, // Sex
    DG12 = 0x0C, // Optional Data
    DG13 = 0x0D, // Birth Name
    DG14 = 0x0E, // Written Signature
    DG15 = 0x0F, // Date of Issuance
    DG16 = 0x10, // Reserved for Future Use
    DG17 = 0x11, // Normal Place of Residence
    DG18 = 0x12, // Municipality ID
    DG19 = 0x13, // Residence Permit I
    DG20 = 0x14, // Residence Permit II
    DG21 = 0x15, // Phone Number
    DG22 = 0x16, // Email Address
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

// eID APDU Commands
pub struct EidCommands;

impl EidCommands {
    // Select file by FID
    pub fn select_file(fid: u16) -> CommandApdu {
        let fid_bytes = fid.to_be_bytes();
        CommandApdu::new(
            Ins::Select,
            0x02, // Select by FID
            0x0C, // Return FCP template
            fid_bytes.to_vec(),
            Some(0),
        )
    }

    // Read binary data
    pub fn read_binary(offset: u16, length: u8) -> CommandApdu {
        let p1 = ((offset >> 8) & 0xFF) as u8;
        let p2 = (offset & 0xFF) as u8;

        CommandApdu::new(
            Ins::ReadBinary,
            p1,
            p2,
            Vec::new(),
            Some(length as u32),
        )
    }

    // Read data group
    pub fn read_data_group(data_group: DataGroup) -> Vec<CommandApdu> {
        vec![
            Self::select_file(data_group.fid()),
            // Self::read_binary(0, 0),
        ]
    }
}
