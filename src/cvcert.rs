mod crypto;
mod errors;
#[cfg(test)]
mod tests;
mod types;

// public reexports
pub use crypto::SecurityProtocol;
pub use errors::Error;
pub use types::{AccessRight, AccessRights, AccessRole, Date};

use rasn::der::{decode as der_decode, encode as der_encode};
use rasn::types::{ObjectIdentifier as Oid, OctetString};
use types::CvcResult;

use crate::asn1::cvcert::{
    CertificateExtensions, Chat, CvCertificate as Asn1CVCertificate,
    CvCertificateBody as Asn1CVCertificateBody, EcdsaPublicKey,
};
use crate::asn1::oid::CHAT_OID;

/// A Card Verifiable Certificate according to TR-03110-3
#[derive(Debug, Clone)]
pub struct CvCertificate {
    inner: Asn1CVCertificate,
}

impl CvCertificate {
    /// Decode a CV certificate from DER format
    pub fn from_der(data: &[u8]) -> CvcResult<Self> {
        if data.is_empty() {
            return Err(Error::InvalidData("Empty certificate data".to_string()));
        }
        Ok(Self {
            inner: der_decode::<Asn1CVCertificate>(data)?,
        })
    }

    /// Decode a CV certificate from hex string
    pub fn from_hex(hex_data: impl Into<String>) -> CvcResult<Self> {
        let data = hex::decode(hex_data.into())?;

        Self::from_der(&data)
    }

    /// Returns this certificate body
    pub fn body(&self) -> CvCertificateBody {
        CvCertificateBody {
            inner: self.inner.body.clone(),
        }
    }

    /// Returns the signature of this certificate as byte slice
    pub fn signature(&self) -> &[u8] {
        self.inner.signature.as_ref()
    }

    /// Returns the certificate profile identifier
    pub fn profile_id(&self) -> &[u8] {
        self.inner.body.profile_id.as_ref()
    }

    /// Returns the certificate authority reference string
    pub fn car(&self) -> String {
        self.body().car()
    }

    /// Returns the certificate holder reference string
    pub fn chr(&self) -> String {
        self.body().chr()
    }

    /// Returns the public key of this certificate
    pub fn public_key(&self) -> EcdsaPublicKey {
        self.body().public_key()
    }

    /// Returns the certificate holder authorization template
    pub fn chat(&self) -> &Chat {
        &self.inner.body.chat
    }

    /// Get the date from which this certificate is effective
    pub fn effective_date(&self) -> CvcResult<Date> {
        self.body().effective_date()
    }

    /// Returns the expiration date of this certificate
    pub fn expiration_date(&self) -> CvcResult<Date> {
        self.body().expiration_date()
    }

    /// Check if the certificate is valid on a given date
    pub fn is_valid_on(&self, date: &Date) -> CvcResult<bool> {
        self.body().is_valid_on(date)
    }

    /// Check if this certificate is issued by the given certificate authority
    pub fn is_issued_by(&self, car: impl Into<String>) -> bool {
        self.car() == car.into()
    }

    /// Get the access role of this certificate
    ///
    /// Possible values:
    /// - **CVCA**: Root CVCA or linked CVCA
    /// - **DVOD**: Document Verifier Official Domestic
    /// - **DVNoF**: Document Verifier Non Official/Foreign
    /// - **AT**: Authentication Terminal
    /// - **Unknown**: Unknown access role
    pub fn access_role(&self) -> AccessRole {
        self.chat().access_role()
    }

    /// Returns the access rights of this certificate
    pub fn access_rights(&self) -> AccessRights {
        self.chat().access_rights()
    }

    /// Returns the extensions of this certificate
    pub fn extensions(&self) -> Option<&CertificateExtensions> {
        self.inner.body.extensions.as_ref()
    }

    /// Check if this certificate has domain parameters (CVCA characteristic)
    pub fn has_domain_parameters(&self) -> bool {
        self.body().has_domain_parameters()
    }

    /// Returns the DER representation of the certificate
    pub fn to_der(&self) -> CvcResult<Vec<u8>> {
        Ok(der_encode(&self.inner)?)
    }

    /// Returns the hex representation of the certificate
    pub fn to_hex(&self) -> CvcResult<String> {
        let der = self.to_der()?;
        Ok(hex::encode(der))
    }

    /// Check if this certificate is self-signed
    pub fn is_self_signed(&self) -> bool {
        self.body().car() == self.body().chr()
    }

    /// Validate the certificate structure according to rules defined in TR-03110-3
    ///
    /// - Self-signed CVCA certificates SHALL contain domain parameters
    /// - Linked CVCA certificates MAY contain domain parameters
    /// - DV and Terminal certificates MUST NOT contain domain parameters
    pub fn validate_structure(&self) -> CvcResult<()> {
        self.body().validate_structure()
    }

    /// Returns the raw body bytes of this certificate
    pub fn raw_body(&self) -> CvcResult<Vec<u8>> {
        Ok(der_encode(&self.inner.body)?)
    }
}

/// CV Certificate Body according to TR-03110-3
#[derive(Debug, Clone)]
pub struct CvCertificateBody {
    inner: Asn1CVCertificateBody,
}

impl CvCertificateBody {
    /// Decode a body from DER format
    pub fn from_der(data: &[u8]) -> CvcResult<Self> {
        Ok(Self {
            inner: der_decode::<Asn1CVCertificateBody>(data)?,
        })
    }

    /// Get the certificate profile identifier
    pub fn profile_id(&self) -> &[u8] {
        self.inner.profile_id.as_ref()
    }

    /// Get the certification authority reference string
    pub fn car(&self) -> String {
        String::from_utf8_lossy(self.inner.car.as_ref()).to_string()
    }

    /// Get the certificate holder reference string
    pub fn chr(&self) -> String {
        String::from_utf8_lossy(self.inner.chr.as_ref()).to_string()
    }

    /// Get the certificate public key
    pub fn public_key(&self) -> EcdsaPublicKey {
        self.inner.public_key.clone()
    }

    /// Get the certificate holder authorization template
    pub fn chat(&self) -> &Chat {
        &self.inner.chat
    }

    /// Get the certificate effective date
    pub fn effective_date(&self) -> CvcResult<Date> {
        if self.inner.effective_date.len() != 6 {
            return Err(Error::InvalidData("Invalid BCD date length".to_string()));
        }

        let mut bcd = [0u8; 6];
        bcd.copy_from_slice(&self.inner.effective_date);
        Date::from_bcd(&bcd)
    }

    /// Get the certificate expiration date
    pub fn expiration_date(&self) -> CvcResult<Date> {
        if self.inner.expiration_date.len() != 6 {
            return Err(Error::InvalidData("Invalid BCD date length".to_string()));
        }

        let mut bcd = [0u8; 6];
        bcd.copy_from_slice(&self.inner.expiration_date);
        Date::from_bcd(&bcd)
    }

    /// Check if the certificate is valid on a given date
    pub fn is_valid_on(&self, date: &Date) -> CvcResult<bool> {
        let effective = self.effective_date()?;
        let expiration = self.expiration_date()?;
        Ok(date >= &effective && date <= &expiration)
    }

    /// Check if this certificate is issued by the given certificate authority
    pub fn is_issued_by(&self, car: impl Into<String>) -> bool {
        self.car() == car.into()
    }

    /// Get the access role from the CHAT
    pub fn access_role(&self) -> AccessRole {
        self.chat().access_role()
    }

    /// Get the access rights from the CHAT
    pub fn access_rights(&self) -> AccessRights {
        self.chat().access_rights()
    }

    /// Check if this certificate has domain parameters (CVCA characteristic)
    pub fn has_domain_parameters(&self) -> bool {
        self.inner.public_key.prime.is_some()
            && self.inner.public_key.a.is_some()
            && self.inner.public_key.b.is_some()
            && self.inner.public_key.generator.is_some()
            && self.inner.public_key.order.is_some()
            && self.inner.public_key.cofactor.is_some()
    }

    /// Validate the body according to TR-03110-3 rules
    pub fn validate_structure(&self) -> CvcResult<()> {
        let role = self.access_role();
        let has_domain_params = self.has_domain_parameters();
        let is_self_signed = self.car() == self.chr();

        match role {
            AccessRole::CVCA => {
                // Self-signed CVCA certificates SHALL contain domain parameters
                if is_self_signed && !has_domain_params {
                    return Err(Error::InvalidData(
                        "Self-signed CVCA certificate must contain domain parameters".to_string(),
                    ));
                }
            }
            AccessRole::DVOD | AccessRole::DVNoF | AccessRole::AT => {
                // DV and Terminal certificates MUST NOT contain domain parameters
                if has_domain_params {
                    return Err(Error::InvalidData(format!(
                        "DV/Terminal certificate must not contain domain parameters. Role: {role:?}",
                    )));
                }
            }
            AccessRole::Unknown => {
                return Err(Error::InvalidData(
                    "Certificate has unknown access role".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Get the DER representation of the body
    pub fn to_der(&self) -> CvcResult<Vec<u8>> {
        Ok(der_encode(&self.inner)?)
    }
}

impl Chat {
    /// Create a new CHAT from a template
    pub fn new(template: [u8; 5]) -> Self {
        Self {
            oid: Oid::new_unchecked(CHAT_OID.into()),
            template: OctetString::from(template),
        }
    }

    /// Decode a CHAT from DER format
    pub fn from_der(der: impl AsRef<[u8]>) -> CvcResult<Self> {
        Ok(der_decode(der.as_ref())?)
    }

    /// Decode a CHAT from hex format
    pub fn from_hex(hex: impl AsRef<str>) -> CvcResult<Self> {
        let der = hex::decode(hex.as_ref())?;
        Self::from_der(&der)
    }

    /// Get the DER representation of the CHAT
    pub fn to_der(&self) -> Vec<u8> {
        // safe to unwrap because Chat is a valid ASN.1 type
        // we ensure that in the constructor
        der_encode(self).unwrap()
    }

    /// Get the hex representation of the DER encoded CHAT
    pub fn to_hex(&self) -> String {
        let der = self.to_der();
        hex::encode(der)
    }

    /// Get the access role of this CHAT
    pub fn access_role(&self) -> AccessRole {
        if let Some(first_byte) = self.template.first() {
            AccessRole::from_bits((first_byte >> 6) & 0b11)
        } else {
            AccessRole::Unknown
        }
    }

    /// Get the access rights of this CHAT
    pub fn access_rights(&self) -> AccessRights {
        if self.template.len() >= 5 {
            let mut template = [0u8; 5];
            template.copy_from_slice(&self.template[0..5]);
            let (_, rights) = AccessRights::from_chat_template(template);
            rights
        } else {
            AccessRights::new()
        }
    }
}

impl EcdsaPublicKey {
    /// Get the security protocol of this public key.
    ///
    /// Returns None if the security protocol is not supported.
    pub fn security_protocol(&self) -> Option<SecurityProtocol> {
        SecurityProtocol::from_oid(&self.oid.to_string()).ok()
    }

    /// Returns the uncompressed public point of this public key as byte slice
    pub fn public_point(&self) -> &[u8] {
        &self.public_point
    }
}
