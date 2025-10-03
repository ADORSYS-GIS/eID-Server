use ::time::OffsetDateTime;
use x509_parser::prelude::*;
use x509_parser::time::ASN1Time;

/// Revocation reasons as per RFC 5280
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

impl RevocationReason {
    /// Parse revocation reason from integer value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Unspecified),
            1 => Some(Self::KeyCompromise),
            2 => Some(Self::CaCompromise),
            3 => Some(Self::AffiliationChanged),
            4 => Some(Self::Superseded),
            5 => Some(Self::CessationOfOperation),
            6 => Some(Self::CertificateHold),
            8 => Some(Self::RemoveFromCrl),
            9 => Some(Self::PrivilegeWithdrawn),
            10 => Some(Self::AaCompromise),
            _ => None,
        }
    }
}

/// Information about a revoked certificate
#[derive(Debug, Clone)]
pub struct RevocationInfo {
    /// Whether the certificate is revoked
    pub revoked: bool,
    /// When the certificate was revoked
    pub revocation_date: ASN1Time,
    /// Reason for revocation (if available)
    pub reason: Option<RevocationReason>,
}

/// Represents a Certificate Revocation List entry
#[derive(Debug, Clone)]
pub struct CrlEntry {
    /// The raw CRL data in DER format
    pub der_data: Vec<u8>,
    /// When this CRL was fetched
    pub fetched_at: OffsetDateTime,
    /// The issuer of this CRL
    pub issuer: String,
    /// Distribution point URL where this CRL was fetched from
    pub distribution_point: String,
    /// CRL number for tracking (if available)
    pub crl_number: Option<Vec<u8>>,
}

impl CrlEntry {
    /// Create a new CRL entry from DER data
    pub fn from_der(
        der_data: Vec<u8>,
        distribution_point: String,
    ) -> Result<Self, crate::pki::crl::errors::CrlError> {
        use crate::pki::crl::errors::CrlError;
        use tracing::debug;

        let (_, crl) = CertificateRevocationList::from_der(&der_data)
            .map_err(|e| CrlError::Parse(e.into()))?;

        let issuer = format!("{}", crl.tbs_cert_list.issuer);

        // Extract CRL number if present (OID: 2.5.29.20)
        let crl_number = crl
            .tbs_cert_list
            .extensions()
            .iter()
            .find(|ext| ext.oid == oid_registry::OID_X509_EXT_CRL_NUMBER)
            .and_then(|ext| {
                // The CRL number is an INTEGER in the extension value
                if ext.value.len() >= 2 {
                    Some(ext.value.to_vec())
                } else {
                    None
                }
            });

        if let Some(ref num) = crl_number {
            debug!("CRL number: {:?}", hex::encode(num));
        }

        Ok(Self {
            der_data,
            fetched_at: OffsetDateTime::now_utc(),
            issuer,
            distribution_point,
            crl_number,
        })
    }

    /// Parse the CRL from DER data
    pub(crate) fn parse<'a>(
        &'a self,
    ) -> Result<CertificateRevocationList<'a>, crate::pki::crl::errors::CrlError> {
        use crate::pki::crl::errors::CrlError;

        let (_, crl) = CertificateRevocationList::from_der(&self.der_data)
            .map_err(|e| CrlError::Parse(e.into()))?;

        Ok(crl)
    }
}
