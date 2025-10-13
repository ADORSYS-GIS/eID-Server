use x509_parser::prelude::*;

/// Represents a Certificate Revocation List
#[derive(Debug, Clone)]
pub struct CrlData {
    /// The raw CRL data in DER format
    pub der_data: Vec<u8>,
}

impl CrlData {
    /// Create a new CRL from DER data
    pub fn from_der(der_data: Vec<u8>) -> Result<Self, crate::pki::crl::errors::CrlError> {
        // Validate that we can parse it
        let _ = CertificateRevocationList::from_der(&der_data)
            .map_err(|e| crate::pki::crl::errors::CrlError::Parse(e.into()))?;

        Ok(Self { der_data })
    }

    /// Parse the CRL from DER data
    fn parse<'a>(
        &'a self,
    ) -> Result<CertificateRevocationList<'a>, crate::pki::crl::errors::CrlError> {
        let (_, crl) = CertificateRevocationList::from_der(&self.der_data)
            .map_err(|e| crate::pki::crl::errors::CrlError::Parse(e.into()))?;
        Ok(crl)
    }

    /// Get list of revoked certificate serial numbers
    pub fn get_revoked_serials(&self) -> Result<Vec<Vec<u8>>, crate::pki::crl::errors::CrlError> {
        let crl = self.parse()?;

        let serials: Vec<Vec<u8>> = crl
            .tbs_cert_list
            .revoked_certificates
            .iter()
            .map(|revoked_cert| revoked_cert.user_certificate.to_bytes_be())
            .collect();

        Ok(serials)
    }
}
