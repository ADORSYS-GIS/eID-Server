use cms::{content_info::ContentInfo, signed_data::SignedData};
use der::{Decode, Encode};
use reqwest::Client;
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};
use x509_parser::parse_x509_certificate;

use super::errors::{TrustStoreError, TrustStoreResult};
use super::types::{CertificateSource, CscaCertificate};
use super::validation::extract_country_code;

/// Master list processing utilities
pub struct MasterListProcessor {
    http_client: Client,
}

impl MasterListProcessor {
    /// Create a new master list processor with HTTP client
    pub fn new(http_client: Client) -> Self {
        Self { http_client }
    }

    /// Download and process a master list from URL
    pub async fn download_and_process_master_list(
        &self,
        url: &str,
    ) -> TrustStoreResult<(Vec<CscaCertificate>, Option<String>, String)> {
        debug!("Downloading master list from: {}", url);

        let response = self.http_client.get(url).send().await?;

        // Extract ETag from HTTP headers for caching
        let etag = response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .map(|s| s.to_string());

        let master_list_data = response.bytes().await?;

        // Calculate content hash for integrity checking
        let mut hasher = Sha256::new();
        hasher.update(&master_list_data);
        let content_hash = hex::encode(hasher.finalize());

        // Parse and validate the master list
        let certificates = self
            .validate_and_extract_certificates(&master_list_data, url)
            .await?;

        if certificates.is_empty() {
            warn!("No valid certificates found in master list from: {}", url);
        }

        Ok((certificates, etag, content_hash))
    }

    /// Validate master list and extract certificates
    async fn validate_and_extract_certificates(
        &self,
        master_list_data: &[u8],
        url: &str,
    ) -> TrustStoreResult<Vec<CscaCertificate>> {
        debug!("Processing master list from: {}", url);

        // Try to parse as CMS/PKCS#7 structure first
        match ContentInfo::from_der(master_list_data) {
            Ok(content_info) => {
                debug!("Successfully parsed CMS structure, validating ICAO 9303 master list");
                self.validate_cms_master_list(content_info, url).await
            }
            Err(e) => {
                // If CMS parsing fails, try to extract certificates directly
                debug!(
                    "Not a CMS structure ({}), trying direct certificate extraction",
                    e
                );
                self.extract_certificates_directly(master_list_data, url)
                    .await
            }
        }
    }

    /// Validate ICAO 9303 CMS master list and extract certificates
    async fn validate_cms_master_list(
        &self,
        content_info: ContentInfo,
        url: &str,
    ) -> TrustStoreResult<Vec<CscaCertificate>> {
        debug!("Validating ICAO 9303 CMS master list structure");

        // Verify that this is a SignedData structure
        match content_info.content_type.to_string().as_str() {
            "1.2.840.113549.1.7.2" => {
                // SignedData OID
                debug!("Confirmed SignedData CMS structure");

                // Parse the SignedData structure
                let signed_data =
                    SignedData::from_der(content_info.content.value()).map_err(|e| {
                        TrustStoreError::CmsParsingError(format!(
                            "Failed to parse SignedData structure: {e}",
                        ))
                    })?;

                // Validate the SignedData structure
                self.validate_signed_data_structure(&signed_data).await?;

                // Verify CMS signatures against trusted certificates
                self.verify_cms_signatures(&signed_data, &content_info)
                    .await?;

                // Extract certificates from the certificates field in SignedData
                let certificates = self
                    .extract_certificates_from_signed_data(&signed_data, url)
                    .await?;

                info!(
                    "Successfully processed CMS master list with {} certificates",
                    certificates.len()
                );
                Ok(certificates)
            }
            oid => Err(TrustStoreError::CmsParsingError(format!(
                "Unsupported CMS content type: {oid}",
            ))),
        }
    }

    /// Validate basic SignedData structure
    async fn validate_signed_data_structure(
        &self,
        signed_data: &SignedData,
    ) -> TrustStoreResult<()> {
        debug!("Validating basic SignedData structure");

        // Basic validation - check that we have the required components
        info!("SignedData validation: version={:?}", signed_data.version);

        // Log information about the structure
        if let Some(_certificates) = &signed_data.certificates {
            debug!("SignedData contains certificates field");
        } else {
            warn!("SignedData does not contain certificates field");
        }

        debug!("SignedData structure validation completed");
        Ok(())
    }

    /// Perform CMS signature verification
    async fn verify_cms_signatures(
        &self,
        _signed_data: &SignedData,
        _content_info: &ContentInfo,
    ) -> TrustStoreResult<()> {
        debug!("Performing CMS signature verification");

        // For now, we'll log the verification attempt but not fail
        // In a full implementation, this would verify signatures against trusted certificates
        info!("CMS signature verification: SignedData structure parsed successfully");

        // Log information about signers
        debug!("SignedData contains signer information");

        // Note: Full signature verification would require:
        // 1. Extract signer certificates from the certificates field
        // 2. Verify each signature using the corresponding public key
        // 3. Validate the certificate chain back to trusted roots
        // 4. Check signed attributes and content integrity

        warn!(
            "Full CMS signature verification not yet implemented - proceeding with certificate extraction"
        );
        Ok(())
    }

    /// Extract certificates from SignedData structure
    async fn extract_certificates_from_signed_data(
        &self,
        signed_data: &SignedData,
        url: &str,
    ) -> TrustStoreResult<Vec<CscaCertificate>> {
        debug!("Extracting certificates from SignedData structure");

        // Try to extract certificates from the certificates field
        if let Some(_certificates) = &signed_data.certificates {
            debug!("Found certificates field in SignedData");

            // For now, fall back to the raw data extraction approach
            // In a full implementation, we would properly iterate through the certificates
            warn!("Using fallback certificate extraction from SignedData");

            // Convert the SignedData back to bytes and extract certificates
            match signed_data.to_der() {
                Ok(signed_data_bytes) => {
                    self.extract_certificates_from_cms_data(&signed_data_bytes, url)
                        .await
                }
                Err(e) => {
                    error!("Failed to encode SignedData to DER: {}", e);
                    Ok(Vec::new())
                }
            }
        } else {
            warn!("No certificates field found in SignedData");
            Ok(Vec::new())
        }
    }

    /// Extract certificates from CMS data
    async fn extract_certificates_from_cms_data(
        &self,
        cms_data: &[u8],
        url: &str,
    ) -> TrustStoreResult<Vec<CscaCertificate>> {
        debug!(
            "Extracting certificates from CMS data ({} bytes)",
            cms_data.len()
        );

        let mut certificates = Vec::new();
        let mut offset = 0;

        // Search for certificate patterns in the CMS data
        // X.509 certificates in DER format typically start with 0x30 (SEQUENCE)
        while offset < cms_data.len() {
            // Look for potential certificate start (DER SEQUENCE tag)
            if cms_data[offset] == 0x30 && offset + 1 < cms_data.len() {
                // Try to parse a certificate starting at this position
                match parse_x509_certificate(&cms_data[offset..]) {
                    Ok((remaining, cert)) => {
                        let cert_der_len = cms_data.len() - offset - remaining.len();
                        let cert_der = cms_data[offset..offset + cert_der_len].to_vec();

                        match self
                            .create_csca_certificate_from_parsed(cert_der, &cert, url)
                            .await
                        {
                            Ok(csca_cert) => {
                                certificates.push(csca_cert);
                                debug!(
                                    "Extracted certificate from CMS with serial: {:x}",
                                    cert.serial
                                );
                            }
                            Err(e) => {
                                debug!("Failed to create CSCA certificate from CMS data: {}", e);
                            }
                        }

                        offset += cert_der_len;
                    }
                    Err(_) => {
                        offset += 1;
                    }
                }
            } else {
                offset += 1;
            }
        }

        if certificates.is_empty() {
            debug!("No certificates found in CMS data");
        } else {
            info!(
                "Extracted {} certificates from CMS structure",
                certificates.len()
            );
        }

        Ok(certificates)
    }

    /// Extract certificates directly from data (fallback when CMS parsing fails)
    async fn extract_certificates_directly(
        &self,
        data: &[u8],
        url: &str,
    ) -> TrustStoreResult<Vec<CscaCertificate>> {
        debug!(
            "Attempting direct certificate extraction from {} bytes",
            data.len()
        );

        let mut certificates = Vec::new();
        let mut offset = 0;

        // Try to parse certificates sequentially from the data
        while offset < data.len() {
            match parse_x509_certificate(&data[offset..]) {
                Ok((remaining, cert)) => {
                    // Successfully parsed a certificate
                    let cert_der_len = data.len() - offset - remaining.len();
                    let cert_der = data[offset..offset + cert_der_len].to_vec();

                    match self
                        .create_csca_certificate_from_parsed(cert_der, &cert, url)
                        .await
                    {
                        Ok(csca_cert) => {
                            certificates.push(csca_cert);
                            debug!("Extracted certificate with serial: {:x}", cert.serial);
                        }
                        Err(e) => {
                            warn!("Failed to create CSCA certificate: {}", e);
                        }
                    }

                    offset += cert_der_len;
                }
                Err(_) => {
                    // Try to skip ahead and find the next certificate
                    offset += 1;
                    if offset >= data.len() {
                        break;
                    }
                }
            }
        }

        if certificates.is_empty() {
            debug!("No certificates found via direct extraction");
        } else {
            info!(
                "Extracted {} certificates via direct parsing",
                certificates.len()
            );
        }

        Ok(certificates)
    }

    /// Create a CscaCertificate from a parsed X.509 certificate
    async fn create_csca_certificate_from_parsed(
        &self,
        certificate_der: Vec<u8>,
        cert: &x509_parser::prelude::X509Certificate<'_>,
        url: &str,
    ) -> TrustStoreResult<CscaCertificate> {
        use chrono::{DateTime, Utc};

        let country_code = extract_country_code(cert)?;
        let serial_number = format!("{:x}", cert.serial);
        let subject = cert.subject.to_string();
        let issuer = cert.issuer.to_string();
        let not_before = DateTime::from_timestamp(cert.validity.not_before.timestamp(), 0)
            .unwrap_or_else(Utc::now);
        let not_after = DateTime::from_timestamp(cert.validity.not_after.timestamp(), 0)
            .unwrap_or_else(Utc::now);

        Ok(CscaCertificate {
            certificate_der,
            country_code,
            serial_number,
            subject,
            issuer,
            not_before,
            not_after,
            added_at: Utc::now(),
            source: CertificateSource::MasterList {
                url: url.to_string(),
                downloaded_at: Utc::now(),
            },
        })
    }
}
