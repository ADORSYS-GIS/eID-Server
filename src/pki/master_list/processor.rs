use hex;
use log::{debug, info, warn};
use pem::Pem;
use std::io::{Cursor, Read};
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;
use zip::ZipArchive;

use super::fetcher::MasterListFetcher;
use super::validation::{
    asn1_time_to_chrono, validate_certificate_dates, validate_self_signed_certificate_signature,
};
use crate::pki::trust_store::{
    certificate_manager::CertificateManager,
    error::TrustStoreError,
    models::{CSCAPublicKeyInfo, get_common_name},
};

/// Manages updates to the trust store, including fetching and parsing Master Lists.
pub struct MasterListProcessor {
    fetcher: Box<dyn MasterListFetcher + Send + Sync>,
}

impl MasterListProcessor {
    /// Creates a new `MasterListProcessor`.
    pub fn new(fetcher: Box<dyn MasterListFetcher + Send + Sync>) -> Self {
        Self { fetcher }
    }

    /// Fetches and processes a master list, updating the certificate manager.
    pub async fn update_from_master_list(
        &self,
        manager: &mut CertificateManager,
        master_list_url: &str,
    ) -> Result<(), TrustStoreError> {
        info!("Fetching master list from: {}", master_list_url);
        let master_list_data = self.fetcher.fetch_master_list(master_list_url).await?;

        info!(
            "Received master list data ({} bytes). Processing...",
            master_list_data.len()
        );

        // Check if the data is a ZIP file
        if master_list_data.len() >= 4 && &master_list_data[0..4] == b"PK\x03\x04" {
            debug!("Detected ZIP file, extracting certificates...");
            self.process_zip_master_list(manager, master_list_data)?;
        } else {
            // Try to process as direct PEM content
            debug!("Processing as direct PEM content...");
            self.process_pem_content(manager, master_list_data)?;
        }

        Ok(())
    }

    /// Processes a ZIP file containing CSCA certificates
    fn process_zip_master_list(
        &self,
        manager: &mut CertificateManager,
        zip_data: Vec<u8>,
    ) -> Result<(), TrustStoreError> {
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).map_err(|e| {
            TrustStoreError::UpdateError(format!("Failed to open ZIP archive: {}", e))
        })?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i).map_err(|e| {
                TrustStoreError::UpdateError(format!("Failed to read ZIP entry {}: {}", i, e))
            })?;

            let filename = file.name().to_string();
            debug!("Processing file in ZIP: {}", filename);

            // Skip directories and non-certificate files
            if file.is_dir()
                || (!filename.ends_with(".pem")
                    && !filename.ends_with(".crt")
                    && !filename.ends_with(".cer"))
            {
                continue;
            }

            let mut contents = Vec::new();
            file.read_to_end(&mut contents).map_err(|e| {
                TrustStoreError::UpdateError(format!("Failed to read file {}: {}", filename, e))
            })?;

            // Process the certificate file content
            if let Err(e) = self.process_pem_content(manager, contents) {
                warn!("Failed to process certificate file {}: {}", filename, e);
                // Continue processing other files even if one fails
            }
        }

        Ok(())
    }

    /// Processes PEM certificate content
    fn process_pem_content(
        &self,
        manager: &mut CertificateManager,
        data: Vec<u8>,
    ) -> Result<(), TrustStoreError> {
        let pem_certs = String::from_utf8(data).map_err(|e| {
            TrustStoreError::UpdateError(format!("Invalid UTF-8 in certificate data: {e}"))
        })?;

        let mut rest = pem_certs.as_bytes();
        while !rest.is_empty() {
            let (remaining, x509_pem_content) = parse_x509_pem(rest).map_err(|e| {
                TrustStoreError::UpdateError(format!("Failed to parse PEM block: {}", e))
            })?;

            let cert_der = x509_pem_content.contents;
            let cert_pem = pem::encode(&Pem::new("CERTIFICATE".to_string(), cert_der.to_vec()));

            let (_, parsed_cert) = parse_x509_certificate(&cert_der)
                .map_err(|e| TrustStoreError::CertificateParsingError(e.into()))?;

            // Validate certificate dates
            let not_before = asn1_time_to_chrono(parsed_cert.tbs_certificate.validity.not_before)?;
            let not_after = asn1_time_to_chrono(parsed_cert.tbs_certificate.validity.not_after)?;

            // Check if certificate dates are valid
            if !validate_certificate_dates(not_before, not_after)? {
                rest = remaining;
                continue;
            }

            // Validate certificate signature
            if !validate_self_signed_certificate_signature(&parsed_cert)? {
                rest = remaining;
                continue;
            }

            let ski = hex::encode(
                parsed_cert
                    .tbs_certificate
                    .extensions()
                    .iter()
                    .find(|extension| {
                        extension.oid
                            == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER
                    })
                    .ok_or_else(|| {
                        TrustStoreError::UpdateError(
                            "Failed to get subject key identifier extension".to_string(),
                        )
                    })?
                    .value,
            );

            let cert_info = CSCAPublicKeyInfo {
                subject_key_identifier: ski.clone(),
                certificate_pem: cert_pem,
                not_before,
                not_after,
                issuer_common_name: get_common_name(&parsed_cert.tbs_certificate.issuer),
                subject_common_name: get_common_name(&parsed_cert.tbs_certificate.subject),
            };

            manager.add_certificate(cert_info);
            info!("Added/Updated valid certificate: {}", ski);

            rest = remaining;
        }

        Ok(())
    }
}
