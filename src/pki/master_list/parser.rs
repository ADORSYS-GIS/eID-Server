use super::{CscaInfo, CscaValidationError, MasterList};
use openssl::x509::X509;
use time::OffsetDateTime;
use tracing::warn;

/// Master List parser for DER format
pub struct MasterListParser;

impl MasterListParser {
    /// Parse Master List from binary DER format
    pub fn parse_der<T: AsRef<[u8]>>(der_data: T) -> Result<MasterList, CscaValidationError> {
        let der_data = der_data.as_ref();
        tracing::debug!(
            "Attempting to parse binary DER format master list ({} bytes)",
            der_data.len()
        );

        // Create a basic master list with current date
        let now = OffsetDateTime::now_utc();
        let mut master_list = MasterList::new(
            "Binary-DER".to_string(),
            now,
            now + time::Duration::days(365),
        );

        // Parse certificates using proper ASN.1/DER structure analysis
        let mut offset = 0;
        let mut cert_count = 0;

        while offset < der_data.len() {
            // Look for ASN.1 SEQUENCE tag (0x30) which indicates start of certificate
            if offset >= der_data.len() || der_data[offset] != 0x30 {
                offset += 1;
                continue;
            }

            // Parse ASN.1/DER length to get the exact certificate size
            match Self::parse_asn1_length(der_data, offset) {
                Ok((cert_length, header_size)) => {
                    let total_cert_size = header_size + cert_length;

                    // Ensure we don't read beyond the data boundaries
                    if offset + total_cert_size > der_data.len() {
                        offset += 1;
                        continue;
                    }

                    let cert_bytes = &der_data[offset..offset + total_cert_size];

                    // Try to parse as X.509 certificate
                    match X509::from_der(cert_bytes) {
                        Ok(x509_cert) => {
                            // Extract country code from certificate subject or use "XX" as default
                            let country_code = Self::extract_country_from_cert(&x509_cert)
                                .unwrap_or_else(|| "XX".to_string());

                            match CscaInfo::from_x509(&x509_cert, country_code) {
                                Ok(cert_info) => {
                                    let country_code = cert_info.country_code.clone();
                                    master_list.add_csca(country_code, cert_info);
                                    cert_count += 1;
                                    offset += total_cert_size;

                                    tracing::debug!(
                                        "Successfully parsed certificate #{} at offset {} (size: {} bytes)",
                                        cert_count,
                                        offset - total_cert_size,
                                        total_cert_size
                                    );
                                }
                                Err(_) => {
                                    offset += 1;
                                }
                            }
                        }
                        Err(_) => {
                            offset += 1;
                        }
                    }
                }
                Err(_) => {
                    offset += 1;
                }
            }

            // Safety check to prevent infinite loops
            if cert_count > 1000 {
                warn!("Reached maximum certificate limit (1000), stopping parsing");
                break;
            }
        }

        if cert_count == 0 {
            return Err(CscaValidationError::MasterListParse(
                "No valid certificates found in binary DER data".to_string(),
            ));
        }

        tracing::debug!(
            "Successfully parsed {} certificates from binary DER format",
            cert_count
        );
        Ok(master_list)
    }

    /// Parse ASN.1/DER length encoding
    /// Returns (content_length, total_header_size) where header includes tag and length bytes
    fn parse_asn1_length(
        data: &[u8],
        offset: usize,
    ) -> Result<(usize, usize), CscaValidationError> {
        if offset >= data.len() {
            return Err(CscaValidationError::MasterListParse(
                "Offset out of bounds for ASN.1 tag".to_string(),
            ));
        }

        // Skip the tag byte (we already verified it's 0x30)
        let length_offset = offset + 1;

        if length_offset >= data.len() {
            return Err(CscaValidationError::MasterListParse(
                "No length byte available".to_string(),
            ));
        }

        let length_byte = data[length_offset];

        if length_byte & 0x80 == 0 {
            // Short form: length is in the single byte (0-127)
            Ok((length_byte as usize, 2)) // tag + length = 2 bytes header
        } else {
            // Long form: first byte indicates how many additional bytes encode the length
            let num_length_bytes = (length_byte & 0x7F) as usize;

            if num_length_bytes == 0 {
                return Err(CscaValidationError::MasterListParse(
                    "Indefinite length not allowed in DER".to_string(),
                ));
            }

            if num_length_bytes > 4 {
                return Err(CscaValidationError::MasterListParse(
                    "Length encoding too long".to_string(),
                ));
            }

            let length_start = length_offset + 1;
            let length_end = length_start + num_length_bytes;

            if length_end > data.len() {
                return Err(CscaValidationError::MasterListParse(
                    "Not enough bytes for length encoding".to_string(),
                ));
            }

            // Decode the length from the subsequent bytes (big-endian)
            let mut content_length = 0usize;
            for i in 0..num_length_bytes {
                content_length = (content_length << 8) | (data[length_start + i] as usize);
            }

            // Total header size = tag + length indicator byte + length bytes
            let header_size = 1 + 1 + num_length_bytes;
            Ok((content_length, header_size))
        }
    }

    /// Extract country code from X.509 certificate subject
    fn extract_country_from_cert(cert: &X509) -> Option<String> {
        let subject = cert.subject_name();

        // Try to find country (C=) entry in subject
        for entry in subject.entries() {
            let nid = entry.object().nid();
            if nid == openssl::nid::Nid::COUNTRYNAME
                && let Ok(country) = entry.data().as_utf8()
            {
                return Some(country.to_string());
            }
        }

        None
    }
}
