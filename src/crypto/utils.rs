use crate::crypto::errors::CryptoResult;
use rand::{TryRngCore, rngs::OsRng};

/// Generate cryptographically secure random bytes
pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut buf = vec![0u8; length];
    OsRng.try_fill_bytes(&mut buf).unwrap();
    buf
}

/// Convert hex string to bytes with validation
pub fn hex_to_bytes(hex_str: &str) -> CryptoResult<Vec<u8>> {
    // Remove common prefixes and whitespace
    let cleaned = hex_str
        .trim()
        .strip_prefix("0x")
        .or_else(|| hex_str.trim().strip_prefix("0X"))
        .unwrap_or(hex_str.trim());

    Ok(hex::decode(cleaned)?)
}

/// ISO/IEC 7816-4 padding
pub fn iso_7816_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let mut padded = data.to_vec();
    let pad_len = block_size - (padded.len() % block_size);
    padded.push(0x80);
    padded.resize(padded.len() + pad_len - 1, 0x00);
    padded
}

/// Remove ISO/IEC 7816-4 padding
pub fn iso_7816_unpad(data: &[u8]) -> Vec<u8> {
    let mut unpadded = data.to_vec();
    if let Some(pad_start) = unpadded.iter().rposition(|&b| b == 0x80) {
        unpadded.truncate(pad_start);
    }
    unpadded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_bytes() {
        assert_eq!(hex_to_bytes("0x1234").unwrap(), vec![0x12, 0x34]);
        assert_eq!(hex_to_bytes(" 0X1234 ").unwrap(), vec![0x12, 0x34]);
        assert_eq!(hex_to_bytes("1234").unwrap(), vec![0x12, 0x34]);
    }

    #[test]
    fn test_iso_7816_pad() {
        assert_eq!(
            iso_7816_pad(&[0x12, 0x34], 8),
            vec![0x12, 0x34, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(iso_7816_pad(&[0x12, 0x34], 2), vec![0x12, 0x34, 0x80, 0x00]);
    }

    #[test]
    fn test_iso_7816_unpad() {
        assert_eq!(
            iso_7816_unpad(&[0x12, 0x34, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00]),
            vec![0x12, 0x34]
        );
        assert_eq!(iso_7816_unpad(&[0x12, 0x34]), vec![0x12, 0x34]);
    }
}
