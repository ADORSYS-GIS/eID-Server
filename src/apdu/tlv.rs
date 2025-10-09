use super::{Error, Result};

/// TLV structures used in APDU messages
#[derive(Debug, Clone)]
pub struct APDUTlv {
    pub tag: u8,
    pub data: Vec<u8>,
}

impl APDUTlv {
    pub fn new(tag: u8, data: impl Into<Vec<u8>>) -> Self {
        Self {
            tag,
            data: data.into(),
        }
    }

    pub fn encrypted_data(data: impl Into<Vec<u8>>) -> Self {
        let mut prefixed_data = vec![0x01];
        prefixed_data.extend_from_slice(&data.into());
        Self::new(0x87, prefixed_data)
    }

    pub fn processing_status(sw1: u8, sw2: u8) -> Self {
        Self::new(0x99, vec![sw1, sw2])
    }

    pub fn mac(mac_bytes: [u8; 8]) -> Self {
        Self::new(0x8E, mac_bytes.to_vec())
    }

    pub fn expected_length(le: u16) -> Self {
        let le_bytes = if le == 0 {
            vec![0x00]
        } else if le > 0x100 {
            le.to_be_bytes().to_vec()
        } else {
            vec![if le == 0x100 { 0x00 } else { le as u8 }]
        };
        Self::new(0x97, le_bytes)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut result = vec![self.tag];

        let len = self.data.len();
        if len < 0x80 {
            result.push(len as u8);
        } else {
            let len_bytes = if len <= 0xFF { 1 } else { 2 };
            result.push(0x80 | len_bytes);
            for i in (0..len_bytes).rev() {
                result.push((len >> (i * 8)) as u8);
            }
        }
        result.extend_from_slice(&self.data);
        result
    }

    pub fn parse_multiple(data: impl AsRef<[u8]>) -> Result<Vec<Self>> {
        let mut objects = Vec::new();
        let mut offset = 0;

        let data = data.as_ref();
        while offset < data.len() {
            let (tlv, next_offset) = Self::parse_at_offset(data, offset)?;
            objects.push(tlv);
            offset = next_offset;
        }
        Ok(objects)
    }

    fn parse_at_offset(data: &[u8], offset: usize) -> Result<(Self, usize)> {
        if offset + 2 > data.len() {
            return Err(Error::InvalidData(
                "Insufficient data for TLV header".into(),
            ));
        }

        let tag = data[offset];
        let (length, length_end) = Self::parse_length(data, offset + 1)?;

        if length_end + length > data.len() {
            return Err(Error::InvalidData(format!(
                "TLV length {length} exceeds available data",
            )));
        }
        let value = data[length_end..length_end + length].to_vec();
        Ok((Self::new(tag, value), length_end + length))
    }

    fn parse_length(data: &[u8], offset: usize) -> Result<(usize, usize)> {
        if offset >= data.len() {
            return Err(Error::InvalidData("No length byte".into()));
        }

        let first_byte = data[offset];
        if first_byte & 0x80 == 0 {
            Ok((first_byte as usize, offset + 1))
        } else {
            let length_bytes = (first_byte & 0x7F) as usize;

            if length_bytes == 0 {
                return Err(Error::InvalidData("Invalid indefinite length".into()));
            }
            if offset + 1 + length_bytes > data.len() {
                return Err(Error::InvalidData(
                    "Insufficient data for long length".into(),
                ));
            }

            let mut length = 0usize;
            for i in 0..length_bytes {
                length = (length << 8) | (data[offset + 1 + i] as usize);
            }
            Ok((length, offset + 1 + length_bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_expected_length() {
        // Test zero length
        let tlv = APDUTlv::expected_length(0);
        assert_eq!(tlv.tag, 0x97);
        assert_eq!(tlv.data, vec![0x00]);

        // Test 256
        let tlv = APDUTlv::expected_length(0x100);
        assert_eq!(tlv.data, vec![0x00]);

        // Test small value
        let tlv = APDUTlv::expected_length(0x42);
        assert_eq!(tlv.data, vec![0x42]);

        // Test large value
        let tlv = APDUTlv::expected_length(0x0200);
        assert_eq!(tlv.data, vec![0x02, 0x00]);
    }

    #[test]
    fn test_tlv_encode_short_length() {
        let tlv = APDUTlv::new(0x87, vec![0x01, 0x02, 0x03]);
        let encoded = tlv.encode();
        assert_eq!(encoded, vec![0x87, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_tlv_encode_long_length() {
        let data = vec![0xAA; 200];
        let tlv = APDUTlv::new(0x87, data.clone());
        let encoded = tlv.encode();

        assert_eq!(encoded[0], 0x87); // Tag
        assert_eq!(encoded[1], 0x81); // Long form: 1 byte length
        assert_eq!(encoded[2], 200); // Length value
        assert_eq!(&encoded[3..], &data);
    }

    #[test]
    fn test_tlv_parse_multiple_objects() {
        let mut data = vec![];
        data.extend_from_slice(&[0x87, 0x02, 0x01, 0x02]);
        data.extend_from_slice(&[0x99, 0x02, 0x90, 0x00]);
        data.extend_from_slice(&[0x8E, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        let parsed = APDUTlv::parse_multiple(&data).unwrap();

        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].tag, 0x87);
        assert_eq!(parsed[1].tag, 0x99);
        assert_eq!(parsed[2].tag, 0x8E);
    }

    #[test]
    fn test_tlv_parse_long_form() {
        let mut data = vec![0x87, 0x81, 0x10]; // Tag, long form (1 byte), length 16
        data.extend_from_slice(&[0xAA; 16]);

        let parsed = APDUTlv::parse_multiple(&data).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].tag, 0x87);
        assert_eq!(parsed[0].data.len(), 16);
    }

    #[test]
    fn test_tlv_parse_insufficient_data() {
        let data = vec![0x87]; // Only tag, no length
        let result = APDUTlv::parse_multiple(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_tlv_roundtrip() {
        let original = APDUTlv::new(0x87, vec![0x01, 0x02, 0x03, 0x04]);
        let encoded = original.encode();
        let parsed = APDUTlv::parse_multiple(&encoded).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].tag, original.tag);
        assert_eq!(parsed[0].data, original.data);
    }
}
