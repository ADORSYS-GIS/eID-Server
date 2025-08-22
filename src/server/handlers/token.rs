use std::collections::HashMap;

// ASN.1 Tag constants (matching the C++ code)
const ASN1_UNIVERSAL: u8 = 0x00;
const ASN1_APPLICATION: u8 = 0x40;
const ASN1_CONTEXT_SPECIFIC: u8 = 0x80;
const ASN1_CONSTRUCTED: u8 = 0x20;

const UNI_OBJECT_IDENTIFIER: u8 = 6;
const EC_PUBLIC_POINT: u8 = 6;
const PUBLIC_KEY: u8 = 73;

// Common Chip Authentication OIDs
fn get_ca_oids() -> HashMap<&'static str, Vec<u8>> {
    let mut oids = HashMap::new();
    // id-CA-ECDH-AES-CBC-CMAC-128
    oids.insert(
        "ca_ecdh_aes_128",
        vec![0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x02],
    );
    // id-CA-ECDH-AES-CBC-CMAC-192
    oids.insert(
        "ca_ecdh_aes_192",
        vec![0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x03],
    );
    oids
}

fn encode_asn1_object(class: u8, tag: u8, data: &[u8], constructed: bool) -> Vec<u8> {
    let mut result = Vec::new();

    if tag <= 30 {
        let tag_byte = class | tag | if constructed { ASN1_CONSTRUCTED } else { 0 };
        result.push(tag_byte);
    } else {
        let first_byte = class | if constructed { ASN1_CONSTRUCTED } else { 0 } | 0x1F;
        result.push(first_byte);

        if tag < 128 {
            result.push(tag);
        } else {
            result.push(tag);
        }
    }

    let len = data.len();
    if len < 0x80 {
        result.push(len as u8);
    } else {
        let len_bytes = if len <= 0xFF {
            1
        } else if len <= 0xFFFF {
            2
        } else if len <= 0xFFFFFF {
            3
        } else {
            4
        };

        result.push(0x80 | len_bytes);
        for i in (0..len_bytes).rev() {
            result.push((len >> (i * 8)) as u8);
        }
    }

    result.extend_from_slice(data);
    result
}

pub fn encode_uncompressed_public_key(oid_name: &str, public_key_bytes: &[u8]) -> Vec<u8> {
    let oids = get_ca_oids();
    let oid = oids.get(oid_name).expect("Unknown OID");

    let encoded_oid = encode_asn1_object(ASN1_UNIVERSAL, UNI_OBJECT_IDENTIFIER, oid, false);

    let encoded_public_point = encode_asn1_object(
        ASN1_CONTEXT_SPECIFIC,
        EC_PUBLIC_POINT,
        public_key_bytes,
        false,
    );

    let mut combined = Vec::new();
    combined.extend_from_slice(&encoded_oid);
    combined.extend_from_slice(&encoded_public_point);
    encode_asn1_object(ASN1_APPLICATION, PUBLIC_KEY, &combined, true)
}
