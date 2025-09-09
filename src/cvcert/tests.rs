use super::*;
use hex_literal::hex;

#[test]
fn test_decode_cvca() {
    let cert_hex = include_str!("../../test_data/cvcerts/DECVCAeID00102.hex");
    let result = CvCertificate::from_hex(cert_hex);
    assert!(result.is_ok());

    // Should be CVCA, self-signed and contain domain parameters
    let cert = result.unwrap();
    assert_eq!(cert.access_role(), AccessRole::CVCA);
    assert!(cert.is_self_signed());
    assert!(cert.has_domain_parameters());

    // Profile version is 1 and identified by a value of 0
    assert_eq!(cert.profile_id(), &[0]);

    // certfificate authority reference and certificate holder reference should be the same
    // since this is a self-signed certificate
    assert_eq!(cert.car(), "DECVCAeID00102");
    assert_eq!(cert.chr(), "DECVCAeID00102");
    assert_eq!(cert.car(), cert.chr());

    // 010001000108 -> 2010-10-18
    assert_eq!(
        cert.effective_date().unwrap(),
        Date::from_bcd(&hex!("010001000108")).unwrap()
    );
    // 010301000108 -> 2013-10-18
    assert_eq!(
        cert.expiration_date().unwrap(),
        Date::from_bcd(&hex!("010301000108")).unwrap()
    );

    let expected_signature_bytes = hex!(
        "5067145C68CAE9520F5BB34817F1CA9C43593DB56406C6A3B006CBF3F314E734"
        "9ACF0CC6BFEBCBDEFD10B4DCF0F231DA56977D88F9F90182D199076A56506451"
    );
    assert_eq!(cert.signature().len(), expected_signature_bytes.len());
    assert_eq!(cert.signature(), expected_signature_bytes);
    // Security protocol should be EcdsaSha256 (brainpoolP256r1 curve)
    assert_eq!(
        cert.public_key().security_protocol(),
        Some(SecurityProtocol::EcdsaSha256)
    );
}

#[test]
fn test_decode_link_cvca() {
    let cert_hex = include_str!("../../test_data/cvcerts/DECVCAeID00103.hex");
    let result = CvCertificate::from_hex(cert_hex);
    assert!(result.is_ok());

    // link CVCA certificates are not self-signed and may contain domain parameters
    let cert = result.unwrap();
    assert_eq!(cert.access_role(), AccessRole::CVCA);
    assert!(!cert.is_self_signed());
    assert!(cert.validate_structure().is_ok());

    // Profile version is 1 and identified by a value of 0
    assert_eq!(cert.profile_id(), &[0]);

    // certfificate authority reference and certificate holder reference should not be the same
    // since this is a link CVCA certificate
    assert_eq!(cert.car(), "DECVCAeID00102");
    assert_eq!(cert.chr(), "DECVCAeID00103");
    // this link CVCA certificate is issued by DECVCAeID00102
    assert!(cert.is_issued_by("DECVCAeID00102"));

    // 010201020003 -> 2012-12-03
    assert_eq!(
        cert.effective_date().unwrap(),
        Date::from_bcd(&hex!("010201020003")).unwrap()
    );
    // 010501020003 -> 2015-12-03
    assert_eq!(
        cert.expiration_date().unwrap(),
        Date::from_bcd(&hex!("010501020003")).unwrap()
    );
    // Signature should be 64 bytes long (EcdsaSha256)
    assert_eq!(cert.signature().len(), 64);
    // Security protocol should be EcdsaSha256 (brainpoolP256r1 curve)
    assert_eq!(
        cert.public_key().security_protocol(),
        Some(SecurityProtocol::EcdsaSha256)
    );
}

#[test]
fn test_dv_cert() {
    let cert_hex = include_str!("../../test_data/cvcerts/CMDVCAeID00001.hex");
    let result = CvCertificate::from_hex(cert_hex);
    assert!(result.is_ok());

    // DV certificates are not self-signed and must not contain domain parameters
    let cert = result.unwrap();
    // DV official domestic
    assert_eq!(cert.access_role(), AccessRole::DVOD);
    assert!(!cert.is_self_signed());
    assert!(!cert.has_domain_parameters());

    // DV certificates should be issued by CVCA
    assert_eq!(cert.car(), "CMCVCAeID00001");
    assert_eq!(cert.chr(), "CMDVCAeID00001");
    // this DV certificate is issued by CMCVCAeID00001
    assert!(cert.is_issued_by("CMCVCAeID00001"));

    // 020500090002 -> 2025-09-02
    assert_eq!(
        cert.effective_date().unwrap(),
        Date::from_bcd(&hex!("020500090002")).unwrap()
    );
    // 020700090002 -> 2027-09-02
    assert_eq!(
        cert.expiration_date().unwrap(),
        Date::from_bcd(&hex!("020700090002")).unwrap()
    );
    // Signature should be 64 bytes long (EcdsaSha256)
    assert_eq!(cert.signature().len(), 64);
}

#[test]
fn test_terminal_cert() {
    let cert_hex = include_str!("../../test_data/cvcerts/CMTERMeID00001.hex");
    let result = CvCertificate::from_hex(cert_hex);
    assert!(result.is_ok());

    let cert = result.unwrap();
    // Terminal certificates are not self-signed and must not contain domain parameters
    assert_eq!(cert.access_role(), AccessRole::AT);
    assert!(!cert.is_self_signed());
    assert!(!cert.has_domain_parameters());

    // Terminal certificates should be issued by DV
    assert_eq!(cert.car(), "CMDVCAeID00001");
    assert_eq!(cert.chr(), "CMTERMeID00001");
    // this Terminal certificate is issued by CMDVCAeID00001
    assert!(cert.is_issued_by("CMDVCAeID00001"));

    // 020500090002 -> 2025-09-02
    assert_eq!(
        cert.effective_date().unwrap(),
        Date::from_bcd(&hex!("020500090002")).unwrap()
    );
    // 020700090002 -> 2027-09-02
    assert_eq!(
        cert.expiration_date().unwrap(),
        Date::from_bcd(&hex!("020700090002")).unwrap()
    );
    // Signature should be 64 bytes long (EcdsaSha256)
    assert_eq!(cert.signature().len(), 64);
}

#[test]
fn test_access_role_bit_patterns() {
    // TR-03110-4 section 2.2.3 Table 3
    assert_eq!(AccessRole::AT.bit_pattern(), 0b00);
    assert_eq!(AccessRole::DVNoF.bit_pattern(), 0b01);
    assert_eq!(AccessRole::DVOD.bit_pattern(), 0b10);
    assert_eq!(AccessRole::CVCA.bit_pattern(), 0b11);

    assert_eq!(AccessRole::from_bits(0b00), AccessRole::AT);
    assert_eq!(AccessRole::from_bits(0b01), AccessRole::DVNoF);
    assert_eq!(AccessRole::from_bits(0b10), AccessRole::DVOD);
    assert_eq!(AccessRole::from_bits(0b11), AccessRole::CVCA);
}

#[test]
fn test_access_right_bit_positions() {
    // TR-03110-4 section 2.2.3 Table 3
    assert_eq!(AccessRight::AgeVerification.bit_position(), 0);
    assert_eq!(AccessRight::CommunityIdVerification.bit_position(), 1);
    assert_eq!(AccessRight::ReadDG01.bit_position(), 8);
    assert_eq!(AccessRight::ReadDG22.bit_position(), 29);
    assert_eq!(AccessRight::WriteDG22.bit_position(), 32);
    assert_eq!(AccessRight::WriteDG17.bit_position(), 37);
}

#[test]
fn test_access_right_categories() {
    // Test special functions
    assert!(AccessRight::AgeVerification.is_special_function());
    assert!(AccessRight::InstallQualifiedCert.is_special_function());
    assert!(!AccessRight::ReadDG01.is_special_function());
    assert!(!AccessRight::WriteDG22.is_special_function());

    // Test read access
    assert!(!AccessRight::AgeVerification.is_read_access());
    assert!(AccessRight::ReadDG01.is_read_access());
    assert!(AccessRight::ReadDG22.is_read_access());
    assert!(!AccessRight::WriteDG22.is_read_access());

    // Test write access
    assert!(!AccessRight::AgeVerification.is_write_access());
    assert!(!AccessRight::ReadDG01.is_write_access());
    assert!(AccessRight::WriteDG17.is_write_access());
    assert!(AccessRight::WriteDG22.is_write_access());
}

#[test]
fn test_access_rights_basic_operations() {
    let mut rights = AccessRights::new();

    // Test adding rights
    rights.add(AccessRight::AgeVerification);
    assert!(rights.has(AccessRight::AgeVerification));
    assert!(!rights.has(AccessRight::ReadDG01));

    // Test removing rights
    rights.remove(AccessRight::AgeVerification);
    assert!(!rights.has(AccessRight::AgeVerification));

    // Test chaining
    rights.add(AccessRight::ReadDG01).add(AccessRight::ReadDG02);
    assert!(rights.has(AccessRight::ReadDG01));
    assert!(rights.has(AccessRight::ReadDG02));
}

#[test]
fn test_access_rights_with_read_access() {
    let rights = AccessRights::new().with_read_access(1..=5);

    assert!(rights.has(AccessRight::ReadDG01));
    assert!(rights.has(AccessRight::ReadDG02));
    assert!(rights.has(AccessRight::ReadDG03));
    assert!(rights.has(AccessRight::ReadDG04));
    assert!(rights.has(AccessRight::ReadDG05));
    assert!(!rights.has(AccessRight::ReadDG06));
    assert!(!rights.has(AccessRight::ReadDG22));
}

#[test]
fn test_access_rights_with_read_access_full_range() {
    let rights = AccessRights::new().with_read_access(1..=22);

    assert!(rights.has(AccessRight::ReadDG01));
    assert!(rights.has(AccessRight::ReadDG22));
    // Should have exactly 21 read rights
    // DG16 is reserved for future use, thus not included
    assert_eq!(rights.rights().len(), 21);
}

#[test]
fn test_access_rights_with_read_access_invalid_range() {
    let rights = AccessRights::new().with_read_access(0..=25);

    // Should only include valid DG numbers (1-22)
    assert!(!rights.has(AccessRight::AgeVerification));
    assert!(rights.has(AccessRight::ReadDG01));
    assert!(rights.has(AccessRight::ReadDG22));
    // DG16 is reserved for future use, thus not included
    assert_eq!(rights.rights().len(), 21);
}

#[test]
fn test_access_rights_with_write_access() {
    let rights = AccessRights::new().with_write_access(19..=22);

    assert!(rights.has(AccessRight::WriteDG19));
    assert!(rights.has(AccessRight::WriteDG20));
    assert!(rights.has(AccessRight::WriteDG21));
    assert!(rights.has(AccessRight::WriteDG22));
    assert!(!rights.has(AccessRight::WriteDG17));
    assert!(!rights.has(AccessRight::WriteDG18));
}

#[test]
fn test_access_rights_with_write_access_invalid_range() {
    let rights = AccessRights::new().with_write_access(1..=25);

    // Should only include valid write DG numbers (17-22)
    assert!(rights.has(AccessRight::WriteDG17));
    assert!(rights.has(AccessRight::WriteDG22));
    // Only 6 valid write rights
    assert_eq!(rights.rights().len(), 6);
}

#[test]
fn test_access_rights_with_special_functions() {
    let rights = AccessRights::new().with_special_functions(0..=3);

    assert!(rights.has(AccessRight::AgeVerification));
    assert!(rights.has(AccessRight::CommunityIdVerification));
    assert!(rights.has(AccessRight::RestrictedIdentification));
    assert!(rights.has(AccessRight::PrivilegedTerminal));
    assert!(!rights.has(AccessRight::CanAllowed));
    assert!(!rights.has(AccessRight::InstallQualifiedCert));
}

#[test]
fn test_access_rights_with_special_functions_invalid_range() {
    let rights = AccessRights::new().with_special_functions(0..=10);

    // Should only include valid special function numbers (0-7)
    assert!(rights.has(AccessRight::AgeVerification));
    assert!(rights.has(AccessRight::InstallQualifiedCert));
    assert_eq!(rights.rights().len(), 8);
}

#[test]
fn test_chat_template_conversion() {
    let mut rights = AccessRights::new();
    rights.add(AccessRight::AgeVerification); // bit 0
    rights.add(AccessRight::ReadDG01); // bit 8
    rights.add(AccessRight::WriteDG22); // bit 32

    let template = rights.to_chat_template(AccessRole::CVCA);

    // Role should be in highest 2 bits of first byte (CVCA = 0b11)
    assert_eq!((template[0] >> 6) & 0b11, 0b11);

    // Check bit 0 (AgeVerification) - should be in byte 4, bit 0
    assert_eq!(template[4] & 0b00000001, 0b00000001);

    // Check bit 8 (ReadDG01) - should be in byte 3, bit 0
    assert_eq!(template[3] & 0b00000001, 0b00000001);

    // Check bit 32 (WriteDG22) - should be in byte 0, bit 0
    assert_eq!(template[0] & 0b00000001, 0b00000001);
}

#[test]
fn test_chat_template_from_conversion() {
    let mut template = [0u8; 5];

    // Set CVCA role (0b11 in highest 2 bits of first byte)
    template[0] |= 0b11 << 6;

    // Set some access rights
    template[4] |= 0b00000001; // bit 0 byte 4 - AgeVerification
    template[3] |= 0b00000001; // bit 8 byte 3 - ReadDG01
    template[0] |= 0b00000001; // bit 32 byte 0 - WriteDG22

    let (role, rights) = AccessRights::from_chat_template(template);

    assert_eq!(role, AccessRole::CVCA);
    assert!(rights.has(AccessRight::AgeVerification));
    assert!(rights.has(AccessRight::ReadDG01));
    assert!(rights.has(AccessRight::WriteDG22));
    assert_eq!(rights.rights().len(), 3);
}

#[test]
fn test_chat_template_round_trip() {
    let original_rights = AccessRights::new()
        .with_read_access(1..=5)
        .with_write_access(20..=22)
        .with_special_functions(0..=2);

    let template = original_rights.to_chat_template(AccessRole::DVNoF);
    let (role, decoded_rights) = AccessRights::from_chat_template(template);

    assert_eq!(role, AccessRole::DVNoF);
    assert_eq!(original_rights.rights(), decoded_rights.rights());
}

#[test]
fn test_date_creation_valid() {
    let date = Date::new(2025, 9, 2).unwrap();
    assert_eq!(date.year(), 2025);
    assert_eq!(date.month(), 9);
    assert_eq!(date.day(), 2);
}

#[test]
fn test_date_creation_invalid_date_data() {
    // valid years are 2000-2099 (TR-03110-3 section D.2.1.3)
    assert!(Date::new(1999, 1, 1).is_err());
    assert!(Date::new(2100, 1, 1).is_err());

    // valid months are 1-12
    assert!(Date::new(2025, 0, 1).is_err());
    assert!(Date::new(2025, 13, 1).is_err());

    // valid days are 1-31
    assert!(Date::new(2025, 9, 0).is_err());
    assert!(Date::new(2025, 9, 32).is_err());

    // February in non-leap year
    assert!(Date::new(2023, 2, 29).is_err());
    assert!(Date::new(2023, 2, 28).is_ok());

    // February in leap year
    assert!(Date::new(2024, 2, 29).is_ok());
    assert!(Date::new(2024, 2, 30).is_err());

    // April (30 days)
    assert!(Date::new(2023, 4, 30).is_ok());
    assert!(Date::new(2023, 4, 31).is_err());
}

#[test]
fn test_date_bcd_conversion() {
    let date = Date::new(2025, 9, 2).unwrap();
    let bcd = date.to_bcd();

    // Expected: 25 09 02 -> [2, 5, 0, 9, 0, 2]
    assert_eq!(bcd, [2, 5, 0, 9, 0, 2]);
}

#[test]
fn test_date_from_bcd_valid() {
    let bcd = [2, 5, 0, 9, 0, 2]; // 25-09-02
    let date = Date::from_bcd(&bcd).unwrap();

    assert_eq!(date.year(), 2025);
    assert_eq!(date.month(), 9);
    assert_eq!(date.day(), 2);
}

#[test]
fn test_date_from_bcd_invalid_length() {
    let bcd = [2, 3, 1, 2, 2]; // Only 5 bytes
    assert!(Date::from_bcd(&bcd).is_err());
}

#[test]
fn test_date_from_bcd_invalid_unpacked() {
    // Last byte has high nibble set
    let bcd = [2, 3, 1, 2, 2, 0x15];
    assert!(Date::from_bcd(&bcd).is_err());

    // Last byte has invalid digit (A)
    let bcd2 = [2, 3, 1, 2, 2, 0x0A];
    assert!(Date::from_bcd(&bcd2).is_err());
}

#[test]
fn test_date_bcd_round_trip() {
    let original = Date::new(2045, 7, 3).unwrap();
    let bcd = original.to_bcd();
    let decoded = Date::from_bcd(&bcd).unwrap();

    assert_eq!(original, decoded);
}

#[test]
fn test_date_display() {
    let date = Date::new(2025, 9, 2).unwrap();
    assert_eq!(format!("{date}"), "2025-09-02");
}

#[test]
fn test_edge_cases_chat_template() {
    // Test empty rights
    let empty_rights = AccessRights::new();
    let template = empty_rights.to_chat_template(AccessRole::AT);
    let (role, decoded_rights) = AccessRights::from_chat_template(template);

    assert_eq!(role, AccessRole::AT);
    assert_eq!(decoded_rights.rights().len(), 0);

    // Test template with all zeros except role
    let mut template = [0u8; 5];
    template[0] = 0b10 << 6; // DVOD role
    let (role, decoded_rights) = AccessRights::from_chat_template(template);

    assert_eq!(role, AccessRole::DVOD);
    assert_eq!(decoded_rights.rights().len(), 0);
}
