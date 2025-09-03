use rasn::prelude::{
    Any, AsnType, Decode, Decoder, Encode, ObjectIdentifier as Oid, OctetString, SequenceOf,
};

/// Certificate Holder Authorization Template (CHAT)
#[derive(Debug, Clone, Decode, Encode, AsnType)]
#[rasn(tag(application, 0x4C))]
pub struct Chat {
    /// chat object identifier
    pub oid: Oid,
    /// chat template
    #[rasn(tag(application, 0x13), size(5))]
    pub template: OctetString,
}

/// ECDSA Public Key
#[derive(Debug, Clone, Decode, Encode, AsnType)]
#[rasn(tag(application, 0x49))]
pub struct EcdsaPublicKey {
    /// key object identifier
    pub oid: Oid,
    #[rasn(tag(context, 1))]
    /// prime modulus
    pub prime: Option<OctetString>,
    #[rasn(tag(context, 2))]
    /// first coefficient
    pub a: Option<OctetString>,
    #[rasn(tag(context, 3))]
    /// second coefficient
    pub b: Option<OctetString>,
    #[rasn(tag(context, 4))]
    /// base point
    pub generator: Option<OctetString>,
    #[rasn(tag(context, 5))]
    /// order of the base point
    pub order: Option<OctetString>,
    #[rasn(tag(context, 6))]
    /// public point
    pub public_point: OctetString,
    #[rasn(tag(context, 7))]
    /// cofactor
    pub cofactor: Option<OctetString>,
}

/// Certificate Extensions
#[derive(Debug, Clone, Decode, Encode, AsnType)]
#[rasn(tag(application, 0x05))]
#[rasn(delegate)]
pub struct CertificateExtensions(pub SequenceOf<Any>);

/// Card Verifiable Certificate Body
#[derive(Debug, Clone, Decode, Encode, AsnType)]
#[rasn(tag(application, 0x4E))]
pub struct CvCertificateBody {
    /// certificate profile identifier
    #[rasn(tag(application, 0x29))]
    pub profile_id: OctetString,
    #[rasn(tag(application, 0x02))]
    /// certificate authority reference
    pub car: OctetString,
    /// public key value and domain parameters
    pub public_key: EcdsaPublicKey,
    #[rasn(tag(application, 0x20))]
    /// certificate holder reference
    pub chr: OctetString,
    /// certificate holder authorization template
    pub chat: Chat,
    /// certificate effective date
    #[rasn(tag(application, 0x25), size(6))]
    pub effective_date: OctetString,
    /// certificate expiration date
    #[rasn(tag(application, 0x24), size(6))]
    pub expiration_date: OctetString,
    /// certificate extensions
    pub extensions: Option<CertificateExtensions>,
}

/// Card Verifiable Certificate
#[derive(Debug, Clone, Decode, Encode, AsnType)]
#[rasn(tag(application, 0x21))]
pub struct CvCertificate {
    /// CV certificate body
    pub body: CvCertificateBody,
    /// CV certificate signature
    #[rasn(tag(application, 0x37))]
    pub signature: OctetString,
}
