use rasn::prelude::*;

/// ICAO String - PrintableString (A-Z and space only)
pub type ICAOString = PrintableString;

/// ICAO Country Code - 1 or 3 character ICAO string
pub type ICAOCountry = ICAOString;

/// ICAO Sex - M, F, or space
pub type ICAOSex = PrintableString;

/// Date - NumericString in format YYYYMMDD
pub type Date = NumericString;

/// Structured place information
#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Encode, Decode)]
pub struct Place {
    #[rasn(tag(explicit(10)))]
    pub street: Option<Utf8String>,

    #[rasn(tag(explicit(11)))]
    pub city: Utf8String,

    #[rasn(tag(explicit(12)))]
    pub state: Option<Utf8String>,

    #[rasn(tag(explicit(13)))]
    pub country: ICAOCountry,

    #[rasn(tag(explicit(14)))]
    pub zipcode: Option<PrintableString>,
}

/// General place - can be structured, freetext, or no info
#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Encode, Decode)]
#[rasn(choice)]
pub enum GeneralPlace {
    StructuredPlace(Place),

    #[rasn(tag(explicit(1)))]
    FreetextPlace(Utf8String),

    #[rasn(tag(explicit(2)))]
    NoPlaceInfo(Utf8String),
}

/// Text - either uncompressed or compressed
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(choice)]
pub enum Text {
    #[rasn(tag(explicit(1)))]
    Uncompressed(Utf8String),

    #[rasn(tag(explicit(2)))]
    Compressed(OctetString),
}

/// Optional data with type and value
#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Encode, Decode)]
pub struct OptionalData {
    pub r#type: ObjectIdentifier,
    pub data: Option<Any>,
}

/// Optional data set
pub type OptionalDataR = SetOf<OptionalData>;

/// Document Type - [APPLICATION 1] ICAOString (SIZE 2)
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 1), size(2))]
pub struct DocumentType(pub PrintableString);

/// Issuing Entity - [APPLICATION 2] CHOICE
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 2), choice)]
pub enum IssuingEntity {
    IssuingState(ICAOCountry),
    IssuingPlace(Place),
}

/// Date of Expiry - [APPLICATION 3] Date
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 3))]
pub struct DateOfExpiry(pub Date);

/// Given Names - [APPLICATION 4] UTF8String
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 4))]
pub struct GivenNames(pub Utf8String);

/// Family Names - [APPLICATION 5] UTF8String
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 5))]
pub struct FamilyNames(pub Utf8String);

/// Nom De Plume - [APPLICATION 6] UTF8String
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 6))]
pub struct NomDePlume(pub Utf8String);

/// Academic Title - [APPLICATION 7] UTF8String
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 7))]
pub struct AcademicTitle(pub Utf8String);

/// Date of Birth - [APPLICATION 8] Date
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 8))]
pub struct DateOfBirth(pub Date);

/// Place of Birth - [APPLICATION 9] GeneralPlace
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 9))]
pub struct PlaceOfBirth(pub GeneralPlace);

/// Nationality - [APPLICATION 10] ICAOCountry
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 10))]
pub struct Nationality(pub ICAOCountry);

/// Sex - [APPLICATION 11] ICAOSex
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 11))]
pub struct Sex(pub ICAOSex);

/// Optional Data R - [APPLICATION 12] SET OF OptionalData
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 12))]
pub struct OptionalDataRTagged(pub OptionalDataR);

/// Birth Name - [APPLICATION 13] UTF8String
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 13))]
pub struct BirthName(pub Utf8String);

/// Written Signature - [APPLICATION 14] OCTET STRING (JPEG-2000)
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 14))]
pub struct WrittenSignature(pub OctetString);

/// Date of Issuance - [APPLICATION 15] Date
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 15))]
pub struct DateOfIssuance(pub Date);

/// Place of Residence - [APPLICATION 17] CHOICE
#[derive(AsnType, Encode, Decode, Clone, Debug, PartialEq)]
#[rasn(tag(application, 17), choice)]
pub enum PlaceOfResidence {
    Residence(GeneralPlace),
    MultResidence(SetOf<GeneralPlace>),
}

/// Municipality ID - [APPLICATION 18] OCTET STRING
#[derive(AsnType, Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[rasn(tag(application, 18))]
pub struct MunicipalityID(pub OctetString);

/// Residence Permit I - [APPLICATION 19] Text
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 19))]
pub struct ResidencePermitI(pub Text);

/// Residence Permit II - [APPLICATION 20] Text
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 20))]
pub struct ResidencePermitII(pub Text);

/// Phone Number - [APPLICATION 21] PrintableString (telephone URI)
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 21))]
pub struct PhoneNumber(pub PrintableString);

/// Email Address - [APPLICATION 22] IA5String
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode)]
#[rasn(tag(application, 22))]
pub struct EmailAddress(pub Ia5String);
