use crate::asn1::oid::{DATE_OF_BIRTH_OID, DATE_OF_EXPIRY_OID, MUNICIPALITY_ID_OID};
use rasn::prelude::{ObjectIdentifier as Oid, *};

/// Date definition: Date ::= NumericString (SIZE (8)) -- YYYYMMDD
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(tag(application, 0x13), delegate, size(8))]
pub struct Date(pub NumericString);

/// Municipality ID definition: MunicipalityID ::= OCTET STRING
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(tag(application, 0x13), delegate)]
pub struct CommunityID(pub OctetString);

/// Auxiliary data template without the tag
#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Decode, Encode)]
pub struct AuxDataTemplateCore {
    pub aux_id: Oid,
    pub ext_info: Any,
}

/// AuxDataTemplate ::= [APPLICATION 0x13] IMPLICIT SEQUENCE {
///         auxID            OBJECT IDENTIFIER,
///         extInfo          ANY DEFINED BY auxID
/// }
#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Decode, Encode)]
#[rasn(tag(application, 0x13), delegate)]
pub struct AuxDataTemplate(pub AuxDataTemplateCore);

/// Authenticated auxiliary data
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(tag(application, 0x07), delegate)]
pub struct AuthenticatedAuxiliaryData(pub SetOf<AuxDataTemplate>);

impl AuthenticatedAuxiliaryData {
    /// Create a new empty AuthenticatedAuxiliaryData
    pub fn new() -> Self {
        Self(SetOf::new())
    }

    /// Add a discretionary data template
    pub fn add_template(&mut self, template: AuxDataTemplateCore) {
        self.0.insert(AuxDataTemplate(template));
    }

    /// Add a date of birth template
    pub fn add_date_of_birth(&mut self, date: Date) -> Result<(), rasn::error::EncodeError> {
        let encoded_date = rasn::der::encode(&date)?;
        let template = AuxDataTemplateCore {
            aux_id: Oid::new_unchecked(DATE_OF_BIRTH_OID.into()),
            ext_info: Any::from(encoded_date),
        };
        self.add_template(template);
        Ok(())
    }

    /// Add a date of expiry template
    pub fn add_date_of_expiry(&mut self, date: Date) -> Result<(), rasn::error::EncodeError> {
        let encoded_date = rasn::der::encode(&date)?;
        let template = AuxDataTemplateCore {
            aux_id: Oid::new_unchecked(DATE_OF_EXPIRY_OID.into()),
            ext_info: Any::from(encoded_date),
        };
        self.add_template(template);
        Ok(())
    }

    /// Add a municipality ID template
    pub fn add_municipality_id(
        &mut self,
        municipality_data: impl Into<Vec<u8>>,
    ) -> Result<(), rasn::error::EncodeError> {
        let encoded = rasn::der::encode(&CommunityID(municipality_data.into().into()))?;
        let template = AuxDataTemplateCore {
            aux_id: Oid::new_unchecked(MUNICIPALITY_ID_OID.into()),
            ext_info: Any::from(encoded),
        };
        self.add_template(template);
        Ok(())
    }

    /// Encode this AuthenticatedAuxiliaryData to ASN.1 DER bytes
    pub fn to_vec(&self) -> Result<Vec<u8>, rasn::error::EncodeError> {
        rasn::der::encode(self)
    }

    /// Encode this AuthenticatedAuxiliaryData to ASN.1 DER encoded hex string
    pub fn to_hex(&self) -> Result<String, rasn::error::EncodeError> {
        Ok(hex::encode(self.to_vec()?))
    }

    /// Get the number of templates
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for AuthenticatedAuxiliaryData {
    fn default() -> Self {
        Self::new()
    }
}
