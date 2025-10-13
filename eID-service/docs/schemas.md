# eService Test Implementation Guide (SOAP, No Signatures)

## 1. Introduction

This document extends the previous guide with **full XML Schema (XSD)** content for the eID-Server interface. The XSD provided by you (TR-03130eID-Server.xsd) is appended in full in the Appendix. The important schema fragments used by the eService are extracted below for quick reference.

**Note:** XML Signature handling is still omitted; placeholders remain where signature would normally apply.

## 2. Overview of SOAP Messages used by the eService

- `useIDRequest` / `useIDResponse`
- `getResultRequest` / `getResultResponse`
- TC Token is provided to the eID-Client by the eService (schema for TCToken included where available)

## 3. Extracted Schema Fragments (from TR-03130eID-Server.xsd)

### 3.x Schema fragment for `useIDRequest`

```xml

<element name="useIDRequest" type="tns:useIDRequestType" />
 <complexType name="useIDRequestType">
  <sequence>
   <element name="UseOperations"
    type="tns:OperationsRequestorType" />
   <element name="AgeVerific

```

### 3.x Schema fragment for `useIDResponse`

```xml

<element name="useIDResponse" type="tns:useIDResponseType" />
 <complexType name="useIDResponseType">
  <sequence>
   <element name="Session" type="tns:SessionType" />
   <element name="eCardServerAddress" type="any

```

### 3.x Schema fragment for `getResultRequest`

```xml

<element name="getResultRequest" type="tns:getResultRequestType" />
 <complexType name="getResultRequestType">
  <sequence>
   <element name="Session" type="tns:SessionType" />
   <element name="RequestCounter" type

```

### 3.x Schema fragment for `getResultResponse`

```xml

<element name="getResultResponse" type="tns:getResultResponseType" />
 <complexType name="getResultResponseType">
  <sequence>
   <element name="PersonalData" type="tns:PersonalDataType"
    minOccurs="0" />
   <ele

```

### 3.x Schema fragment for `SessionType`

```xml

<complexType name="SessionType">
  <sequence>
   <element name="ID">
    <simpleType>
     <restriction base="hexBinary">
      <minLength value="16" />
     </restriction>
    </simpleType>
   </element>
  </sequence>

```

### 3.x Schema fragment for `PreSharedKeyType`

```xml

<element name="PSK" type="tns:PreSharedKeyType" />
   <element ref="dss:Result" />
  </sequence>
 </complexType>
 <complexType name="PersonalDataType">
  <sequence>
   <element name="DocumentType" type="tns:DocumentType"
    minOc

```

### 3.x Schema fragment for `TCTokenType`

_Not found in supplied XSD file. Refer to the Appendix for the full XSD or the TR-03124 spec for TCToken._

### 3.x Schema fragment for `PSK`

```xml

<element name="PSK" type="tns:PreSharedKeyType" />
   <element ref="dss:Result" />
  </sequence>
 </complexType>
 <complexType name="PersonalDataType">
  <sequence>
   <element name="DocumentType" type="tns:Document

```

### 3.x Schema fragment for `Session`

```xml

<complexType name="SessionType">
  <sequence>
   <element name="ID">
    <simpleType>
     <restriction base="hexBinary">
      <minLength value="16" />
     </restriction>
    </simpleType>
   </element>
  </sequence>

```

## 4. Construction Rules (mapping between SOAP payloads and XSD)

1. `useIDRequest`: build according to the `useIDRequest` element/type in the XSD. At minimum include `UseOperations` (even empty) if the XSD requires it.

2. `useIDResponse`: always parse and validate presence of `Session` and `PSK` (PreSharedKey) elements. The PSK element contains `ID` and `Key` which the eService must embed into the TC Token `SessionIdentifier` and `PathSecurity-Parameters` respectively.

3. `getResultRequest` / `getResultResponse`: use the `Session/ID` value returned in `useIDResponse` to request the result.

## 5. TC Token XSD (TCTokenType)

The TCTokenType is defined in TR-03124 (eID-Client). If not present in the supplied XSD, a compatible minimal schema fragment is below and should be used by the eService when constructing the TC Token XML fragment.

```xml

<xs:complexType name="TCTokenType">

  <xs:sequence>

    <xs:element name="ServerAddress" type="xs:anyURI"/>

    <xs:element name="SessionIdentifier" type="xs:string"/>

    <xs:element name="RefreshAddress" type="xs:anyURI"/>

    <xs:element name="CommunicationErrorAddress" type="xs:anyURI" minOccurs="0"/>

    <xs:element name="Binding" type="xs:anyURI"/>

    <xs:element name="PathSecurity-Protocol" type="xs:anyURI" minOccurs="0"/>

    <xs:element name="PathSecurity-Parameters" minOccurs="0">

      <xs:complexType>

        <xs:choice>

          <xs:element name="PSK" type="xs:hexBinary"/>

        </xs:choice>

      </xs:complexType>

    </xs:element>

  </xs:sequence>

</xs:complexType>

```

## 6. Full XSD (Appendix)

The full provided XSD (TR-03130eID-Server.xsd) is included below for completeness. Use it as the authoritative source for message validation.

```xml

<?xml version="1.0" encoding="UTF-8"?>
<schema xmlns="http://www.w3.org/2001/XMLSchema" xmlns:dss="urn:oasis:names:tc:dss:1.0:core:schema"
 xmlns:tns="http://bsi.bund.de/eID/" xmlns:Q1="urn:oasis:names:tc:SAML:1.0:assertion"
 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" targetNamespace="http://bsi.bund.de/eID/"
 elementFormDefault="qualified" attributeFormDefault="unqualified"
 version="2.4.0 2021-08-02">

    <import namespace="urn:oasis:names:tc:dss:1.0:core:schema"
  schemaLocation="external/oasis-dss-core-schema-v1.0-os.xsd" />
 <import namespace="urn:oasis:names:tc:SAML:2.0:assertion"
  schemaLocation="external/saml-schema-assertion-2.0.xsd" />
 <complexType name="SessionType">
  <sequence>
   <element name="ID">
    <simpleType>
     <restriction base="hexBinary">
      <minLength value="16" />
     </restriction>
    </simpleType>
   </element>
  </sequence>
 </complexType>
 <element name="useIDResponse" type="tns:useIDResponseType" />
 <complexType name="useIDResponseType">
  <sequence>
   <element name="Session" type="tns:SessionType" />
   <element name="eCardServerAddress" type="anyURI" minOccurs="0" />
   <element name="PSK" type="tns:PreSharedKeyType" />
   <element ref="dss:Result" />
  </sequence>
 </complexType>
 <complexType name="PersonalDataType">
  <sequence>
   <element name="DocumentType" type="tns:DocumentType"
    minOccurs="0" />
   <element name="IssuingState" type="tns:ICAOCountry"
    minOccurs="0" />
   <element name="DateOfExpiry" type="date" minOccurs="0" />
   <element name="GivenNames" type="string" minOccurs="0" />
   <element name="FamilyNames" type="string" minOccurs="0" />
   <element name="ArtisticName" type="string" minOccurs="0" />
   <element name="AcademicTitle" type="string" minOccurs="0" />
   <element name="DateOfBirth" type="tns:GeneralDateType"
    minOccurs="0" />
   <element name="PlaceOfBirth" type="tns:GeneralPlaceType"
    minOccurs="0" />
   <element name="Nationality" type="tns:ICAOCountry"
    minOccurs="0" />
   <element name="BirthName" type="string" minOccurs="0" />
   <element name="PlaceOfResidence" type="tns:GeneralPlaceType"
    minOccurs="0" />
   <element name="CommunityID" type="tns:CommunityIDType" minOccurs="0" />
   <element name="ResidencePermitI" type="string"
    minOccurs="0" />
   <element name="RestrictedID" type="tns:RestrictedIDType"
    minOccurs="0" />
  </sequence>
 </complexType>
 <complexType name="GeneralPlaceType">
  <choice>
   <element name="StructuredPlace" type="tns:PlaceType" />
   <element name="FreetextPlace" type="string" />
   <element name="NoPlaceInfo" type="string" />
  </choice>
 </complexType>
 <complexType name="PlaceType">
  <sequence>
   <element name="Street" type="string" minOccurs="0" />
   <element name="City" type="string" />
   <element name="State" type="string" minOccurs="0" />
   <element name="Country" type="tns:ICAOCountry" />
   <element name="ZipCode" type="string" minOccurs="0" />
  </sequence>
 </complexType>
 <simpleType name="DocumentType">
  <restriction base="string">
   <pattern value="[A-Z ]{2}" />
  </restriction>
 </simpleType>
 <simpleType name="ICAOCountry">
  <restriction base="string">
   <pattern value="[A-Z ]{1,3}" />
  </restriction>
 </simpleType>
 <complexType name="AgeVerificationRequestType">
  <sequence>
   <element name="Age">
    <simpleType>
     <restriction base="int">
      <minInclusive value="0" />
     </restriction>
    </simpleType>
   </element>
  </sequence>
 </complexType>
 <complexType name="VerificationResultType">
  <sequence>
   <element name="FulfilsRequest" type="boolean" />
  </sequence>
 </complexType>
 <element name="useIDRequest" type="tns:useIDRequestType" />
 <complexType name="useIDRequestType">
  <sequence>
   <element name="UseOperations"
    type="tns:OperationsRequestorType" />
   <element name="AgeVerificationRequest"
    type="tns:AgeVerificationRequestType" minOccurs="0" />
   <element name="PlaceVerificationRequest"
    type="tns:PlaceVerificationRequestType" minOccurs="0" />
   <element name="TransactionInfo" type="string" minOccurs="0" />
   <element name="TransactionAttestationRequest"
    type="tns:TransactionAttestationRequestType" minOccurs="0" />
   <element name="LevelOfAssuranceRequest"
    type="tns:LevelOfAssuranceType" minOccurs="0" />
   <element name="EIDTypeRequest" type="tns:EIDTypeRequestType"
    maxOccurs="1" minOccurs="0" />
   <element name="PSK" type="tns:PreSharedKeyType"
    minOccurs="0" />
  </sequence>
 </complexType>
 <complexType name="OperationsSelectorType">
  <sequence>
   <element name="DocumentType"
    type="tns:AttributeSelectionType" default="PROHIBITED" />
   <element name="IssuingState"
    type="tns:AttributeSelectionType" default="PROHIBITED" />
   <element name="DateOfExpiry"
    type="tns:AttributeSelectionType" default="PROHIBITED" />
   <element name="GivenNames" type="tns:AttributeSelectionType"
    default="PROHIBITED" />
   <element name="FamilyNames"
    type="tns:AttributeSelectionType" default="PROHIBITED" />
   <element name="ArtisticName"
    type="tns:AttributeSelectionType" default="PROHIBITED" />
   <element name="AcademicTitle"
    type="tns:AttributeSelectionType" default="PROHIBITED" />
   <element name="DateOfBirth"
    type="tns:AttributeSelectionType" default="PROHIBITED" />
   <element name="PlaceOfBirth"
    type="tns:AttributeSelectionType" default="PROHIBITED" />
   <element name="Nationality"
    type="tns:AttributeSelectionType" default="PROHIBITED" />
   <element name="BirthName" type="tns:AttributeSelectionType"
    default="PROHIBITED" />
   <element name="PlaceOfResidence"
    type="tns:AttributeSelectionType" default="PROHIBITED" />
   <element name="CommunityID" 
    type="tns:AttributeSelectionType" default="PROHIBITED"/>
   <element name="ResidencePermitI"
    type="tns:AttributeSelectionType" default="PROHIBITED" />
   <element name="RestrictedID"
    type="tns:AttributeSelectionType" default="PROHIBITED" />
   <element name="AgeVerification"
    type="tns:AttributeSelectionType" default="PROHIBITED" />
   <element name="PlaceVerification"
    type="tns:AttributeSelectionType" default="PROHIBITED" />
  </sequence>
 </complexType>
 <complexType name="PlaceVerificationRequestType">
  <sequence>
   <element name="CommunityID" type="tns:CommunityIDType" />
  </sequence>
 </complexType>
 <element name="getServerInfoResponse" type="tns:getServerInfoResponseType" />
 <complexType name="getServerInfoResponseType">
  <sequence>
   <element name="ServerVersion" type="tns:VersionType" />
   <element name="DocumentVerificationRights" type="tns:OperationsSelectorType" />
  </sequence>
 </complexType>
 <complexType name="VersionType">
  <sequence>
   <element name="VersionString" type="string" />
   <element name="Major" type="int" />
   <element name="Minor" type="int" />
   <element name="Bugfix" type="int" minOccurs="0" />
  </sequence>
 </complexType>
 <element name="getServerInfoRequest" type="tns:nullType" />
 <complexType name="nullType">
  <sequence />
 </complexType>
 <element name="getResultRequest" type="tns:getResultRequestType" />
 <complexType name="getResultRequestType">
  <sequence>
   <element name="Session" type="tns:SessionType" />
   <element name="RequestCounter" type="int" />
  </sequence>
 </complexType>
 <element name="getResultResponse" type="tns:getResultResponseType" />
 <complexType name="getResultResponseType">
  <sequence>
   <element name="PersonalData" type="tns:PersonalDataType"
    minOccurs="0" />
   <element name="FulfilsAgeVerification"
    type="tns:VerificationResultType" minOccurs="0" />
   <element name="FulfilsPlaceVerification"
    type="tns:VerificationResultType" minOccurs="0" />
   <element name="OperationsAllowedByUser"
    type="tns:OperationsResponderType" minOccurs="0" />
   <element name="TransactionAttestationResponse"
    type="tns:TransactionAttestationResponseType" minOccurs="0" />
   <element name="LevelOfAssuranceResult"
    type="tns:LevelOfAssuranceType" minOccurs="0" />
   <element name="EIDTypeResponse" 
    type="tns:EIDTypeResponseType" minOccurs="0" />
   <element ref="dss:Result" />
  </sequence>
 </complexType>
 <complexType name="PreSharedKeyType">
  <sequence>
   <element name="ID">
    <simpleType>
     <restriction base="string">
      <minLength value="16" />
     </restriction>
    </simpleType>
   </element>
   <element name="Key">
    <simpleType>
     <restriction base="hexBinary">
      <minLength value="16" />
     </restriction>
    </simpleType>
   </element>
  </sequence>
 </complexType>
 <!-- New types for eID-WSDL (after version 1.3) -->
 <complexType name="GeneralDateType">
  <sequence>
   <element name="DateString">
    <simpleType>
     <restriction base="string">
      <whiteSpace value="preserve" />
      <pattern value="[0-9 ]{8}" />
     </restriction>
    </simpleType>
   </element>
   <element name="DateValue" type="date" minOccurs="0" />
  </sequence>
 </complexType>
 <complexType name="RestrictedIDType">
  <sequence>
   <element name="ID" type="hexBinary" />
   <element name="ID2" type="hexBinary" minOccurs="0" />
  </sequence>
 </complexType>
 <simpleType name="AttributeSelectionType">
  <restriction base="string">
   <enumeration value="ALLOWED" />
   <enumeration value="PROHIBITED" />
  </restriction>
 </simpleType>
 <!-- Additional types for SAML attributes -->
 <complexType name="PlaceVerificationResultType">
  <sequence>
   <element name="Request" type="tns:PlaceVerificationRequestType" />
   <element name="Result" type="tns:VerificationResultType" />
  </sequence>
 </complexType>
 <complexType name="AgeVerificationResultType">
  <sequence>
   <element name="Request" type="tns:AgeVerificationRequestType" />
   <element name="Result" type="tns:VerificationResultType" />
  </sequence>
 </complexType>
 <complexType name="DocumentValidityResultType">
  <sequence>
   <element name="ReferenceDate" type="date" />
   <element name="Status" type="string" />
  </sequence>
  <attribute name="Version" type="positiveInteger" use="required" />
  <anyAttribute namespace="##any" processContents="lax" />
 </complexType>
 <!-- Additional types used in SAML AuthnRequest -->
 <element name="EncryptedAuthnRequestExtension" type="saml:EncryptedElementType">
  <annotation>
   <documentation>
    This element MUST contain an encrypted version of an
    AuthnRequestExtension element within its xenc:EncryptedData
    sub-element.
   </documentation>
  </annotation>
 </element>
 <element name="AuthnRequestExtension" type="tns:AuthnRequestExtensionType" />
 <complexType name="AuthnRequestExtensionType">
  <sequence>
   <element name="RequestedAttributes" type="tns:RequestedAttributesType" />
  </sequence>
  <attribute name="Version" type="positiveInteger" use="required" />
  <anyAttribute namespace="##any" processContents="lax" />
 </complexType>
 <complexType name="RequestedAttributesType">
  <sequence>
   <element ref="saml:Attribute" minOccurs="0" maxOccurs="unbounded" />
  </sequence>
 </complexType>
 <!-- New defined Attribute since Version 1.5 -->
 <attribute name="RequiredAttribute" type="boolean" default="true" />
 <!-- New defined Types and Attributes since Version 2.0 -->
 <!-- No more Unions since 2.0.1 -->
 <simpleType name="AttributeRequestType">
  <restriction base="string">
   <enumeration value="REQUIRED" />
   <enumeration value="ALLOWED" />
   <enumeration value="PROHIBITED" />
  </restriction>
 </simpleType>
 <simpleType name="AttributeResponseType">
  <restriction base="string">
   <enumeration value="NOTONCHIP" />
   <enumeration value="ALLOWED" />
   <enumeration value="PROHIBITED" />
  </restriction>
 </simpleType>

 <attribute name="AttributeNotOnChip" type="boolean" default="false" />
 <complexType name="OperationsRequestorType">
  <sequence>
   <element name="DocumentType" type="tns:AttributeRequestType"
    default="PROHIBITED" />
   <element name="IssuingState" type="tns:AttributeRequestType"
    default="PROHIBITED" />
   <element name="DateOfExpiry" type="tns:AttributeRequestType"
    default="PROHIBITED" />
   <element name="GivenNames" type="tns:AttributeRequestType"
    default="PROHIBITED" />
   <element name="FamilyNames" type="tns:AttributeRequestType"
    default="PROHIBITED" />
   <element name="ArtisticName" type="tns:AttributeRequestType"
    default="PROHIBITED" />
   <element name="AcademicTitle"
    type="tns:AttributeRequestType" default="PROHIBITED" />
   <element name="DateOfBirth" type="tns:AttributeRequestType"
    default="PROHIBITED" />
   <element name="PlaceOfBirth" type="tns:AttributeRequestType"
    default="PROHIBITED" />
   <element name="Nationality" type="tns:AttributeRequestType"
    default="PROHIBITED" />
   <element name="BirthName" type="tns:AttributeRequestType"
    default="PROHIBITED" />
   <element name="PlaceOfResidence"
    type="tns:AttributeRequestType" default="PROHIBITED" />
   <element name="CommunityID" type="tns:AttributeRequestType" 
    default="PROHIBITED" />
   <element name="ResidencePermitI"
    type="tns:AttributeRequestType" default="PROHIBITED" />
   <element name="RestrictedID" type="tns:AttributeRequestType"
    default="PROHIBITED" />
   <element name="AgeVerification"
    type="tns:AttributeRequestType" default="PROHIBITED" />
   <element name="PlaceVerification"
    type="tns:AttributeRequestType" default="PROHIBITED" />
  </sequence>
 </complexType>
 <complexType name="OperationsResponderType">
  <sequence>
   <element name="DocumentType"
    type="tns:AttributeResponseType" default="PROHIBITED" />
   <element name="IssuingState"
    type="tns:AttributeResponseType" default="PROHIBITED" />
   <element name="DateOfExpiry"
    type="tns:AttributeResponseType" default="PROHIBITED" />
   <element name="GivenNames" type="tns:AttributeResponseType"
    default="PROHIBITED" />
   <element name="FamilyNames" type="tns:AttributeResponseType"
    default="PROHIBITED" />
   <element name="ArtisticName"
    type="tns:AttributeResponseType" default="PROHIBITED" />
   <element name="AcademicTitle"
    type="tns:AttributeResponseType" default="PROHIBITED" />
   <element name="DateOfBirth" type="tns:AttributeResponseType"
    default="PROHIBITED" />
   <element name="PlaceOfBirth"
    type="tns:AttributeResponseType" default="PROHIBITED" />
   <element name="Nationality" type="tns:AttributeResponseType"
    default="PROHIBITED" />
   <element name="BirthName" type="tns:AttributeResponseType"
    default="PROHIBITED" />
   <element name="PlaceOfResidence"
    type="tns:AttributeResponseType" default="PROHIBITED" />
   <element name="CommunityID" type="tns:AttributeResponseType" 
    default="PROHIBITED"/>
   <element name="ResidencePermitI"
    type="tns:AttributeResponseType" default="PROHIBITED" />
   <element name="RestrictedID"
    type="tns:AttributeResponseType" default="PROHIBITED" />
   <element name="AgeVerification"
    type="tns:AttributeResponseType" default="PROHIBITED" />
   <element name="PlaceVerification"
    type="tns:AttributeResponseType" default="PROHIBITED" />
  </sequence>
 </complexType>
 
 <!-- Additional types used in SAML AuthnRequest according to eIDAS since Version 2.1.0 -->
 
 <simpleType name="UseEidasType">
  <restriction base="boolean" />
 </simpleType>
 
 <simpleType name="LevelOfAssuranceType">
  <restriction base="anyURI">
   <enumeration value="http://eidas.europa.eu/LoA/low" />
   <enumeration value="http://eidas.europa.eu/LoA/substantial" />
   <enumeration value="http://eidas.europa.eu/LoA/high" />
   <enumeration value="http://bsi.bund.de/eID/LoA/normal" />
   <enumeration value="http://bsi.bund.de/eID/LoA/substantiell" />
   <enumeration value="http://bsi.bund.de/eID/LoA/hoch" />
   <enumeration value="http://bsi.bund.de/eID/LoA/undefined" />
  </restriction>
 </simpleType>

 <simpleType name="SendingMemberStateType">
  <restriction base="string">
   <pattern value="[A-Z]{2}" />
  </restriction>
 </simpleType>
 
 <simpleType name="ICAOSex">
  <restriction base="string">
   <enumeration value="M" />
   <enumeration value="F" />
   <enumeration value=" " />
  </restriction>
 </simpleType>
 
 <complexType name="EidasExtensionType">
  <sequence>
   <element name="LevelOfAssurance" type="tns:LevelOfAssuranceType"
    default="http://eidas.europa.eu/LoA/high" minOccurs="0"/>
   <element name="SendingMemberState" type="tns:SendingMemberStateType" minOccurs="0"/>
  </sequence>
 </complexType>

 <!-- Additional types used since Version 2.3.0 -->

 <complexType name="TransactionAttestationRequestType">
  <sequence>
   <element name="TransactionAttestationFormat" type="anyURI" />
   <element name="TransactionContext" type="string" />
  </sequence>
 </complexType>


 <complexType name="TransactionAttestationResponseType">
  <sequence>
   <element name="TransactionAttestationFormat" type="anyURI" />
   <element name="TransactionAttestationData"
    type="dss:AnyType" />
  </sequence>
 </complexType>


 <simpleType name="IdentityFlavourType">
  <restriction base="string">
   <enumeration value="NaturalPerson" />
   <enumeration value="LegalPerson" />
   <enumeration value="LegalPersonRepresentative" />
  </restriction>
 </simpleType>

 <!-- Additional types used since Version 2.4.0 -->
 <complexType name="EIDTypeRequestType">
  <sequence>
   <element name="CardCertified" type="tns:EIDTypeSelectionType" minOccurs="0" />
   <element name="SECertified" type="tns:EIDTypeSelectionType" minOccurs="0" />
   <element name="SEEndorsed" type="tns:EIDTypeSelectionType" minOccurs="0" />
   <element name="HWKeyStore" type="tns:EIDTypeSelectionType" minOccurs="0" />
  </sequence>
 </complexType>
 

 <complexType name="EIDTypeResponseType">
  <choice>
   <element name="CardCertified" type="tns:EIDTypeUsedType" />
   <element name="SECertified" type="tns:EIDTypeUsedType" />
   <element name="SEEndorsed" type="tns:EIDTypeUsedType" />
   <element name="HWKeyStore" type="tns:EIDTypeUsedType" />
  </choice>
 </complexType>
 

    <simpleType name="EIDTypeSelectionType">
     <restriction base="string">
      <enumeration value="ALLOWED"/>
      <enumeration value="DENIED"/>
     </restriction>
    </simpleType>

    <simpleType name="EIDTypeUsedType">
     <restriction base="string">
      <enumeration value="USED"/>
     </restriction>
    </simpleType>

    <simpleType name="CommunityIDType">
         <restriction base="string">
      <pattern
       value="[0][0-9]{3}([0-9]{2}([0][0-9]([0-9]{2}([0][0-9]{3})?)?)?)?" />
     </restriction>
    </simpleType>
</schema>


```
