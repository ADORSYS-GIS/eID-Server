export type AttributeRequestType = 'REQUIRED' | 'ALLOWED' | 'PROHIBITED';
export type AttributeResponseType = 'ALLOWED' | 'PROHIBITED' | 'NOTONCHIP';
export type EIDTypeSelection = 'ALLOWED' | 'DENIED';
export type LevelOfAssurance =
    | 'http://eidas.europa.eu/LoA/low'
    | 'http://eidas.europa.eu/LoA/substantial'
    | 'http://eidas.europa.eu/LoA/high'
    | 'http://bsi.bund.de/eID/LoA/normal'
    | 'http://bsi.bund.de/eID/LoA/substantiell'
    | 'http://bsi.bund.de/eID/LoA/hoch';

export interface OperationsRequest {
    DocumentType: AttributeRequestType;
    IssuingState: AttributeRequestType;
    DateOfExpiry: AttributeRequestType;
    GivenNames: AttributeRequestType;
    FamilyNames: AttributeRequestType;
    ArtisticName: AttributeRequestType;
    AcademicTitle: AttributeRequestType;
    DateOfBirth: AttributeRequestType;
    PlaceOfBirth: AttributeRequestType;
    Nationality: AttributeRequestType;
    BirthName: AttributeRequestType;
    PlaceOfResidence: AttributeRequestType;
    CommunityID: AttributeRequestType;
    ResidencePermitI: AttributeRequestType;
    RestrictedID: AttributeRequestType;
    AgeVerification: AttributeRequestType;
    PlaceVerification: AttributeRequestType;
}

export interface AgeVerificationRequest {
    age: number;
}

export interface PlaceVerificationRequest {
    communityId: string;
}

export interface TransactionAttestationRequest {
    format: string;
    context: string;
}

export interface TransactionInfo {
    info: string;
}

export interface EIDTypeRequest {
    CardCertified?: EIDTypeSelection;
    SECertified?: EIDTypeSelection;
    SEEndorsed?: EIDTypeSelection;
    HWKeyStore?: EIDTypeSelection;
}

export interface AuthenticationConfig {
    operations: OperationsRequest;
    ageVerification?: AgeVerificationRequest;
    placeVerification?: PlaceVerificationRequest;
    transactionAttestation?: TransactionAttestationRequest;
    transactionInfo?: TransactionInfo;
    levelOfAssurance?: LevelOfAssurance;
    eidTypeRequest: EIDTypeRequest;
}

export interface UseIDResponse {
    Session: {
        ID: string;
    };
    PSK: {
        ID: string;
        Key: string;
    };
    eCardServerAddress?: string;
    Result: {
        ResultMajor: string;
        ResultMinor?: string;
        ResultMessage?: string;
    };
}

export interface PersonalData {
    DocumentType?: string;
    IssuingState?: string;
    DateOfExpiry?: string;
    GivenNames?: string;
    FamilyNames?: string;
    ArtisticName?: string;
    AcademicTitle?: string;
    DateOfBirth?: {
        DateString: string;
        DateValue?: string;
    };
    PlaceOfBirth?: {
        StructuredPlace?: {
            Street?: string;
            City: string;
            State?: string;
            Country: string;
            ZipCode?: string;
        };
        FreetextPlace?: string;
        NoPlaceInfo?: string;
    };
    Nationality?: string;
    BirthName?: string;
    PlaceOfResidence?: {
        StructuredPlace?: {
            Street?: string;
            City: string;
            State?: string;
            Country: string;
            ZipCode?: string;
        };
        FreetextPlace?: string;
    };
    CommunityID?: string;
    ResidencePermitI?: string;
    RestrictedID?: {
        ID: string;
        ID2?: string;
    };
}

export interface GetResultResponse {
    PersonalData?: PersonalData;
    FulfilsAgeVerification?: {
        FulfilsRequest: boolean;
    };
    FulfilsPlaceVerification?: {
        FulfilsRequest: boolean;
    };
    OperationsAllowedByUser?: {
        [key: string]: AttributeResponseType;
    };
    TransactionAttestationResponse?: {
        TransactionAttestationFormat: string;
        TransactionAttestationData: string;
    };
    LevelOfAssuranceResult?: LevelOfAssurance;
    EIDTypeResponse?: {
        CardCertified?: 'USED';
        SECertified?: 'USED';
        SEEndorsed?: 'USED';
        HWKeyStore?: 'USED';
    };
    Result: {
        ResultMajor: string;
        ResultMinor?: string;
        ResultMessage?: string;
    };
}

export interface SessionData {
    sessionId: string;
    pskId: string;
    pskKey: string;
    eCardServerAddress?: string;
    config: AuthenticationConfig;
    startTime: number;
    resultMajor?: string;
    resultMinor?: string;
}