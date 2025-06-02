use std::fmt;

/// Major result codes as defined in TR-03112 Part 1, Section A.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MajorCode {
    Ok,
    Warning,
    Error,
}

impl fmt::Display for MajorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok"),
            Self::Warning => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#warning"
            ),
            Self::Error => write!(f, "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error"),
        }
    }
}

/// Minor result codes as defined in TR-03112 Part 1, Section A.2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinorCode {
    // AL - General errors
    NoPermission,
    InternalError,
    ParameterError,
    UnknownAPIFunction,
    FrameworkError,

    // IFD - Interface device related errors
    InvalidContext,
    UnknownIFD,
    InvalidSlotHandle,
    CardError,
    UnknownAction,
    NotTerminated,
    Timeout,
    UnknownProtocol,
    CancellationByUser,
    IfdSharingViolation,
    UnknownChannel,
    InvalidChannel,

    // SAL - Service access layer errors
    SecurityConditionNotSatisfied,
    CommunicationError,

    // DP - Data presentation layer errors
    NotInitialized,

    // Key related errors
    KeyGenerationNotPossible,

    // DID related errors
    UnknownDID,
    AuthenticationFailed,

    // DSI related errors
    InvalidSignature,

    // Additional codes
    None, // Indicates no minor code is needed
}

impl fmt::Display for MinorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Special case for None
            Self::None => Ok(()),

            // AL - General errors
            Self::NoPermission => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#noPermission"
            ),
            Self::InternalError => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#internalError"
            ),
            Self::ParameterError => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#parameterError"
            ),
            Self::UnknownAPIFunction => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#unknownAPIFunction"
            ),
            Self::FrameworkError => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#frameworkError"
            ),

            // IFD - Interface device related errors
            Self::InvalidContext => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifd#invalidContext"
            ),
            Self::UnknownIFD => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifd#unknownIFD"
            ),
            Self::InvalidSlotHandle => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifd#invalidSlotHandle"
            ),
            Self::CardError => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifd#cardError"
            ),
            Self::UnknownAction => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifd#unknownAction"
            ),
            Self::NotTerminated => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifd#notTerminated"
            ),
            Self::Timeout => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifd#timeoutError"
            ),
            Self::UnknownProtocol => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifd#unknownProtocol"
            ),
            Self::CancellationByUser => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifd#cancellationByUser"
            ),
            Self::IfdSharingViolation => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifd#ifdSharingViolation"
            ),
            Self::UnknownChannel => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifd#unknownChannel"
            ),
            Self::InvalidChannel => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifd#invalidChannel"
            ),

            // SAL - Service access layer errors
            Self::SecurityConditionNotSatisfied => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al#securityConditionNotSatisfied"
            ),
            Self::CommunicationError => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#communicationError"
            ),

            // DP - Data presentation layer errors
            Self::NotInitialized => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#notInitialized"
            ),

            // Key related errors
            Self::KeyGenerationNotPossible => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/key#keyGenerationNotPossible"
            ),

            // DID related errors
            Self::UnknownDID => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#unknownDID"
            ),
            Self::AuthenticationFailed => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#authenticationFailed"
            ),

            // DSI related errors
            Self::InvalidSignature => write!(
                f,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/dsi#invalidSignature"
            ),
        }
    }
}
