import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import { motion } from "framer-motion";
import {
  CheckCircle2,
  XCircle,
  AlertCircle,
  Loader2,
  User,
  MapPin,
  Calendar,
  Shield,
  FileText,
  Home as HomeIcon,
  UserX,
  Server,
  Terminal,
} from "lucide-react";
import type { GetResultResponse, PersonalData } from "@/types/eid";
import { ICAOCountryCodes } from "@/lib/countryCodes";

// Error code mapping according to eID-Client spec
const ERROR_MAPPINGS = {
  trustedChannelEstablishmentFailed: {
    title: "Trusted Channel Establishment Failed",
    description:
      "The eID-Client failed to set up a trusted channel to the eID-Server.",
    icon: "Shield",
    color: "text-red-600",
    bgColor: "bg-red-50",
  },
  cancellationByUser: {
    title: "Authentication Cancelled by User",
    description:
      "The user aborted the authentication. This includes abortion due to entering a wrong PIN or no card present.",
    icon: "UserX",
    color: "text-orange-600",
    bgColor: "bg-orange-50",
  },
  serverError: {
    title: "eID-Server Error",
    description:
      "The eID-Server encountered an error. The exact error is communicated to the eService directly by the eID-Server.",
    icon: "Server",
    color: "text-red-600",
    bgColor: "bg-red-50",
  },
  clientError: {
    title: "Client Error",
    description: "Any error not covered by the other error codes occurred.",
    icon: "Terminal",
    color: "text-purple-600",
    bgColor: "bg-purple-50",
  },
};

// TLS Alert Descriptions according to RFC 5246
const TLS_ALERT_DESCRIPTIONS = {
  close_notify: "The connection was closed unexpectedly.",
  unexpected_message: "An inappropriate message was received.",
  bad_record_mac: "The record MAC is incorrect.",
  decryption_failed: "A ciphertext could not be decrypted.",
  record_overflow: "The record length is too long.",
  decompression_failure: "The decompression function received improper input.",
  handshake_failure:
    "The sender was unable to negotiate an acceptable set of security parameters.",
  no_certificate: "No certificate was provided when required.",
  bad_certificate:
    "A certificate was corrupt, contained signatures that did not verify correctly, etc.",
  unsupported_certificate: "A certificate was of an unsupported type.",
  certificate_revoked: "A certificate was revoked by its signer.",
  certificate_expired: "A certificate has expired or is not currently valid.",
  certificate_unknown:
    "Some other (unspecified) issue arose in processing the certificate.",
  illegal_parameter:
    "A field in the handshake was out of range or inconsistent with other fields.",
  unknown_ca:
    "A valid certificate chain or partial chain was received, but the certificate was not accepted because the CA certificate could not be located or could not be matched with a known, trusted CA.",
  access_denied:
    "A valid certificate was received, but when access control was applied, the sender decided not to proceed with negotiation.",
  decode_error:
    "A message could not be decoded because some field was out of the specified range or the length of the message was incorrect.",
  decrypt_error:
    "A handshake cryptographic operation failed, including being unable to correctly verify a signature or validate a Finished message.",
  export_restriction:
    "A negotiation not in compliance with export restrictions was detected.",
  protocol_version:
    "The protocol version the client has attempted to negotiate is recognized but not supported.",
  insufficient_security:
    "The server requires ciphers more secure than those supported by the client.",
  internal_error: "An internal error occurred.",
  user_canceled:
    "The handshake was canceled for some reason unrelated to a protocol failure.",
  no_renegotiation: "The server refused to renegotiate the connection.",
};

interface ResultData {
  success: boolean;
  result: {
    ResultMajor: string;
    ResultMinor?: string;
    ResultMessage?: string;
  };
  personalData?: PersonalData;
  ageVerification?: { FulfilsRequest: boolean };
  placeVerification?: { FulfilsRequest: boolean };
  operationsAllowed?: { [key: string]: string };
  transactionAttestation?: any;
  levelOfAssurance?: string;
  eidType?: any;
  config?: any;
}

export default function Results() {
  const router = useRouter();
  const { token } = router.query;
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<{
    message: string;
    cause?: any;
    description?: string;
  } | null>(null);
  const [resultData, setResultData] = useState<ResultData | null>(null);

  useEffect(() => {
    if (!token) return;

    const fetchResult = async () => {
      try {
        const response = await fetch(`/api/auth/result?token=${token}`);

        if (!response.ok) {
          const errorData = await response.json();
          setError({
            message: errorData.error || "Failed to fetch result",
            cause: errorData.cause,
            description: errorData.description,
          });
          return;
        }

        const data = await response.json();
        setResultData(data);
      } catch (err: any) {
        setError({ message: err.message });
      } finally {
        setLoading(false);
      }
    };

    fetchResult();
  }, [token]);

  const getCountryName = (code?: string) => {
    if (!code) return "N/A";
    return ICAOCountryCodes[code] || code;
  };

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return "N/A";

    // Handle YYYY-MM-DD format
    if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
      try {
        return new Date(dateStr).toLocaleDateString("en-GB", {
          day: "2-digit",
          month: "2-digit",
          year: "numeric",
        });
      } catch {
        return dateStr;
      }
    }

    // Handle YYYYMMDD format
    if (/^\d{8}$/.test(dateStr)) {
      try {
        const year = dateStr.substring(0, 4);
        const month = dateStr.substring(4, 6);
        const day = dateStr.substring(6, 8);
        return `${day}/${month}/${year}`;
      } catch {
        return dateStr;
      }
    }

    return dateStr;
  };

  const getErrorInfo = (resultMinor?: string) => {
    if (!resultMinor) return null;

    const errorKey = Object.keys(ERROR_MAPPINGS).find((key) =>
      resultMinor.toLowerCase().includes(key.toLowerCase()),
    );

    return errorKey
      ? ERROR_MAPPINGS[errorKey as keyof typeof ERROR_MAPPINGS]
      : null;
  };

  const getTLSAlertInfo = (resultMessage?: string) => {
    if (!resultMessage) return null;

    // Check if the result message contains a TLS alert description
    const tlsAlert = Object.keys(TLS_ALERT_DESCRIPTIONS).find((key) =>
      resultMessage.toLowerCase().includes(key.toLowerCase()),
    );

    return tlsAlert
      ? TLS_ALERT_DESCRIPTIONS[tlsAlert as keyof typeof TLS_ALERT_DESCRIPTIONS]
      : null;
  };

  const getStatusBadge = (status: string) => {
    const badges = {
      ALLOWED: { bg: "bg-green-100", text: "text-green-800", label: "Allowed" },
      PROHIBITED: {
        bg: "bg-red-100",
        text: "text-red-800",
        label: "Prohibited",
      },
      NOTONCHIP: {
        bg: "bg-orange-100",
        text: "text-orange-800",
        label: "Not on Chip",
      },
    };

    const badge = badges[status as keyof typeof badges] || badges.PROHIBITED;

    return (
      <span
        className={`px-3 py-1 rounded-full text-xs font-medium ${badge.bg} ${badge.text}`}
      >
        {badge.label}
      </span>
    );
  };

  const getLevelOfAssuranceName = (loa: string) => {
    const mapping: { [key: string]: string } = {
      "http://eidas.europa.eu/LoA/low": "eIDAS Low",
      "http://eidas.europa.eu/LoA/substantial": "eIDAS Substantial",
      "http://eidas.europa.eu/LoA/high": "eIDAS High",
      "http://bsi.bund.de/eID/LoA/normal": "BSI Normal",
      "http://bsi.bund.de/eID/LoA/substantiell": "BSI Substantiell",
      "http://bsi.bund.de/eID/LoA/hoch": "BSI Hoch",
    };
    return mapping[loa] || loa;
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-b from-gray-50 to-white flex items-center justify-center">
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          className="text-center"
        >
          <Loader2 className="w-16 h-16 text-blue-600 animate-spin mx-auto mb-4" />
          <p className="text-xl text-gray-700 font-medium">
            Retrieving authentication results...
          </p>
        </motion.div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gradient-to-b from-gray-50 to-white flex items-center justify-center p-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="max-w-2xl w-full bg-white rounded-3xl shadow-xl border border-red-200 p-8"
        >
          <div className="flex items-center gap-4 mb-6">
            <XCircle className="w-12 h-12 text-red-600" />
            <h1 className="text-3xl font-semibold text-gray-900">
              Authentication Failed
            </h1>
          </div>

          {/* Basic error message */}
          <p className="text-lg text-gray-700 mb-8">{error.message}</p>
          {error.description && (
            <div className="mb-4 p-4 bg-red-50 border-l-4 border-red-400">
              <h3 className="font-bold text-red-800">Description</h3>
              <p className="text-red-700">{error.description}</p>
            </div>
          )}
          {error.cause && (
            <div className="mb-4 p-4 bg-gray-100 rounded">
              <h3 className="font-bold text-gray-800">Cause</h3>
              <pre className="text-sm text-gray-600 whitespace-pre-wrap">
                {JSON.stringify(error.cause, null, 2)}
              </pre>
            </div>
          )}

          {/* If we have result data with error details, show them */}
          {resultData && !resultData.success && resultData.result && (
            <div className="mb-8 space-y-4">
              {/* Error Type Information */}
              {(() => {
                const errorInfo = getErrorInfo(resultData.result.ResultMinor);
                const minorFragment =
                  resultData.result.ResultMinor?.split("#").pop();

                if (errorInfo) {
                  const IconComponent =
                    errorInfo.icon === "Shield"
                      ? Shield
                      : errorInfo.icon === "UserX"
                        ? UserX
                        : errorInfo.icon === "Server"
                          ? Server
                          : errorInfo.icon === "Terminal"
                            ? Terminal
                            : AlertCircle;
                  return (
                    <div
                      className={`p-4 rounded-lg ${errorInfo.bgColor} border-l-4 border-red-400`}
                    >
                      <div className="flex items-center gap-3 mb-2">
                        <IconComponent
                          className={`w-6 h-6 ${errorInfo.color}`}
                        />
                        <h3 className="text-lg font-semibold text-gray-900">
                          {errorInfo.title}
                        </h3>
                      </div>
                      <p className="text-gray-700">{errorInfo.description}</p>
                    </div>
                  );
                }

                // Render enriched context for direct eID-Server errors
                return (
                  <div className="p-4 rounded-lg bg-red-50 border-l-4 border-red-400">
                    <div className="flex items-center gap-3 mb-2">
                      <Server className="w-6 h-6 text-red-600" />
                      <h3 className="text-lg font-semibold text-gray-900">
                        eID-Server Error
                      </h3>
                    </div>
                    {resultData.result.ResultMessage && (
                      <p className="text-gray-700">
                        {resultData.result.ResultMessage}
                      </p>
                    )}
                    {minorFragment && (
                      <div className="mt-2">
                        <span className="text-xs font-semibold bg-red-200 text-red-800 px-2 py-1 rounded">
                          {minorFragment}
                        </span>
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* Technical Details */}
              <div className="bg-gray-50 rounded-lg p-4">
                <h4 className="text-sm font-semibold text-gray-700 mb-2">
                  Technical Details
                </h4>
                <div className="space-y-1 text-sm">
                  {resultData.result.ResultMinor && (
                    <div>
                      <span className="font-medium">Result Minor:</span>{" "}
                      <span className="font-mono">
                        {resultData.result.ResultMinor}
                      </span>
                    </div>
                  )}
                  {resultData.result.ResultMessage && (
                    <div>
                      <span className="font-medium">Message:</span>{" "}
                      {resultData.result.ResultMessage}
                    </div>
                  )}
                  {(() => {
                    const tlsAlertInfo = getTLSAlertInfo(
                      resultData.result.ResultMessage,
                    );
                    return tlsAlertInfo ? (
                      <div>
                        <span className="font-medium">TLS Alert:</span>{" "}
                        {tlsAlertInfo}
                      </div>
                    ) : null;
                  })()}
                </div>
              </div>
            </div>
          )}

          <button
            onClick={() => router.push("/")}
            className="px-6 py-3 bg-blue-600 text-white rounded-full font-medium hover:bg-blue-700 transition-colors"
          >
            Return to Home
          </button>
        </motion.div>
      </div>
    );
  }

  if (!resultData) {
    return null;
  }

  const {
    success,
    result,
    personalData,
    ageVerification,
    placeVerification,
    operationsAllowed,
    transactionAttestation,
    levelOfAssurance,
    eidType,
  } = resultData;

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-50 to-white">
      {/* Header */}
      <header className="py-8 px-6 border-b border-gray-200">
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="max-w-6xl mx-auto"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {success ? (
                <CheckCircle2 className="w-10 h-10 text-green-600" />
              ) : (
                <XCircle className="w-10 h-10 text-red-600" />
              )}
              <div>
                <h1 className="text-4xl font-semibold text-gray-900">
                  Authentication {success ? "Successful" : "Failed"}
                </h1>
              </div>
            </div>
            <button
              onClick={() => router.push("/")}
              className="flex items-center gap-2 px-4 py-2 bg-gray-100 hover:bg-gray-200 rounded-full text-gray-700 font-medium transition-colors"
            >
              <HomeIcon className="w-5 h-5" />
              New Request
            </button>
          </div>
        </motion.div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-12">
        {/* Error Details - Show when authentication fails */}
        {!success && result && (
          <motion.section
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-8 bg-white rounded-3xl shadow-sm border border-red-200 p-8"
          >
            <div className="flex items-center gap-3 mb-6">
              <AlertCircle className="w-6 h-6 text-red-600" />
              <h2 className="text-2xl font-semibold text-gray-900">
                Error Details
              </h2>
            </div>

            <div className="space-y-4">
              {/* Error Type Information */}
              {(() => {
                const errorInfo = getErrorInfo(result.ResultMinor);
                const minorFragment = result.ResultMinor?.split("#").pop();

                if (errorInfo) {
                  const IconComponent =
                    errorInfo.icon === "Shield"
                      ? Shield
                      : errorInfo.icon === "UserX"
                        ? UserX
                        : errorInfo.icon === "Server"
                          ? Server
                          : errorInfo.icon === "Terminal"
                            ? Terminal
                            : AlertCircle;
                  return (
                    <div
                      className={`p-4 rounded-lg ${errorInfo.bgColor} border-l-4 border-red-400`}
                    >
                      <div className="flex items-center gap-3 mb-2">
                        <IconComponent
                          className={`w-6 h-6 ${errorInfo.color}`}
                        />
                        <h3 className="text-lg font-semibold text-gray-900">
                          {errorInfo.title}
                        </h3>
                      </div>
                      <p className="text-gray-700">{errorInfo.description}</p>
                    </div>
                  );
                }

                // Render enriched context for direct eID-Server errors
                return (
                  <div className="p-4 rounded-lg bg-red-50 border-l-4 border-red-400">
                    <div className="flex items-center gap-3 mb-2">
                      <Server className="w-6 h-6 text-red-600" />
                      <h3 className="text-lg font-semibold text-gray-900">
                        eID-Server Error
                      </h3>
                    </div>
                    {result.ResultMessage && (
                      <p className="text-gray-700">{result.ResultMessage}</p>
                    )}
                    {minorFragment && (
                      <div className="mt-2">
                        <span className="text-xs font-semibold bg-red-200 text-red-800 px-2 py-1 rounded">
                          {minorFragment}
                        </span>
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* Technical Details */}
              <div className="bg-gray-50 rounded-lg p-4">
                <h4 className="text-sm font-semibold text-gray-700 mb-2">
                  Technical Details
                </h4>
                <div className="space-y-1 text-sm">
                  {result.ResultMinor && (
                    <div>
                      <span className="font-medium">Result Minor:</span>{" "}
                      <span className="font-mono">{result.ResultMinor}</span>
                    </div>
                  )}
                  {result.ResultMessage && (
                    <div>
                      <span className="font-medium">Message:</span>{" "}
                      {result.ResultMessage}
                    </div>
                  )}
                  {(() => {
                    const tlsAlertInfo = getTLSAlertInfo(result.ResultMessage);
                    return tlsAlertInfo ? (
                      <div>
                        <span className="font-medium">TLS Alert:</span>{" "}
                        {tlsAlertInfo}
                      </div>
                    ) : null;
                  })()}
                </div>
              </div>
            </div>
          </motion.section>
        )}

        {/* Personal Data */}
        {personalData && (
          <motion.section
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="mb-8 bg-white rounded-3xl shadow-sm border border-gray-200 p-8"
          >
            <div className="flex items-center gap-3 mb-6">
              <User className="w-6 h-6 text-blue-600" />
              <h2 className="text-2xl font-semibold text-gray-900">
                Personal Information
              </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {personalData.GivenNames && (
                <DataField
                  label="Given Names"
                  value={personalData.GivenNames}
                />
              )}
              {personalData.FamilyNames && (
                <DataField
                  label="Family Names"
                  value={personalData.FamilyNames}
                />
              )}
              {personalData.BirthName && (
                <DataField label="Birth Name" value={personalData.BirthName} />
              )}
              {personalData.ArtisticName && (
                <DataField
                  label="Artistic Name"
                  value={personalData.ArtisticName}
                />
              )}
              {personalData.AcademicTitle && (
                <DataField
                  label="Academic Title"
                  value={personalData.AcademicTitle}
                />
              )}
              {personalData.DateOfBirth && (
                <DataField
                  label="Date of Birth"
                  value={formatDate(
                    personalData.DateOfBirth.DateValue ||
                      personalData.DateOfBirth.DateString,
                  )}
                  icon={<Calendar className="w-5 h-5 text-gray-400" />}
                />
              )}
              {personalData.PlaceOfBirth && (
                <DataField
                  label="Place of Birth"
                  value={
                    personalData.PlaceOfBirth.FreetextPlace ||
                    personalData.PlaceOfBirth.StructuredPlace?.City ||
                    "Unknown"
                  }
                  icon={<MapPin className="w-5 h-5 text-gray-400" />}
                />
              )}
              {personalData.Nationality && (
                <DataField
                  label="Nationality"
                  value={getCountryName(personalData.Nationality)}
                />
              )}
              {personalData.CommunityID && (
                <DataField
                  label="Community ID"
                  value={personalData.CommunityID}
                />
              )}
              {personalData.RestrictedID && (
                <DataField
                  label="Restricted ID"
                  value={personalData.RestrictedID.ID}
                />
              )}
            </div>
          </motion.section>
        )}

        {/* Document Information */}
        {personalData &&
          (personalData.DocumentType ||
            personalData.IssuingState ||
            personalData.DateOfExpiry) && (
            <motion.section
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
              className="mb-8 bg-white rounded-3xl shadow-sm border border-gray-200 p-8"
            >
              <div className="flex items-center gap-3 mb-6">
                <FileText className="w-6 h-6 text-purple-600" />
                <h2 className="text-2xl font-semibold text-gray-900">
                  Document Information
                </h2>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {personalData.DocumentType && (
                  <DataField
                    label="Document Type"
                    value={personalData.DocumentType}
                  />
                )}
                {personalData.IssuingState && (
                  <DataField
                    label="Issuing State"
                    value={getCountryName(personalData.IssuingState)}
                  />
                )}
                {personalData.DateOfExpiry && (
                  <DataField
                    label="Date of Expiry"
                    value={formatDate(personalData.DateOfExpiry)}
                    icon={<Calendar className="w-5 h-5 text-gray-400" />}
                  />
                )}
              </div>
            </motion.section>
          )}

        {/* Residence Information */}
        {personalData && personalData.PlaceOfResidence && (
          <motion.section
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="mb-8 bg-white rounded-3xl shadow-sm border border-gray-200 p-8"
          >
            <div className="flex items-center gap-3 mb-6">
              <HomeIcon className="w-6 h-6 text-green-600" />
              <h2 className="text-2xl font-semibold text-gray-900">
                Residence Information
              </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {personalData.PlaceOfResidence.StructuredPlace && (
                <>
                  <DataField
                    label="Street"
                    value={
                      personalData.PlaceOfResidence.StructuredPlace.Street ||
                      "N/A"
                    }
                  />
                  <DataField
                    label="City"
                    value={personalData.PlaceOfResidence.StructuredPlace.City}
                  />
                  <DataField
                    label="Country"
                    value={getCountryName(
                      personalData.PlaceOfResidence.StructuredPlace.Country,
                    )}
                  />
                  <DataField
                    label="Zip Code"
                    value={
                      personalData.PlaceOfResidence.StructuredPlace.ZipCode ||
                      "N/A"
                    }
                  />
                </>
              )}
              {personalData.PlaceOfResidence.FreetextPlace && (
                <DataField
                  label="Place of Residence"
                  value={personalData.PlaceOfResidence.FreetextPlace}
                />
              )}
            </div>
          </motion.section>
        )}

        {/* Verification Results */}
        {(ageVerification || placeVerification) && (
          <motion.section
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="mb-8 bg-white rounded-3xl shadow-sm border border-gray-200 p-8"
          >
            <div className="flex items-center gap-3 mb-6">
              <Shield className="w-6 h-6 text-orange-600" />
              <h2 className="text-2xl font-semibold text-gray-900">
                Verification Results
              </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {ageVerification && (
                <VerificationField
                  label="Age Verification"
                  fulfilled={ageVerification.FulfilsRequest}
                  icon={<Calendar className="w-5 h-5 text-gray-400" />}
                />
              )}
              {placeVerification && (
                <VerificationField
                  label="Place Verification"
                  fulfilled={placeVerification.FulfilsRequest}
                  icon={<MapPin className="w-5 h-5 text-gray-400" />}
                />
              )}
            </div>
          </motion.section>
        )}

        {/* Operations Allowed */}
        {operationsAllowed && (
          <motion.section
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
            className="mb-8 bg-white rounded-3xl shadow-sm border border-gray-200 p-8"
          >
            <div className="flex items-center gap-3 mb-6">
              <AlertCircle className="w-6 h-6 text-blue-600" />
              <h2 className="text-2xl font-semibold text-gray-900">
                Operations Allowed by User
              </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {Object.entries(operationsAllowed).map(([key, status]) => (
                <div
                  key={key}
                  className="flex items-center justify-between p-3 rounded-lg bg-gray-50"
                >
                  <span className="text-sm font-medium text-gray-700">
                    {key
                      .replace(/([A-Z])/g, " $1")
                      .replace(/ I D/g, " ID")
                      .trim()}
                  </span>
                  {getStatusBadge(status)}
                </div>
              ))}
            </div>
          </motion.section>
        )}

        {/* Additional Information */}
        {(levelOfAssurance || eidType || transactionAttestation) && (
          <motion.section
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.6 }}
            className="mb-8 bg-white rounded-3xl shadow-sm border border-gray-200 p-8"
          >
            <div className="flex items-center gap-3 mb-6">
              <FileText className="w-6 h-6 text-purple-600" />
              <h2 className="text-2xl font-semibold text-gray-900">
                Additional Information
              </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {levelOfAssurance && (
                <DataField
                  label="Level of Assurance"
                  value={getLevelOfAssuranceName(levelOfAssurance)}
                />
              )}
              {eidType && (
                <DataField
                  label="eID Type Used"
                  value={
                    Object.keys(eidType).find(
                      (key) => eidType[key] === "USED",
                    ) || "Unknown"
                  }
                />
              )}
              {transactionAttestation && (
                <DataField
                  label="Transaction Attestation"
                  value={transactionAttestation.TransactionAttestationFormat}
                />
              )}
            </div>
          </motion.section>
        )}
      </main>
    </div>
  );
}

// Helper Components
interface DataFieldProps {
  label: string;
  value?: string;
  icon?: React.ReactNode;
}

function DataField({ label, value, icon }: DataFieldProps) {
  if (!value) return null;

  return (
    <div className="p-4 rounded-lg bg-gray-50">
      <div className="flex items-center gap-2 mb-1">
        {icon}
        <span className="text-sm font-medium text-gray-600">{label}</span>
      </div>
      <p className="text-lg font-semibold text-gray-900">{value}</p>
    </div>
  );
}

interface VerificationFieldProps {
  label: string;
  fulfilled: boolean;
  icon?: React.ReactNode;
}

function VerificationField({ label, fulfilled, icon }: VerificationFieldProps) {
  return (
    <div className="p-4 rounded-lg bg-gray-50">
      <div className="flex items-center gap-2 mb-2">
        {icon}
        <span className="text-sm font-medium text-gray-600">{label}</span>
      </div>
      <div className="flex items-center gap-2">
        {fulfilled ? (
          <CheckCircle2 className="w-5 h-5 text-green-600" />
        ) : (
          <XCircle className="w-5 h-5 text-red-600" />
        )}
        <span
          className={`font-semibold ${fulfilled ? "text-green-900" : "text-red-900"}`}
        >
          {fulfilled ? "Fulfilled" : "Not Fulfilled"}
        </span>
      </div>
    </div>
  );
}
