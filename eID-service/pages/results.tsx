import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';
import { motion } from 'framer-motion';
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
  Home as HomeIcon
} from 'lucide-react';
import type { GetResultResponse, PersonalData } from '@/types/eid';

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
  const [error, setError] = useState<string | null>(null);
  const [resultData, setResultData] = useState<ResultData | null>(null);

  useEffect(() => {
    if (!token) return;

    const fetchResult = async () => {
      try {
        const response = await fetch(`/api/auth/result?token=${token}`);
        
        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.error || 'Failed to fetch result');
        }

        const data = await response.json();
        setResultData(data);
      } catch (err: any) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchResult();
  }, [token]);

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return 'N/A';
    try {
      return new Date(dateStr).toLocaleDateString('en-GB', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
      });
    } catch {
      return dateStr;
    }
  };

  const getStatusBadge = (status: string) => {
    const badges = {
      ALLOWED: { bg: 'bg-green-100', text: 'text-green-800', label: 'Allowed' },
      PROHIBITED: { bg: 'bg-red-100', text: 'text-red-800', label: 'Prohibited' },
      NOTONCHIP: { bg: 'bg-gray-100', text: 'text-gray-800', label: 'Not on Chip' },
    };
    
    const badge = badges[status as keyof typeof badges] || badges.PROHIBITED;
    
    return (
      <span className={`px-3 py-1 rounded-full text-xs font-medium ${badge.bg} ${badge.text}`}>
        {badge.label}
      </span>
    );
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
          <p className="text-lg text-gray-700 mb-8">{error}</p>
          <button
            onClick={() => router.push('/')}
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

  const { success, result, personalData, ageVerification, placeVerification, operationsAllowed, transactionAttestation, levelOfAssurance, eidType } = resultData;

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
                  Authentication {success ? 'Successful' : 'Failed'}
                </h1>
                <p className="text-sm text-gray-600 mt-1">
                  {result.ResultMajor}
                </p>
              </div>
            </div>
            <button
              onClick={() => router.push('/')}
              className="flex items-center gap-2 px-4 py-2 bg-gray-100 hover:bg-gray-200 rounded-full text-gray-700 font-medium transition-colors"
            >
              <HomeIcon className="w-5 h-5" />
              New Request
            </button>
          </div>
        </motion.div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-12">
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

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {personalData.GivenNames && (
                <DataField label="Given Names" value={personalData.GivenNames} />
              )}
              {personalData.FamilyNames && (
                <DataField label="Family Names" value={personalData.FamilyNames} />
              )}
              {personalData.BirthName && (
                <DataField label="Birth Name" value={personalData.BirthName} />
              )}
              {personalData.ArtisticName && (
                <DataField label="Artistic Name" value={personalData.ArtisticName} />
              )}
              {personalData.AcademicTitle && (
                <DataField label="Academic Title" value={personalData.AcademicTitle} />
              )}
              {personalData.DateOfBirth && (
                <DataField 
                  label="Date of Birth" 
                  value={personalData.DateOfBirth.DateValue || personalData.DateOfBirth.DateString}
                  icon={<Calendar className="w-5 h-5 text-gray-400" />}
                />
              )}
              {personalData.PlaceOfBirth && (
                <DataField 
                  label="Place of Birth" 
                  value={
                    personalData.PlaceOfBirth.FreetextPlace || 
                    personalData.PlaceOfBirth.StructuredPlace?.City ||
                    'Unknown'
                  }
                  icon={<MapPin className="w-5 h-5 text-gray-400" />}
                />
              )}
              {personalData.Nationality && (
                <DataField label="Nationality" value={personalData.Nationality} />
              )}
            </div>
          </motion.section>
        )}

        {/* Document Information */}
        {personalData && (personalData.DocumentType || personalData.IssuingState || personalData.DateOfExpiry) && (
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

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {personalData.DocumentType && (
                <DataField label="Document Type" value={personalData.DocumentType} />
              )}
              {personalData.IssuingState && (
                <DataField label="Issuing State" value={personalData.IssuingState} />
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

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {personalData.PlaceOfResidence.StructuredPlace && (
                <>
                  <DataField
                    label="Street"
                    value={personalData.PlaceOfResidence.StructuredPlace.Street || 'N/A'}
                  />
                  <DataField
                    label="City"
                    value={personalData.PlaceOfResidence.StructuredPlace.City}
                  />
                  <DataField
                    label="Country"
                    value={personalData.PlaceOfResidence.StructuredPlace.Country}
                  />
                  <DataField
                    label="Zip Code"
                    value={personalData.PlaceOfResidence.StructuredPlace.ZipCode || 'N/A'}
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

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
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

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {Object.entries(operationsAllowed).map(([key, status]) => (
                <div key={key} className="flex items-center justify-between p-3 rounded-lg bg-gray-50">
                  <span className="text-sm font-medium text-gray-700">
                    {key.replace(/([A-Z])/g, ' $1').trim()}
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

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {levelOfAssurance && (
                <DataField label="Level of Assurance" value={levelOfAssurance} />
              )}
              {eidType && (
                <DataField
                  label="eID Type Used"
                  value={Object.keys(eidType).find(key => eidType[key] === 'USED') || 'Unknown'}
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
        <span className={`font-semibold ${fulfilled ? 'text-green-900' : 'text-red-900'}`}>
          {fulfilled ? 'Fulfilled' : 'Not Fulfilled'}
        </span>
      </div>
    </div>
  );
}