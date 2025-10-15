import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';
import { motion } from 'framer-motion';
import { 
  XCircle, 
  AlertCircle, 
  Shield, 
  UserX, 
  Server, 
  Terminal,
  Home as HomeIcon,
  RefreshCw
} from 'lucide-react';

interface ErrorDetails {
  resultMajor: string;
  resultMinor?: string;
  resultMessage?: string;
  tlsAlertDescription?: string;
}

// Error code mapping according to eID-Client spec
const ERROR_MAPPINGS = {
  'trustedChannelEstablishmentFailed': {
    title: 'Trusted Channel Establishment Failed',
    description: 'The eID-Client failed to set up a trusted channel to the eID-Server.',
    icon: Shield,
    color: 'text-red-600',
    bgColor: 'bg-red-50'
  },
  'cancellationByUser': {
    title: 'Authentication Cancelled by User',
    description: 'The user aborted the authentication. This includes abortion due to entering a wrong PIN or no card present.',
    icon: UserX,
    color: 'text-orange-600',
    bgColor: 'bg-orange-50'
  },
  'serverError': {
    title: 'eID-Server Error',
    description: 'The eID-Server encountered an error. The exact error is communicated to the eService directly by the eID-Server.',
    icon: Server,
    color: 'text-red-600',
    bgColor: 'bg-red-50'
  },
  'clientError': {
    title: 'Client Error',
    description: 'Any error not covered by the other error codes occurred.',
    icon: Terminal,
    color: 'text-purple-600',
    bgColor: 'bg-purple-50'
  }
};

function getErrorInfo(resultMinor?: string) {
  if (!resultMinor) return null;
  
  const errorKey = Object.keys(ERROR_MAPPINGS).find(key => 
    resultMinor.toLowerCase().includes(key.toLowerCase())
  );
  
  return errorKey ? ERROR_MAPPINGS[errorKey as keyof typeof ERROR_MAPPINGS] : null;
}

export default function ErrorPage() {
  const router = useRouter();
  const { token, ResultMajor, ResultMinor, ResultMessage, ResultMessageTLS } = router.query;
  const [errorDetails, setErrorDetails] = useState<ErrorDetails | null>(null);

  useEffect(() => {
    // Check if we have error details from the URL query parameters
    if (ResultMajor && typeof ResultMajor === 'string') {
      setErrorDetails({
        resultMajor: ResultMajor,
        resultMinor: typeof ResultMinor === 'string' ? ResultMinor : undefined,
        resultMessage: typeof ResultMessage === 'string' ? ResultMessage : undefined,
        tlsAlertDescription: typeof ResultMessageTLS === 'string' ? ResultMessageTLS : undefined,
      });
    }
  }, [ResultMajor, ResultMinor, ResultMessage, ResultMessageTLS]);

  const errorInfo = errorDetails ? getErrorInfo(errorDetails.resultMinor) : null;

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

        {/* Error Details */}
        {errorDetails && (
          <div className="mb-8 space-y-4">
            {/* Error Type Information */}
            {errorInfo && (
              <div className={`p-4 rounded-lg ${errorInfo.bgColor} border-l-4 border-red-400`}>
                <div className="flex items-center gap-3 mb-2">
                  <errorInfo.icon className={`w-6 h-6 ${errorInfo.color}`} />
                  <h3 className="text-lg font-semibold text-gray-900">{errorInfo.title}</h3>
                </div>
                <p className="text-gray-700">{errorInfo.description}</p>
              </div>
            )}

            {/* Technical Details */}
            <div className="bg-gray-50 rounded-lg p-4">
              <h4 className="text-sm font-semibold text-gray-700 mb-2">Technical Details</h4>
              <div className="space-y-1 text-sm">
                <div><span className="font-medium">Result Major:</span> <span className="font-mono">{errorDetails.resultMajor}</span></div>
                {errorDetails.resultMinor && (
                  <div><span className="font-medium">Result Minor:</span> <span className="font-mono">{errorDetails.resultMinor}</span></div>
                )}
                {errorDetails.resultMessage && (
                  <div><span className="font-medium">Message:</span> {errorDetails.resultMessage}</div>
                )}
                {errorDetails.tlsAlertDescription && (
                  <div><span className="font-medium">TLS Alert:</span> {errorDetails.tlsAlertDescription}</div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Default error message if no details available */}
        {!errorDetails && (
          <p className="text-lg text-gray-700 mb-8">
            An error occurred during the authentication process. Please try again.
          </p>
        )}

        <div className="flex gap-4">
          <button
            onClick={() => router.push('/')}
            className="flex-1 px-6 py-3 bg-blue-600 text-white rounded-full font-medium hover:bg-blue-700 transition-colors"
          >
            Return to Home
          </button>
          {token && (
            <button
              onClick={() => router.reload()}
              className="px-6 py-3 bg-gray-100 text-gray-700 rounded-full font-medium hover:bg-gray-200 transition-colors flex items-center gap-2"
            >
              <RefreshCw className="w-4 h-4" />
              Retry
            </button>
          )}
        </div>
      </motion.div>
    </div>
  );
}