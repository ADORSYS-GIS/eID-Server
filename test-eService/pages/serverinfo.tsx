import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';
import { motion } from 'framer-motion';
import {
  Server,
  FileText,
  Home as HomeIcon,
  Loader2,
  XCircle,
  AlertCircle
} from 'lucide-react';
import type { GetServerInfoResponse, AttributeResponseType } from '../types/eid';

export default function ServerInfo() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [serverInfo, setServerInfo] = useState<GetServerInfoResponse | null>(null);

  useEffect(() => {
    const fetchServerInfo = async () => {
      try {
        const response = await fetch('/api/serverinfo');
        
        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.error || 'Failed to fetch server info');
        }

        const data = await response.json();
        setServerInfo(data);
      } catch (err: any) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchServerInfo();
  }, []);

  const getStatusBadge = (status: AttributeResponseType) => {
    const badges: Record<AttributeResponseType, { bg: string; text: string; label: string }> = {
      ALLOWED: { bg: 'bg-green-100', text: 'text-green-800', label: 'Allowed' },
      PROHIBITED: { bg: 'bg-red-100', text: 'text-red-800', label: 'Prohibited' },
      NOTONCHIP: { bg: 'bg-gray-100', text: 'text-gray-800', label: 'Not on Chip' },
    };

    const badge = badges[status];

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
            Retrieving server information...
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
              Failed to Load Server Info
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

  if (!serverInfo) {
    return null;
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-50 to-white">
      {/* Header */}
      <header className="py-6 px-6 border-b border-gray-200">
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="max-w-6xl mx-auto"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Server className="w-8 h-8 text-blue-600" />
              <div>
                <h1 className="text-3xl font-semibold text-gray-900">
                  eID-Server Information
                </h1>
              </div>
            </div>
            <button
              onClick={() => router.push('/')}
              className="flex items-center gap-2 px-3 py-1.5 bg-gray-100 hover:bg-gray-200 rounded-full text-gray-700 font-medium text-sm transition-colors"
            >
              <HomeIcon className="w-4 h-4" />
              Return to Home
            </button>
          </div>
        </motion.div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8">
        {/* Server Version */}
        <motion.section
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="mb-6 bg-white rounded-2xl shadow-sm border border-gray-200 p-6"
        >
          <div className="flex items-center gap-3 mb-4">
            <AlertCircle className="w-5 h-5 text-blue-600" />
            <h2 className="text-xl font-semibold text-gray-900">
              Server Version
            </h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <DataField label="Version" value={serverInfo.ServerVersion.VersionString} />
            <DataField label="Major" value={serverInfo.ServerVersion.Major} />
            <DataField label="Minor" value={serverInfo.ServerVersion.Minor} />
            <DataField label="Bugfix" value={serverInfo.ServerVersion.Bugfix} />
          </div>
        </motion.section>

        {/* Document Verification Rights */}
        <motion.section
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="mb-6 bg-white rounded-2xl shadow-sm border border-gray-200 p-6"
        >
          <div className="flex items-center gap-3 mb-4">
            <FileText className="w-5 h-5 text-purple-600" />
            <h2 className="text-xl font-semibold text-gray-900">
              Document Verification Rights
            </h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {Object.entries(serverInfo.DocumentVerificationRights).map(([key, status]) => (
              <div key={key} className="flex items-center justify-between p-3 rounded-lg bg-gray-50">
                <span className="text-sm font-medium text-gray-700">
                  {key.replace(/([A-Z])/g, ' $1').replace(/ I D/g, ' ID').trim()}
                </span>
                {getStatusBadge(status as AttributeResponseType)}
              </div>
            ))}
          </div>
        </motion.section>
      </main>
    </div>
  );
}

// Helper Components
interface DataFieldProps {
  label: string;
  value?: string;
}

function DataField({ label, value }: DataFieldProps) {
  if (!value) return null;

  return (
    <div className="p-3 rounded-lg bg-gray-50">
      <span className="text-xs font-medium text-gray-600">{label}</span>
      <p className="text-base font-semibold text-gray-900">{value}</p>
    </div>
  );
}