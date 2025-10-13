/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,
  // Configure environment variables
  env: {
    EID_SERVER_URL: process.env.EID_SERVER_URL,
    EID_SERVER_ADDRESS: process.env.EID_SERVER_ADDRESS,
    NEXT_PUBLIC_BASE_URL: process.env.NEXT_PUBLIC_BASE_URL,
  },
  // Configure API routes
  async rewrites() {
    return [
      {
        source: '/api/auth/start',
        destination: '/api/auth/start',
      },
      {
        source: '/api/auth/result',
        destination: '/api/auth/result',
      },
      {
        source: '/api/tctoken',
        destination: '/api/tctoken',
      },
      {
        source: '/api/refresh',
        destination: '/api/refresh',
      },
    ];
  },
  // Configure security headers
  async headers() {
    return [
      {
        source: '/api/tctoken',
        headers: [
          {
            key: 'Content-Type',
            value: 'text/xml; charset=UTF-8',
          },
        ],
      },
    ];
  },
};

module.exports = nextConfig;