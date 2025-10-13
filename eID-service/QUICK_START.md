# Quick Start Guide - eID Test eService

## Prerequisites

- **Node.js** (v16 or higher)
- **npm** (comes with Node.js)
- **eID-Server** running and accessible
- **eID-Client** (AusWeisApp2) installed on your system

## 1. Install Dependencies

```bash
npm install
```

## 2. Configure Environment

Copy the example environment file:

```bash
cp .env.local.example .env.local
```

Edit `.env.local` with your settings:

```bash
# Required: Your eID-Server SOAP endpoint
EID_SERVER_URL=https://your-eid-server.com/eIDService

# Optional: Base URL for your service (default: http://localhost:3000)
NEXT_PUBLIC_BASE_URL=http://localhost:3000
```

## 3. Start the Application

**Development mode:**

```bash
npm run dev
```

**Production mode:**

```bash
npm run build
npm start
```

## 4. Access the Application

Open your browser and go to:

```bash
http://localhost:3000
```

## 5. Test the Authentication Flow

1. **Configure Operations**: Select REQUIRED/ALLOWED/PROHIBITED for personal data attributes
2. **Set Verifications**: Enable age/place verification if needed
3. **Click "Start eID Authentication"**
4. **eID-Client will open**: AusWeisApp2 will launch automatically
5. **Complete authentication**: Follow the eID-Client prompts
6. **View results**: Return to the application to see authentication results

## Environment Variables Reference

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `EID_SERVER_URL` | ✅ | eID-Server SOAP endpoint | `https://localhost:8443/eIDService` |
| `NEXT_PUBLIC_BASE_URL` | ❌ | Your service URL | `http://localhost:3000` |
| `NODE_ENV` | ❌ | Environment mode | `development` or `production` |

## TLS/mTLS Configuration (Optional)

For secure communication with eID-Server:

```bash
# Add to .env.local
TLS_CERT=base64_encoded_client_certificate
TLS_KEY=base64_encoded_client_private_key
TLS_CA=base64_encoded_ca_certificate
```

To generate base64 encoded certificates:

```bash
# Linux/Mac
base64 -i client.crt -o client.crt.b64
base64 -i client.key -o client.key.b64
base64 -i ca.crt -o ca.crt.b64

# Windows
certutil -encode client.crt client.crt.b64
```

## Troubleshooting

### Application won't start

- Check Node.js version: `node --version`
- Ensure port 3000 is available: `lsof -i :3000`
- Check for port conflicts

### eID-Client doesn't open

- Verify AusWeisApp2 is installed
- Check browser console for errors
- Ensure the tcTokenURL is properly formatted

### eID-Server connection fails

- Verify `EID_SERVER_URL` is correct
- Check network connectivity
- Review TLS certificate configuration
- Check eID-Server logs

### Authentication fails

- Review eID-Server response logs
- Verify session management is working
- Check SOAP message format
- Ensure proper error handling

## Development Commands

```bash
# Start development server
npm run dev

# Build for production
npm run build

# Start production server
npm start

# Run linter
npm run lint

# Install dependencies
npm install
```

## Default Configuration

The application works out-of-the-box with these defaults:

- **eID-Server URL**: `https://localhost:8443/eIDService`
- **Base URL**: `http://localhost:3000`
- **Session Timeout**: 30 minutes
- **TLS**: Disabled in development, enabled in production

## Next Steps

1. **Configure your eID-Server**: Update `EID_SERVER_URL` in `.env.local`
2. **Test basic authentication**: Try with default settings
3. **Customize operations**: Select specific personal data attributes
4. **Enable verifications**: Try age and place verification
5. **Set up TLS**: Configure certificates for production use
