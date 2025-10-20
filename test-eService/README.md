# eID Service

Test eService for testing eID authentication flows with eID-Server and eID-Client (AusWeisApp2).

## Prerequisites

- **Node.js** (v16 or higher)
- **npm** (comes with Node.js)
- **eID-Server** running and accessible
- **eID-Client** (AusWeisApp2) installed on your system

## Quick Start

> **HTTPS Note**: The development server automatically runs with HTTPS when certificates are configured. Simply set `HTTPS_CERT_PATH` and `HTTPS_KEY_PATH` in your `.env.local` file, and the server will start with HTTPS enabled.

1. **Install Dependencies**

   ```bash
   npm install
   ```

2. **Configure Environment**

   Create a `.env.local` file in the root of the project. This file is for local development and should not be committed to version control.

   ```bash
   touch .env.local
   ```

   Then, add the following content to the `.env.local` file, adjusting the values for your environment:

   ```
   # eID-Server Configuration
   EID_SERVER_URL="Your server URL"
   EID_SERVER_ADDRESS="Your server address"

   # Application Configuration
   NEXT_PUBLIC_BASE_URL=https://localhost:8080
   PORT=8443

   # HTTPS Server Configuration
   HTTPS_CERT_PATH=./certs/fullchain.pem
   HTTPS_KEY_PATH=./certs/client.key

   # TLS/mTLS Configuration (optional)
   # EID_SERVER_TLS_MODE=normal
   # EID_SERVER_CERT_PATH=path/to/client-cert.pem
   # EID_SERVER_KEY_PATH=path/to/client-key.pem
   # EID_SERVER_CA_PATH=path/to/ca-cert.pem
   # EID_SERVER_REJECT_UNAUTHORIZED=false

   # Security
   NODE_ENV=development
   ```

3. **Generate Self-Signed Certificate (for development)**

   ```bash
   # Generate a self-signed certificate for HTTPS
   openssl req -x509 -newkey rsa:2048 -nodes -keyout cert.key -out cert.pem -days 365 -subj "/CN=localhost"

   # Update your .env.local with certificate paths
   echo "HTTPS_CERT_PATH=cert.pem" >> .env.local
   echo "HTTPS_KEY_PATH=cert.key" >> .env.local
   ```

4. **Start Development Server**

   ```bash
   npm run dev
   ```

5. **Open Application**
   Navigate to `https://localhost:8443` (accept the self-signed certificate warning)

## Configuration

### Environment Variables

#### Basic Configuration

| Variable               | Description                                | Default                             |
| ---------------------- | ------------------------------------------ | ----------------------------------- |
| `EID_SERVER_URL`       | eID-Server SOAP endpoint                   | `https://localhost:8443/eIDService` |
| `EID_SERVER_ADDRESS`   | eID-Server address for TC Token            | `https://localhost:8443/eIDService` |
| `NEXT_PUBLIC_BASE_URL` | Your service base URL (for browser/client) | `https://localhost:3000`            |
| `PORT`                 | Server port (optional)                     | `3000`                              |

#### HTTPS Server Configuration

| Variable          | Description                            | Default |
| ----------------- | -------------------------------------- | ------- |
| `HTTPS_CERT_PATH` | Path to HTTPS server certificate (PEM) | -       |
| `HTTPS_KEY_PATH`  | Path to HTTPS server private key (PEM) | -       |
| `HTTPS_CA_PATH`   | Path to HTTPS CA certificate (PEM)     | -       |

#### eID-Server TLS Configuration

| Variable                         | Description                               | Default       |
| -------------------------------- | ----------------------------------------- | ------------- |
| `EID_SERVER_TLS_MODE`            | TLS mode: 'normal' or 'mtls'              | `normal`      |
| `EID_SERVER_CERT_PATH`           | Path to client certificate (PEM) for mTLS | -             |
| `EID_SERVER_KEY_PATH`            | Path to client private key (PEM) for mTLS | -             |
| `EID_SERVER_CA_PATH`             | Path to eID-Server CA certificate (PEM)   | -             |
| `EID_SERVER_REJECT_UNAUTHORIZED` | Validate certificates strictly            | `false` (dev) |

### eID-Server Integration

The eService communicates with the eID-Server via SOAP:

1. **getServerInfo Request** - Fetches eID-Server capabilities and settings
2. **useID Request** - Requests authentication session and PSK
3. **TC Token Generation** - Creates TC Token for eID-Client
4. **getResult Request** - Retrieves authentication results

### Supported Operations

All personal data attributes can be configured as:

- **REQUIRED** - Must be provided by user
- **ALLOWED** - May be provided if user consents
- **PROHIBITED** - Not requested

### Verification Features

- **Age Verification** - Verify user meets minimum age requirement
- **Place Verification** - Verify user resides in specific community
- **Transaction Attestation** - Generate transaction attestations
- **Level of Assurance** - Set required authentication level

### eID Types Selection

The eService allows specifying which types of eID are allowed or denied for the authentication process. This provides granular control over the accepted authentication methods.

- **CardCertified** - Certified eID cards
- **SECertified** - Certified Secure Elements
- **SEEndorsed** - Endorsed Secure Elements
- **HWKeyStore** - Hardware-backed keystores

### TLS Configuration

The eService supports flexible TLS configuration:

- **HTTPS Server**: Run with self-signed or CA-signed certificates
- **Normal TLS**: Standard TLS connection to eID-Server
- **mTLS**: Mutual TLS with client certificate authentication
- **Certificate Validation**: Configurable certificate validation for development

See [CERTIFICATE_GUIDE.md](CERTIFICATE_GUIDE.md) for detailed certificate configuration instructions.

### Port Configuration

**Important**: `PORT` and `NEXT_PUBLIC_BASE_URL` serve different purposes:

- **`PORT`**: The actual port the server listens on (default: 3000)
- **`NEXT_PUBLIC_BASE_URL`**: The URL clients use to access the service (for browser/API calls)

**Example Configuration:**

```bash
# Server runs on port 3000
PORT=3000

# But clients access it via https://localhost:8443
NEXT_PUBLIC_BASE_URL=https://localhost:8443
```

If you want to run on a different port, change both variables:

```bash
PORT=8443
NEXT_PUBLIC_BASE_URL=https://localhost:8443
```

## Usage

1. **Configure Authentication** - Select operations and settings on the main page
2. **Start Authentication** - Click "Start eID Authentication"
3. **eID-Client Activation** - Service triggers eID-Client with TC Token URL
4. **User Authentication** - User completes authentication with eID card
5. **Results Display** - View detailed authentication results

## API Endpoints

- `POST /api/auth/start` - Start authentication session
- `GET /api/tctoken` - Serve TC Token to eID-Client
- `GET /api/refresh` - Handle eID-Client callback
- `GET /api/auth/result` - Retrieve authentication results

## Development

### Project Structure

```toml
├── pages/                 # Next.js pages
│   ├── api/               # API routes
│   ├── index.tsx          # Main configuration page
│   ├── results.tsx        # Results display page
│   └── _app.tsx           # App wrapper
├── lib/                   # Utility libraries
│   ├── soapClient.ts      # SOAP communication with eID-Server
│   └── sessionManager.ts  # Session management
├── types/                 # TypeScript type definitions
├── styles/                # Global styles and Tailwind CSS
└── docs/                  # Specification documents
```

## Specifications

This implementation follows:

- **TR-03130 Part 1** - eID-Server specifications
- **TR-03124 Part 1** - eID-Client specifications

See the `docs/` folder for detailed specifications and example payloads.

## License

This project is for testing purposes only. Follow applicable regulations and standards for production use.
