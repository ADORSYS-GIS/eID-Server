# TLS Certificate Configuration Guide

This guide explains how to configure TLS certificates for the eID Test eService, supporting both normal TLS with eID-Client and mTLS with eID-Server.

## Certificate Overview

The eService supports flexible TLS configuration:

- **HTTPS Server**: Self-signed certificates accepted for development
- **eID-Client Communication**: Normal TLS (server certificates)
- **eID-Server Communication**: Optional mTLS (mutual TLS with client certificates)

## Certificate Requirements

### For HTTPS Server (eService)

- **Server Certificate** (PEM format)
- **Private Key** (PEM format)
- **CA Certificate** (optional, for certificate chain validation)

### For eID-Server Communication (mTLS)

- **Client Certificate** (PEM format)
- **Client Private Key** (PEM format)
- **CA Certificate** (optional, for server certificate validation)

## Quick Setup

### 1. Generate Self-Signed Certificates (Development)

```bash
# Generate private key
openssl genrsa -out server.key 2048

# Generate certificate signing request
openssl req -new -key server.key -out server.csr -subj "/C=DE/ST=Berlin/L=Berlin/O=eID-Test-eService/CN=localhost"

# Generate self-signed certificate (valid for 1 year)
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

# Clean up
rm server.csr
```

### 2. Configure Environment Variables

Create or update your `.env.local` file:

```bash
# HTTPS Server Configuration
HTTPS_CERT_PATH=./certs/server.crt
HTTPS_KEY_PATH=./certs/server.key
HTTPS_CA_PATH=./certs/ca.crt  # Optional

# eID-Server Configuration
EID_SERVER_URL=https://your-eid-server.com/eIDService
EID_SERVER_TLS_MODE=mtls  # or 'normal' for regular TLS

# mTLS Certificates (for eID-Server communication)
EID_SERVER_CERT_PATH=./certs/client.crt
EID_SERVER_KEY_PATH=./certs/client.key
EID_SERVER_CA_PATH=./certs/server-ca.crt  # Optional

# Alternative: Direct PEM content (instead of file paths)
EID_SERVER_CERT=-----BEGIN CERTIFICATE-----
MIIDtTCCAp2gAwIBAgIJAKg...
-----END CERTIFICATE-----

EID_SERVER_KEY=-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
-----END PRIVATE KEY-----

# Base URL (will auto-detect HTTPS)
NEXT_PUBLIC_BASE_URL=https://localhost:3000
```

## TLS Modes Explained

### Normal TLS Mode (`EID_SERVER_TLS_MODE=normal`)

- **Use case**: Standard TLS connection to eID-Server
- **Requirements**: Server certificate validation only
- **Certificates**: Optional client certificates

### Mutual TLS Mode (`EID_SERVER_TLS_MODE=mtls`)

- **Use case**: Mutual authentication with eID-Server
- **Requirements**: Both client and server certificates
- **Certificates**: Mandatory client certificate + key

## Certificate File Structure

```toml
your-project/
├── certs/
│   ├── server.crt          # HTTPS server certificate
│   ├── server.key          # HTTPS server private key
│   ├── client.crt          # mTLS client certificate
│   ├── client.key          # mTLS client private key
│   └── server-ca.crt       # eID-Server CA certificate (optional)
├── .env.local
└── ...
```

## Certificate Formats

### Supported Formats

- **PEM format** (most common)
- **Base64 encoded** content
- **File paths** or direct content

### Certificate Content Example

```pem
-----BEGIN CERTIFICATE-----
MIIDtTCCAp2gAwIBAgIJAKg...
[Base64 encoded certificate]
-----END CERTIFICATE-----
```

### Private Key Content Example

```pem
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
[Base64 encoded private key]
-----END PRIVATE KEY-----
```

## Common Certificate Issues

### Self-Signed Certificate Warnings

**Issue**: Browser shows security warning
**Solution**:

- Development: Accept the certificate in browser
- Production: Use proper CA-signed certificates

### Certificate Validation Errors

**Issue**: `UNABLE_TO_VERIFY_LEAF_SIGNATURE` or similar
**Solution**:

- Set `NODE_ENV=development` to accept self-signed certs
- Provide proper CA certificate in `EID_SERVER_CA_PATH`

### mTLS Authentication Failures

**Issue**: eID-Server rejects client certificate
**Solution**:

- Verify certificate is signed by trusted CA
- Check certificate expiration
- Ensure private key matches certificate

## Advanced Configuration

### Custom Certificate Validation

```javascript
// In SOAP client configuration
const tlsOptions = {
  rejectUnauthorized: true, // Strict validation
  ca: fs.readFileSync('./certs/trusted-ca.crt'),
  checkServerIdentity: (host, cert) => {
    // Custom validation logic
    return undefined; // Accept connection
  }
};
```
