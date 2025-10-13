// Load environment variables from .env.local
require('dotenv').config({ path: '.env.local' });

const { createServer: createHttpsServer } = require('https');
const { createServer: createHttpServer } = require('http');
const { parse } = require('url');
const next = require('next');
const fs = require('fs');
const path = require('path');

const dev = process.env.NODE_ENV !== 'production';
const app = next({ dev });
const handle = app.getRequestHandler();

// Server configuration
const PORT = process.env.PORT || 3000;
const isHttps = PORT.toString() === '8443';

// For outgoing requests, we might need to trust self-signed certs (e.g., eID-Server)
if (process.env.NODE_ENV !== 'production') {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

app.prepare().then(() => {
    if (isHttps) {
        // --- HTTPS Server Setup ---
        console.log('Attempting to start HTTPS server on port', PORT);
        
        const certPath = process.env.HTTPS_CERT_PATH || path.join(__dirname, 'certs', 'fullchain.pem');
        const keyPath = process.env.HTTPS_KEY_PATH || path.join(__dirname, 'certs', 'client.key');
        const caPath = process.env.HTTPS_CA_PATH; // Optional

        try {
            if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
                throw new Error('Certificate or key file not found at the specified paths.');
            }

            const httpsOptions = {
                cert: fs.readFileSync(certPath),
                key: fs.readFileSync(keyPath),
                ca: caPath && fs.existsSync(caPath) ? fs.readFileSync(caPath) : undefined,
                // Enforce modern, secure TLS protocols and ciphers to avoid handshake errors
                secureProtocol: 'TLSv1_2_method',
                ciphers: [
                    'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-ECDSA-AES128-GCM-SHA256',
                    'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-ECDSA-AES256-GCM-SHA384',
                    'DHE-RSA-AES128-GCM-SHA256', 'kEDH+AESGCM',
                    'ECDHE-RSA-AES128-SHA256', 'ECDHE-ECDSA-AES128-SHA256',
                    'ECDHE-RSA-AES256-SHA384', 'ECDHE-ECDSA-AES256-SHA384',
                    'DHE-RSA-AES128-SHA256', 'DHE-RSA-AES256-SHA256',
                    '!aNULL', '!eNULL', '!EXPORT', '!DES', '!RC4', '!3DES', '!MD5', '!PSK'
                ].join(':')
            };
            
            console.log('✅ HTTPS certificates loaded successfully.');
            console.log('🔒 Enforcing modern TLS protocols and strong cipher suites.');

            createHttpsServer(httpsOptions, (req, res) => {
                const parsedUrl = parse(req.url, true);
                handle(req, res, parsedUrl);
            }).listen(PORT, (err) => {
                if (err) throw err;
                console.log(`> ✅ Ready on https://localhost:${PORT}`);
                if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
                  console.log('> 🔒 Self-signed certificate acceptance is enabled for outgoing requests.');
                }
            });

        } catch (error) {
            console.error('❌ Error loading HTTPS certificates:', error.message);
            console.log(`📝 Please ensure certificate files exist at:\n- Cert: ${certPath}\n- Key:  ${keyPath}`);
            process.exit(1);
        }

    } else {
        // --- HTTP Server Setup ---
        console.log('Starting HTTP server on port', PORT);
        createHttpServer((req, res) => {
            const parsedUrl = parse(req.url, true);
            handle(req, res, parsedUrl);
        }).listen(PORT, (err) => {
            if (err) throw err;
            console.log(`> ✅ Ready on http://localhost:${PORT}`);
        });
    }
});