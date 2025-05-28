import express, { Request, Response, RequestHandler } from 'express';
import { deflate } from 'zlib';
import { promisify } from 'util';
import { createSign } from 'crypto';
import { readFileSync } from 'fs';
import { URL } from 'url';
import axios from 'axios';
import https from 'https';

const app = express();
const deflateAsync = promisify(deflate);

// Configuration
const config = {
  eidServerUrl: 'https://dev.id.governikus-eid.de/gov_autent/async',
  keycloakUrl: 'https://localhost:8443',
  realm: 'master',
  privateKeyPath: './keys/saml-signing.key',
  certificatePath: './keys/saml-signing.crt'
};

// Helper function for logging
function logStep(step: string, data: any) {
  console.log('\n===', step, '===');
  console.log(JSON.stringify(data, null, 2));
  console.log('===================\n');
}

// API endpoint to proxy TcToken call
const tcTokenHandler: RequestHandler = async (req, res, next) => {
  const { url } = req.query;
  if (!url || typeof url !== 'string') {
    res.status(400).json({ error: 'Missing url parameter' });
    return;
  }
  try {
    logStep('Proxying TcToken Endpoint', { url });
    const axiosConfig = {
      maxRedirects: 0,
      validateStatus: () => true,
      httpsAgent: new https.Agent({ rejectUnauthorized: false })
    } as any;
    const response = await axios.get(url, axiosConfig);
    res.json({
      status: response.status,
      headers: response.headers,
      data: response.data,
      redirectUrl: response.headers.location || null
    });
  } catch (error: any) {
    logStep('Error in /api/tc-token', { message: error.message });
    res.status(500).json({ error: error.message });
  }
};

// API endpoint to proxy eID server call
const eidServerHandler: RequestHandler = async (req, res, next) => {
  const { url } = req.query;
  if (!url || typeof url !== 'string') {
    res.status(400).json({ error: 'Missing url parameter' });
    return;
  }
  try {
    logStep('Proxying eID Server', { url });
    const axiosConfig = {
      maxRedirects: 0,
      validateStatus: () => true,
      httpsAgent: new https.Agent({ rejectUnauthorized: false })
    } as any;
    const response = await axios.get(url, axiosConfig);
    res.json({
      status: response.status,
      headers: response.headers,
      data: response.data,
      redirectUrl: response.headers.location || null
    });
  } catch (error: any) {
    logStep('Error in /api/eid-server', { message: error.message });
    res.status(500).json({ error: error.message });
  }
};

// Routes
const startHandler: RequestHandler = async (req, res, next) => {
  try {
    logStep('Starting Flow', { timestamp: new Date().toISOString() });
    
    // Show the initial form
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>eID Authentication Flow</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
          .step { margin-bottom: 30px; padding: 20px; border: 1px solid #ccc; border-radius: 5px; }
          .url { word-break: break-all; background: #f5f5f5; padding: 10px; margin: 10px 0; }
          button { padding: 10px 20px; margin: 10px 0; cursor: pointer; }
          pre { white-space: pre-wrap; }
          .response { margin-top: 10px; padding: 10px; background: #f0f0f0; }
          .logs { margin-top: 20px; padding: 10px; background: #f8f8f8; border: 1px solid #ddd; }
          .form-group { margin-bottom: 15px; }
          label { display: block; margin-bottom: 5px; }
          input[type="text"] { width: 100%; padding: 8px; }
        </style>
      </head>
      <body>
        <h1>eID Authentication Flow</h1>
        
        <div class="step">
          <h2>Step 1: Configure Keycloak</h2>
          <form id="configForm">
            <div class="form-group">
              <label for="keycloakUrl">Keycloak URL:</label>
              <input type="text" id="keycloakUrl" value="${config.keycloakUrl}" />
            </div>
            <div class="form-group">
              <label for="realm">Realm:</label>
              <input type="text" id="realm" value="${config.realm}" />
            </div>
            <button type="button" onclick="generateTcTokenUrl()">Generate TcToken URL</button>
          </form>
          <div id="tcTokenUrlResult" class="response"></div>
        </div>
        
        <div class="step">
          <h2>Step 2: Call TcToken Endpoint</h2>
          <div id="tcTokenStep" style="display: none;">
            <div class="url" id="tcTokenUrl"></div>
            <button onclick="callTcTokenEndpoint()">Call TcToken Endpoint</button>
            <div id="tcTokenResponse" class="response"></div>
          </div>
        </div>
        
        <div class="step">
          <h2>Step 3: Call eID Server</h2>
          <div id="eidServerStep" style="display: none;">
            <div class="url" id="eidServerUrl"></div>
            <button onclick="callEidServer()">Call eID Server</button>
            <div id="eidServerResponse" class="response"></div>
          </div>
        </div>

        <script>
          let lastTcTokenProxyResult = null;
          let lastEidServerProxyResult = null;

          async function generateTcTokenUrl() {
            const keycloakUrl = document.getElementById('keycloakUrl').value;
            const realm = document.getElementById('realm').value;
            
            // Generate a unique relay state
            const relayState = btoa(JSON.stringify({
              ru: keycloakUrl + '/admin/master/console/',
              rt: 'code',
              rm: 'query',
              st: '_' + Math.random().toString(36).substr(2, 9)
            }));
            
            const tcTokenUrl = keycloakUrl + '/realms/' + realm + '/tc-token-endpoint/tc-token?RelayState=' + encodeURIComponent(relayState);
            document.getElementById('tcTokenUrl').textContent = tcTokenUrl;
            document.getElementById('tcTokenStep').style.display = 'block';
            document.getElementById('tcTokenResponse').innerHTML = '';
            document.getElementById('eidServerStep').style.display = 'none';
            document.getElementById('eidServerResponse').innerHTML = '';
            window.relayState = relayState;
            window.tcTokenUrl = tcTokenUrl;
            window.eidServerUrl = null;
            lastTcTokenProxyResult = null;
            lastEidServerProxyResult = null;
            console.log('Generated TcToken URL:', tcTokenUrl);
          }

          async function callTcTokenEndpoint() {
            const tcTokenUrl = document.getElementById('tcTokenUrl').textContent;
            try {
              document.getElementById('tcTokenResponse').innerHTML = '<em>Loading...</em>';
              console.log('Calling TcToken endpoint:', tcTokenUrl);
              
              const resp = await fetch('/api/tc-token?url=' + encodeURIComponent(tcTokenUrl));
              if (!resp.ok) {
                throw new Error('HTTP error! status: ' + resp.status);
              }
              
              const result = await resp.json();
              console.log('TcToken response:', result);
              lastTcTokenProxyResult = result;

              // Build response HTML
              let responseHtml = 
                '<b>Request URL:</b> <div class="url">' + tcTokenUrl + '</div>' +
                '<b>Status:</b> ' + result.status + '<br/>' +
                '<b>Headers:</b> <pre>' + JSON.stringify(result.headers, null, 2) + '</pre>';

              // Handle response data
              if (result.data) {
                if (typeof result.data === 'string') {
                  responseHtml += '<b>Body:</b> <pre>' + result.data + '</pre>';
                } else {
                  responseHtml += '<b>Body:</b> <pre>' + JSON.stringify(result.data, null, 2) + '</pre>';
                }
              }

              // Handle redirect URL
              if (result.redirectUrl) {
                responseHtml += '<b>Redirect URL:</b> <div class="url">' + result.redirectUrl + '</div>';
                document.getElementById('eidServerUrl').textContent = result.redirectUrl;
                document.getElementById('eidServerStep').style.display = 'block';
                window.eidServerUrl = result.redirectUrl;
              }

              document.getElementById('tcTokenResponse').innerHTML = responseHtml;

              // If we got a successful response but no redirect, show a message
              if (result.status === 200 && !result.redirectUrl) {
                document.getElementById('tcTokenResponse').innerHTML += 
                  '<div style="color: orange; margin-top: 10px;">Note: Received 200 OK but no redirect URL. This might be unexpected.</div>';
              }

            } catch (error) {
              console.error('Error in callTcTokenEndpoint:', error);
              document.getElementById('tcTokenResponse').innerHTML = 
                '<h3>Error:</h3><pre>' + error.message + '</pre>' +
                '<div style="color: red; margin-top: 10px;">Please check the console for more details.</div>';
            }
          }

          async function callEidServer() {
            const eidServerUrl = document.getElementById('eidServerUrl').textContent;
            if (!eidServerUrl) {
              document.getElementById('eidServerResponse').innerHTML = 
                '<h3>Error:</h3><pre>No eID server URL available</pre>';
              return;
            }

            try {
              document.getElementById('eidServerResponse').innerHTML = '<em>Loading...</em>';
              console.log('Calling eID server:', eidServerUrl);
              
              const resp = await fetch('/api/eid-server?url=' + encodeURIComponent(eidServerUrl));
              if (!resp.ok) {
                throw new Error('HTTP error! status: ' + resp.status);
              }
              
              const result = await resp.json();
              console.log('eID server response:', result);
              lastEidServerProxyResult = result;

              // Build response HTML
              let responseHtml = 
                '<b>Request URL:</b> <div class="url">' + eidServerUrl + '</div>' +
                '<b>Status:</b> ' + result.status + '<br/>' +
                '<b>Headers:</b> <pre>' + JSON.stringify(result.headers, null, 2) + '</pre>';

              // Handle response data
              if (result.data) {
                if (typeof result.data === 'string') {
                  responseHtml += '<b>Body:</b> <pre>' + result.data + '</pre>';
                } else {
                  responseHtml += '<b>Body:</b> <pre>' + JSON.stringify(result.data, null, 2) + '</pre>';
                }
              }

              // Handle redirect URL
              if (result.redirectUrl) {
                responseHtml += '<b>Redirect URL:</b> <div class="url">' + result.redirectUrl + '</div>';
              }

              document.getElementById('eidServerResponse').innerHTML = responseHtml;

            } catch (error) {
              console.error('Error in callEidServer:', error);
              document.getElementById('eidServerResponse').innerHTML = 
                '<h3>Error:</h3><pre>' + error.message + '</pre>' +
                '<div style="color: red; margin-top: 10px;">Please check the console for more details.</div>';
            }
          }
        </script>
      </body>
      </html>
    `);
  } catch (error: any) {
    logStep('Error', { message: error?.message || 'Unknown error occurred' });
    res.status(500).send(`Error: ${error?.message || 'Unknown error occurred'}`);
  }
};

// Register routes
app.get('/api/tc-token', tcTokenHandler);
app.get('/api/eid-server', eidServerHandler);
app.get('/start', startHandler);

// Start server
app.listen(3000, () => {
  console.log('Server running at http://localhost:3000');
  console.log('Visit http://localhost:3000/start to begin the flow');
}); 