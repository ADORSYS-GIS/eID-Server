import axios from 'axios';
import { deflate } from 'zlib';
import { promisify } from 'util';
import { createSign } from 'crypto';
import { readFileSync } from 'fs';
import https from 'https';

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

async function testEidFlow() {
  try {
    // Step 1: Generate SAML Request
    const samlRequestTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="_${Math.random().toString(36).substr(2, 9)}"
    Version="2.0"
    IssueInstant="${new Date().toISOString()}"
    Destination="${config.eidServerUrl}"
    AssertionConsumerServiceURL="${config.keycloakUrl}/realms/${config.realm}/broker/eid/endpoint"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">${config.keycloakUrl}/realms/${config.realm}</saml2:Issuer>
    <saml2p:Extensions>
        <eidas:SPType xmlns:eidas="http://eidas.europa.eu/saml-extensions">public</eidas:SPType>
        <eidas:RequestedAttributes xmlns:eidas="http://eidas.europa.eu/saml-extensions">
            <eidas:RequestedAttribute Name="http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
            <eidas:RequestedAttribute Name="http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
            <eidas:RequestedAttribute Name="http://eidas.europa.eu/attributes/naturalperson/DateOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
        </eidas:RequestedAttributes>
    </saml2p:Extensions>
</saml2p:AuthnRequest>`;

    logStep('SAML Request Template', { template: samlRequestTemplate });

    // Step 2: Generate Relay State
    const relayState = Buffer.from(JSON.stringify({
      ru: `${config.keycloakUrl}/admin/master/console/`,
      rt: 'code',
      rm: 'query',
      st: '_' + Math.random().toString(36).substr(2, 9)
    })).toString('base64');

    logStep('Generated Relay State', {
      raw: relayState,
      decoded: JSON.parse(Buffer.from(relayState, 'base64').toString())
    });

    // Step 3: Call TcToken Endpoint
    const tcTokenUrl = `${config.keycloakUrl}/realms/${config.realm}/tc-token-endpoint/tc-token?RelayState=${encodeURIComponent(relayState)}`;
    logStep('Calling TcToken Endpoint', { url: tcTokenUrl });

    const axiosConfig = {
      validateStatus: (status: number) => status >= 200 && status < 400,
      httpsAgent: new https.Agent({  
        rejectUnauthorized: false
      })
    };

    const tcTokenResponse = await axios.get(tcTokenUrl, axiosConfig);

    logStep('TcToken Response', {
      status: tcTokenResponse.status,
      headers: tcTokenResponse.headers,
      data: tcTokenResponse.data
    });

    // Step 4: Follow redirect to eID Server
    if (tcTokenResponse.status === 302 || tcTokenResponse.status === 303) {
      const eidServerUrl = tcTokenResponse.headers.location;
      logStep('Following redirect to eID Server', { url: eidServerUrl });

      const eidServerResponse = await axios.get(eidServerUrl, axiosConfig);

      logStep('eID Server Response', {
        status: eidServerResponse.status,
        headers: eidServerResponse.headers,
        data: eidServerResponse.data
      });
    }

  } catch (error: any) {
    logStep('Error', {
      message: error.message,
      response: error.response ? {
        status: error.response.status,
        headers: error.response.headers,
        data: error.response.data
      } : null
    });
  }
}

// Run the test
testEidFlow().then(() => {
  console.log('Test completed');
}).catch((error) => {
  console.error('Test failed:', error);
}); 