import { NextApiRequest, NextApiResponse } from 'next';
import { XMLBuilder } from 'fast-xml-parser';
import { sessionManager } from '@/lib/sessionManager';
import { SOAPClient } from '@/lib/soapClient';

export default async function handler(
    req: NextApiRequest,
    res: NextApiResponse
) {
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { token } = req.query;

        if (!token || typeof token !== 'string') {
            return res.status(400).send('Missing or invalid token parameter');
        }

        // Get session data
        let session = await sessionManager.getSession(token);

        if (!session) {
            console.log(`Session not found for token: ${token}`);
            return res.status(404).send('Session not found or expired');
        }

        // Check if this is a configuration session (needs useID call) or already has useID data
        if (!session.sessionId) {
            console.log(`Configuration session found, calling useID for token: ${token}`);
            
            // Get eID-Server URL from environment or use default
            const eidServerUrl = process.env.EID_SERVER_URL || 'https://localhost:8443/eIDService';

            // Configure TLS options for eID-Server communication
            const tlsOptions: any = {
                rejectUnauthorized: process.env.NODE_ENV === 'production',
                mode: (process.env.EID_SERVER_TLS_MODE === 'mtls' ? 'mtls' : 'normal') as 'mtls' | 'normal',
                // Support both file paths and direct PEM content
                certPath: process.env.EID_SERVER_CERT_PATH,
                keyPath: process.env.EID_SERVER_KEY_PATH,
                caPath: process.env.EID_SERVER_CA_PATH,
                // Fallback to direct content if paths not provided
                cert: process.env.EID_SERVER_CERT,
                key: process.env.EID_SERVER_KEY,
                ca: process.env.EID_SERVER_CA,
            };

            const soapClient = new SOAPClient(eidServerUrl, tlsOptions);

            // Call useID on eID-Server
            console.log('Calling useID with config for token:', token);
            const useIDResponse = await soapClient.callUseID(session.config);

            // Check result
            if (!useIDResponse.Result.ResultMajor.includes('#ok')) {
                console.log(`useID failed for token ${token}:`, useIDResponse.Result.ResultMajor);
                return res.status(400).send(`eID-Server returned error: ${useIDResponse.Result.ResultMajor}`);
            }

            // Update session with useID response data
            const updated = await sessionManager.updateSessionWithUseIDResponse(
                token,
                useIDResponse.Session.ID,
                useIDResponse.PSK.ID,
                useIDResponse.PSK.Key,
                useIDResponse.eCardServerAddress
            );

            if (!updated) {
                console.log(`Failed to update session for token: ${token}`);
                return res.status(500).send('Failed to update session');
            }

            // Re-fetch the session to get the latest data
            session = await sessionManager.getSession(token);
            if (!session) {
                console.log(`Session not found after update for token: ${token}`);
                return res.status(404).send('Session not found after update');
            }

            console.log(`Successfully updated session for token: ${token}`);
        } else {
            console.log(`Session already has useID data for token: ${token}`);
        }

        // Use eCardServerAddress from useID response, or default
        const serverAddress = session.eCardServerAddress ||
            process.env.EID_SERVER_ADDRESS ||
            'https://localhost:8443/eIDService';

        // Build TC Token XML
        const builder = new XMLBuilder({
            ignoreAttributes: false,
            format: false, // No formatting for TC Token
            suppressEmptyNode: true,
        });

        const tcToken = {
            TCTokenType: {
                ServerAddress: serverAddress,
                SessionIdentifier: session.pskId,
                RefreshAddress: `https://localhost:8443/api/refresh?token=${token}`,
                CommunicationErrorAddress: `https://localhost:8443/error?token=${token}`,
                Binding: 'urn:liberty:paos:2006-08',
                'PathSecurity-Protocol': 'urn:ietf:rfc:4279',
                'PathSecurity-Parameters': {
                    PSK: session.pskKey,
                },
            },
        };

        const xmlContent = builder.build(tcToken);

        // TC Token must be served as text/xml without XML declaration
        const tcTokenWithoutDeclaration = xmlContent.replace(/<\?xml[^?]*\?>\s*/, '');

        console.log('Serving TC Token for session:', session.sessionId);

        res.setHeader('Content-Type', 'text/xml; charset=UTF-8');
        res.status(200).send(tcTokenWithoutDeclaration);
    } catch (error: any) {
        console.error('Error serving TC Token:', error);
        res.status(500).send('Internal server error');
    }
}