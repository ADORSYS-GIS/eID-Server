import { NextApiRequest, NextApiResponse } from 'next';
import { SOAPClient } from '@/lib/soapClient';
import { sessionManager } from '@/lib/sessionManager';

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
            return res.status(400).json({ error: 'Missing or invalid token parameter' });
        }

        // Get session data
        const session = await sessionManager.getSession(token);

        if (!session) {
            return res.status(404).json({ error: 'Session not found or expired' });
        }

        // Check if the eID-Client reported an error
        if (session.resultMajor && session.resultMajor.includes('error')) {
            console.log('eID-Client reported an error, not calling getResult.');
            return res.status(200).json({
                success: false,
                result: {
                    ResultMajor: session.resultMajor,
                    ResultMinor: session.resultMinor,
                    ResultMessage: 'eID-Client reported an error during the authentication process.',
                },
            });
        }

        // Get eID-Server URL
        const eidServerUrl = process.env.EID_SERVER_URL || 'https://localhost:8443/eIDService';

        // Initialize SOAP client
        const tlsOptions = {
            rejectUnauthorized: process.env.NODE_ENV === 'production',
        };

        const soapClient = new SOAPClient(eidServerUrl, tlsOptions);

        // Call getResult on eID-Server
        console.log('Calling getResult for session:', session.sessionId);
        const getResultResponse = await soapClient.callGetResult(session.sessionId);

        // Return result data
        res.status(200).json({
            success: getResultResponse.Result.ResultMajor.includes('#ok'),
            result: getResultResponse.Result,
            personalData: getResultResponse.PersonalData,
            ageVerification: getResultResponse.FulfilsAgeVerification,
            placeVerification: getResultResponse.FulfilsPlaceVerification,
            operationsAllowed: getResultResponse.OperationsAllowedByUser,
            transactionAttestation: getResultResponse.TransactionAttestationResponse,
            levelOfAssurance: getResultResponse.LevelOfAssuranceResult,
            eidType: getResultResponse.EIDTypeResponse,
            config: session.config,
        });

        // Clean up session after successful retrieval
        // sessionManager.deleteSession(token); // Optional: keep for multiple checks
    } catch (error: any) {
        console.error('Error getting result:', error);
        res.status(500).json({
            error: 'Failed to get authentication result',
            message: error.message,
        });
    }
}