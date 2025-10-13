import { NextApiRequest, NextApiResponse } from 'next';
import { SOAPClient } from '@/lib/soapClient';
import { sessionManager } from '@/lib/sessionManager';
import type { AuthenticationConfig } from '@/types/eid';

export default async function handler(
    req: NextApiRequest,
    res: NextApiResponse
) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const config: AuthenticationConfig = req.body;

        // Validate configuration
        if (!config || !config.operations) {
            return res.status(400).json({ error: 'Invalid configuration' });
        }

        // Store configuration for later useID call
        const token = await sessionManager.createConfigurationSession(config);

        // The TC Token URL must point to the public-facing HTTPS server that the eID-Client will connect to.
        // In this setup, that is the server running on port 8443.
        const tcTokenUrl = `https://localhost:8443/api/tctoken?token=${token}`;

        // Return TC Token URL for eID-Client activation
        res.status(200).json({
            tcTokenUrl,
            token, // Included for client-side debugging if needed
        });
    } catch (error: any) {
        console.error('Error starting authentication:', error);
        res.status(500).json({
            error: 'Failed to start authentication',
            message: error.message,
        });
    }
}