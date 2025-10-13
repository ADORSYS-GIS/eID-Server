import { NextApiRequest, NextApiResponse } from 'next';
import { sessionManager } from '@/lib/sessionManager';

export default async function handler(
    req: NextApiRequest,
    res: NextApiResponse
) {
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { token, ResultMajor, ResultMinor } = req.query;

        if (!token || typeof token !== 'string') {
            return res.status(400).send('Missing or invalid token parameter');
        }

        // Verify session exists
        const session = await sessionManager.getSession(token);

        if (!session) {
            return res.status(404).send('Session not found or expired');
        }

        console.log('eID-Client callback received for session:', session.sessionId);
        console.log('Result parameters:', { ResultMajor, ResultMinor });

        // Save the client result to the session
        await sessionManager.updateSessionWithClientResult(
            token,
            ResultMajor as string,
            ResultMinor as string
        );
        
        // The final redirect must go to the secure, public-facing HTTPS server.
        const redirectUrl = `https://localhost:8443/results?token=${token}`;

        res.redirect(302, redirectUrl);
    } catch (error: any) {
        console.error('Error handling refresh:', error);
        res.status(500).send('Internal server error');
    }
}