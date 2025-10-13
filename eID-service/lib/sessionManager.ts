import { v4 as uuidv4 } from 'uuid';
import type { SessionData, AuthenticationConfig } from '@/types/eid';
import fs from 'fs/promises';
import path from 'path';

// Define the path for the session storage directory
const SESSIONS_DIR = path.join(process.cwd(), '.sessions');

class SessionManager {
    private readonly SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes

    constructor() {
        this.ensureSessionsDir();
        // Cleanup expired sessions every 5 minutes
        setInterval(() => this.cleanupExpiredSessions(), 5 * 60 * 1000);
    }

    private async ensureSessionsDir() {
        try {
            await fs.mkdir(SESSIONS_DIR, { recursive: true });
        } catch (error) {
            console.error('Failed to create session directory:', error);
        }
    }

    private getSessionFilePath(token: string): string {
        // Basic sanitization to prevent path traversal
        if (!/^[a-f0-9-]+$/.test(token)) {
            throw new Error('Invalid token format');
        }
        return path.join(SESSIONS_DIR, `${token}.json`);
    }

    async createConfigurationSession(config: AuthenticationConfig): Promise<string> {
        const token = uuidv4();
        const sessionData: SessionData = {
            sessionId: '',
            pskId: '',
            pskKey: '',
            eCardServerAddress: undefined,
            config,
            startTime: Date.now(),
        };

        const filePath = this.getSessionFilePath(token);
        await fs.writeFile(filePath, JSON.stringify(sessionData, null, 2));

        console.log(`Created configuration session file for token: ${token}`);
        return token;
    }

    async updateSessionWithUseIDResponse(
        token: string,
        sessionId: string,
        pskId: string,
        pskKey: string,
        eCardServerAddress?: string
    ): Promise<boolean> {
        try {
            const session = await this.getSession(token);
            if (!session) {
                return false;
            }

            session.sessionId = sessionId;
            session.pskId = pskId;
            session.pskKey = pskKey;
            session.eCardServerAddress = eCardServerAddress;
            
            const filePath = this.getSessionFilePath(token);
            await fs.writeFile(filePath, JSON.stringify(session, null, 2));
            
            console.log(`Updated session with useID response for token: ${token}`);
            return true;
        } catch (error) {
            console.error(`Error updating session for token ${token}:`, error);
            return false;
        }
    }

    async updateSession(
        token: string,
        dataToUpdate: Partial<SessionData>
    ): Promise<boolean> {
        try {
            const session = await this.getSession(token);
            if (!session) {
                return false;
            }

            // Merge new data into the existing session
            const updatedSession = { ...session, ...dataToUpdate };
            
            const filePath = this.getSessionFilePath(token);
            await fs.writeFile(filePath, JSON.stringify(updatedSession, null, 2));
            
            console.log(`Updated session for token: ${token}`);
            return true;
        } catch (error) {
            console.error(`Error updating session for token ${token}:`, error);
            return false;
        }
    }

    async updateSessionWithClientResult(
        token: string,
        resultMajor?: string,
        resultMinor?: string
    ): Promise<boolean> {
        try {
            const session = await this.getSession(token);
            if (!session) {
                return false;
            }

            session.resultMajor = resultMajor;
            session.resultMinor = resultMinor;
            
            const filePath = this.getSessionFilePath(token);
            await fs.writeFile(filePath, JSON.stringify(session, null, 2));
            
            console.log(`Updated session with client result for token: ${token}`);
            return true;
        } catch (error) {
            console.error(`Error updating session for token ${token}:`, error);
            return false;
        }
    }

    async getSession(token: string): Promise<SessionData | undefined> {
        try {
            const filePath = this.getSessionFilePath(token);
            const fileContent = await fs.readFile(filePath, 'utf-8');
            const session = JSON.parse(fileContent) as SessionData;

            // Check if session has expired
            if (Date.now() - session.startTime > this.SESSION_TIMEOUT) {
                console.log(`Session expired for token: ${token}`);
                await this.deleteSession(token);
                return undefined;
            }

            return session;
        } catch (error: any) {
            // If file not found, it's a valid "not found" case
            if (error.code === 'ENOENT') {
                console.log(`Session file not found for token: ${token}`);
            } else {
                console.error(`Error reading session for token ${token}:`, error);
            }
            return undefined;
        }
    }

    async deleteSession(token: string): Promise<boolean> {
        try {
            const filePath = this.getSessionFilePath(token);
            await fs.unlink(filePath);
            console.log(`Deleted session file for token: ${token}`);
            return true;
        } catch (error: any) {
             if (error.code !== 'ENOENT') {
                console.error(`Error deleting session file for token ${token}:`, error);
            }
            return false;
        }
    }

    private async cleanupExpiredSessions(): Promise<void> {
        try {
            const files = await fs.readdir(SESSIONS_DIR);
            let cleanedCount = 0;
            const now = Date.now();

            for (const file of files) {
                if (path.extname(file) === '.json') {
                    const token = path.basename(file, '.json');
                    const filePath = path.join(SESSIONS_DIR, file);
                    try {
                        const fileContent = await fs.readFile(filePath, 'utf-8');
                        const session = JSON.parse(fileContent) as SessionData;
                        if (now - session.startTime > this.SESSION_TIMEOUT) {
                            await fs.unlink(filePath);
                            cleanedCount++;
                        }
                    } catch (readError) {
                        // Could be a corrupted file, delete it
                        console.error(`Error reading session file ${file} during cleanup, deleting.`, readError);
                        await fs.unlink(filePath).catch(delError => console.error(`Failed to delete corrupted session file ${file}`, delError));
                    }
                }
            }

            if (cleanedCount > 0) {
                console.log(`Cleaned up ${cleanedCount} expired sessions`);
            }
        } catch (error: any) {
            if (error.code !== 'ENOENT') {
               console.error('Error during session cleanup:', error);
            }
        }
    }
}

// Singleton setup remains important to avoid re-creating intervals etc.
declare global {
    var sessionManager: SessionManager | undefined;
}

export const sessionManager = global.sessionManager || new SessionManager();

if (process.env.NODE_ENV !== 'production') {
    global.sessionManager = sessionManager;
}