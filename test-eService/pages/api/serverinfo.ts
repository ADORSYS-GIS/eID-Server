import { NextApiRequest, NextApiResponse } from "next";
import { SOAPClient, SOAPError } from "@/lib/soapClient";

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
) {
  if (req.method !== "GET") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    // Get eID-Server URL
    const eidServerUrl =
      process.env.EID_SERVER_URL || "https://localhost:8443/eIDService";

    // Initialize SOAP client
    const tlsOptions = {
      rejectUnauthorized: process.env.NODE_ENV === "production",
    };

    // Configure WS-Security options (reuse existing certificates if enabled)
    const wsSecurityOptions = {
      enabled: process.env.WS_SECURITY_ENABLED === "true",
      privateKey: process.env.HTTPS_KEY_PATH || process.env.HTTPS_KEY,
      certificate: process.env.HTTPS_CERT_PATH || process.env.HTTPS_CERT,
      trustedCertsDir: "./certs/",
    };

    const soapClient = new SOAPClient(eidServerUrl, tlsOptions, wsSecurityOptions);

    // Call getServerInfo on eID-Server
    const getServerInfoResponse = await soapClient.callGetServerInfo();

    // Return result data
    res.status(200).json(getServerInfoResponse);
  } catch (error: any) {
    console.error("Error getting server info:", error);

    // Handle custom SOAP errors
    if (error instanceof SOAPError) {
      return res.status(500).json({
        error: "eID-Server returned an error",
        resultMajor: error.resultMajor,
        resultMinor: error.resultMinor,
        resultMessage: error.resultMessage,
      });
    }

    res.status(500).json({
      error: "Failed to get server info",
      message: error.message,
    });
  }
}
