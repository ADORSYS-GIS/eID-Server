import { NextApiRequest, NextApiResponse } from "next";
import { SOAPClient, SOAPError } from "@/lib/soapClient";
import fs from "fs";

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

    // Read certificate and key from file paths if provided
    // Read certificate and key from file paths. Ensure paths are configured.
    if (!process.env.HTTPS_KEY_PATH || !process.env.HTTPS_CERT_PATH) {
      throw new Error(
        "Missing HTTPS_KEY_PATH or HTTPS_CERT_PATH environment variables for WS-Security",
      );
    }
    const privateKey = fs.readFileSync(process.env.HTTPS_KEY_PATH, "utf-8");
    const certificate = fs.readFileSync(process.env.HTTPS_CERT_PATH, "utf-8");

    // Configure WS-Security options
    const wsSecurityOptions = {
      enabled: process.env.WS_SECURITY_ENABLED === "true",
      privateKey: privateKey,
      certificate: certificate,
      trustedCertsDir: "./certs/",
    };

    const soapClient = new SOAPClient(
      eidServerUrl,
      tlsOptions,
      wsSecurityOptions,
    );

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
