import { NextApiRequest, NextApiResponse } from "next";
import { SOAPClient, SOAPError } from "@/lib/soapClient";
import { sessionManager } from "@/lib/sessionManager";
import fs from "fs";

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
) {
  if (req.method !== "GET") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { token } = req.query;

    if (!token || typeof token !== "string") {
      return res
        .status(400)
        .json({ error: "Missing or invalid token parameter" });
    }

    // Get session data
    const session = await sessionManager.getSession(token);

    if (!session) {
      return res.status(404).json({ error: "Session not found or expired" });
    }

    // Check if the eID-Client reported an error
    if (session.resultMajor && session.resultMajor.includes("error")) {
      console.log("eID-Client reported an error, not calling getResult.");
      return res.status(200).json({
        success: false,
        result: {
          ResultMajor: session.resultMajor,
          ResultMinor: session.resultMinor,
          ResultMessage:
            "eID-Client reported an error during the authentication process.",
        },
      });
    }

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

    // Call getResult on eID-Server
    console.log("Calling getResult for session:", session.sessionId);
    const getResultResponse = await soapClient.callGetResult(session.sessionId);

    // Return result data
    res.status(200).json({
      success: getResultResponse.Result.ResultMajor.includes("#ok"),
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
    console.error("Error getting result:", error);

    // Handle custom SOAP errors
    if (error instanceof SOAPError) {
      return res.status(200).json({
        success: false,
        result: {
          ResultMajor: error.resultMajor,
          ResultMinor: error.resultMinor,
          ResultMessage: error.resultMessage,
        },
      });
    }

    res.status(500).json({
      error: "Failed to get authentication result",
      message: error.message,
      cause: error.cause,
      description: error.description,
    });
  }
}
