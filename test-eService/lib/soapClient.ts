import axios, { AxiosInstance } from "axios";
import https from "https";
import fs from "fs";
import { XMLParser, XMLBuilder } from "fast-xml-parser";
import {
  WSSecurityUtils,
  WSSecurityOptions,
  WSSecurityPolicy,
  WSSecurityError,
} from "./wsSecurity";
import type {
  AuthenticationConfig,
  UseIDResponse,
  GetResultResponse,
  GetServerInfoResponse,
} from "../types/eid";

export class SOAPError extends Error {
  public resultMajor?: string;
  public resultMinor?: string;
  public resultMessage?: string;

  constructor(
    message: string,
    resultMajor?: string,
    resultMinor?: string,
    resultMessage?: string,
  ) {
    super(message);
    this.name = "SOAPError";
    this.resultMajor = resultMajor;
    this.resultMinor = resultMinor;
    this.resultMessage = resultMessage;
  }
}

export class SOAPClient {
  private client: AxiosInstance;
  private parser: XMLParser;
  private builder: XMLBuilder;
  private eidServerUrl: string;
  private wsSecurityUtils?: WSSecurityUtils;
  private wsSecurityEnabled: boolean;

  constructor(
    eidServerUrl: string,
    tlsOptions?: {
      certPath?: string; // Path to PEM certificate file
      keyPath?: string; // Path to PEM private key file
      caPath?: string; // Path to CA certificate file
      cert?: string | Buffer; // Certificate content (PEM format)
      key?: string | Buffer; // Private key content (PEM format)
      ca?: string | Buffer; // CA certificate content (PEM format)
      rejectUnauthorized?: boolean;
      mode?: "normal" | "mtls"; // TLS mode: normal TLS vs mutual TLS
    },
    wsSecurityOptions?: {
      enabled?: boolean;
      privateKey?: string | Buffer;
      certificate?: string | Buffer;
      trustedCertsDir?: string;
      policy?: WSSecurityPolicy;
    },
  ) {
    this.eidServerUrl = eidServerUrl;
    this.wsSecurityEnabled = wsSecurityOptions?.enabled || false;

    // Configure HTTPS agent for TLS/mTLS
    const httpsAgentConfig: any = {
      rejectUnauthorized: tlsOptions?.rejectUnauthorized ?? false, // Accept self-signed certs by default for eID testing
      // Allow legacy renegotiation for older eID-Servers
      secureOptions: require("crypto").constants.SSL_OP_LEGACY_SERVER_CONNECT,
    };

    // Handle certificate loading from paths or direct content
    let certContent: Buffer | undefined;
    let keyContent: Buffer | undefined;
    let caContent: Buffer | undefined;

    // Load certificates from paths if provided
    if (tlsOptions?.certPath && tlsOptions?.keyPath) {
      try {
        certContent = fs.readFileSync(tlsOptions.certPath);
        keyContent = fs.readFileSync(tlsOptions.keyPath);
        console.log("✅ Loaded mTLS certificates from files");
      } catch (error: any) {
        console.error("❌ Error loading certificate files:", error.message);
        throw new Error(`Failed to load certificate files: ${error.message}`);
      }
    }

    // Load CA certificate from path if provided
    if (tlsOptions?.caPath) {
      try {
        caContent = fs.readFileSync(tlsOptions.caPath);
        console.log("✅ Loaded CA certificate from file");
      } catch (error: any) {
        console.error("❌ Error loading CA file:", error.message);
      }
    }

    // Use direct certificate content if provided (overrides file paths)
    if (tlsOptions?.cert) {
      certContent =
        typeof tlsOptions.cert === "string"
          ? Buffer.from(tlsOptions.cert)
          : tlsOptions.cert;
    }
    if (tlsOptions?.key) {
      keyContent =
        typeof tlsOptions.key === "string"
          ? Buffer.from(tlsOptions.key)
          : tlsOptions.key;
    }
    if (tlsOptions?.ca) {
      caContent =
        typeof tlsOptions.ca === "string"
          ? Buffer.from(tlsOptions.ca)
          : tlsOptions.ca;
    }

    // Configure mTLS if in mutual TLS mode or if certificates are provided
    const isMTLS = tlsOptions?.mode === "mtls" || (certContent && keyContent);

    if (isMTLS && certContent && keyContent) {
      httpsAgentConfig.cert = certContent;
      httpsAgentConfig.key = keyContent;
      console.log(
        "🔒 Configured mutual TLS (mTLS) for eID-Server communication",
      );
    } else if (isMTLS) {
      console.warn("⚠️  mTLS mode requested but certificates not provided");
    } else {
      console.log("🔐 Using normal TLS for eID-Server communication");
    }

    // Add CA certificate if provided
    if (caContent) {
      httpsAgentConfig.ca = caContent;
      console.log("📜 Added CA certificate for certificate validation");
    }

    // For eID testing, accept self-signed certificates
    if (!tlsOptions?.rejectUnauthorized && !caContent) {
      console.log("⚠️  Accepting self-signed certificates (eID testing mode)");
    }

    // Initialize WS-Security if enabled
    if (
      this.wsSecurityEnabled &&
      wsSecurityOptions?.privateKey &&
      wsSecurityOptions?.certificate
    ) {
      try {
        this.wsSecurityUtils = new WSSecurityUtils({
          privateKey: wsSecurityOptions.privateKey,
          certificate: wsSecurityOptions.certificate,
          trustedCertsDir: wsSecurityOptions.trustedCertsDir, // Pass trustedCertsDir
          policy: wsSecurityOptions.policy,
        });
        console.log("🔐 WS-Security enabled for SOAP messages");
      } catch (error: any) {
        console.error("❌ Failed to initialize WS-Security:", error.message);
        throw new Error(`WS-Security initialization failed: ${error.message}`);
      }
    } else if (this.wsSecurityEnabled) {
      console.warn("⚠️  WS-Security enabled but certificates not provided");
    }

    const httpsAgent = new https.Agent(httpsAgentConfig);

    this.client = axios.create({
      httpsAgent,
      timeout: 30000,
      headers: {
        "Content-Type": "text/xml;charset=UTF-8",
        SOAPAction: "",
      },
    });

    // Add request interceptor for debugging
    this.client.interceptors.request.use(
      (config) => {
        console.log("SOAP Request:", {
          url: config.url,
          method: config.method,
          headers: config.headers,
          data: config.data,
        });
        return config;
      },
      (error) => {
        console.error("SOAP Request Error:", error);
        return Promise.reject(error);
      },
    );

    // Add response interceptor for debugging
    this.client.interceptors.response.use(
      (response) => {
        console.log("SOAP Response:", {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
          data: response.data,
        });
        return response;
      },
      (error) => {
        console.error("SOAP Response Error:", error);
        if (error.response) {
          console.error("Response Data:", error.response.data);
          console.error("Response Status:", error.response.status);
          console.error("Response Headers:", error.response.headers);
        }
        return Promise.reject(error);
      },
    );

    this.parser = new XMLParser({
      ignoreAttributes: false,
      removeNSPrefix: true,
      parseTagValue: false,
    });

    this.builder = new XMLBuilder({
      ignoreAttributes: false,
      format: false,
      suppressEmptyNode: true,
    });
  }

  private buildUseIDRequest(config: AuthenticationConfig): string {
    const request: any = {
      "?xml": {
        "@_version": "1.0",
        "@_encoding": "UTF-8",
      },
      "soapenv:Envelope": {
        "@_xmlns:soapenv": "http://schemas.xmlsoap.org/soap/envelope/",
        "@_xmlns:eid": "http://bsi.bund.de/eID/",
        "soapenv:Header": {},
        "soapenv:Body": {
          "eid:useIDRequest": {
            "eid:UseOperations": {},
          },
        },
      },
    };

    const useOperations =
      request["soapenv:Envelope"]["soapenv:Body"]["eid:useIDRequest"][
        "eid:UseOperations"
      ];

    // Add all operations
    Object.entries(config.operations).forEach(([key, value]) => {
      if (value !== "PROHIBITED") {
        useOperations[`eid:${key}`] = value;
      }
    });

    const useIDRequest =
      request["soapenv:Envelope"]["soapenv:Body"]["eid:useIDRequest"];

    // Add AgeVerification if enabled
    if (config.ageVerification) {
      useIDRequest["eid:AgeVerificationRequest"] = {
        "eid:Age": config.ageVerification.age,
      };
    }

    // Add PlaceVerification if enabled
    if (config.placeVerification) {
      useIDRequest["eid:PlaceVerificationRequest"] = {
        "eid:CommunityID": config.placeVerification.communityId,
      };
    }

    // Add TransactionInfo if enabled
    if (config.transactionInfo) {
      useIDRequest["eid:TransactionInfo"] = config.transactionInfo.info;
    }

    // Add TransactionAttestation if enabled
    if (config.transactionAttestation) {
      useIDRequest["eid:TransactionAttestationRequest"] = {
        "eid:TransactionAttestationFormat":
          config.transactionAttestation.format,
        "eid:TransactionContext": config.transactionAttestation.context,
      };
    }

    // Add LevelOfAssurance if specified
    if (config.levelOfAssurance) {
      useIDRequest["eid:LevelOfAssuranceRequest"] = config.levelOfAssurance;
    }

    // Add EIDTypeRequest if any types are specified
    const eidTypes = Object.entries(config.eidTypeRequest).filter(
      ([_, value]) => value,
    );
    if (eidTypes.length > 0) {
      useIDRequest["eid:EIDTypeRequest"] = {};
      eidTypes.forEach(([key, value]) => {
        useIDRequest["eid:EIDTypeRequest"][`eid:${key}`] = value;
      });
    }

    return this.builder.build(request);
  }

  private buildGetResultRequest(
    sessionId: string,
    requestCounter: number = 1,
  ): string {
    const request = {
      "?xml": {
        "@_version": "1.0",
        "@_encoding": "UTF-8",
      },
      "soapenv:Envelope": {
        "@_xmlns:soapenv": "http://schemas.xmlsoap.org/soap/envelope/",
        "@_xmlns:eid": "http://bsi.bund.de/eID/",
        "soapenv:Header": {},
        "soapenv:Body": {
          "eid:getResultRequest": {
            "eid:Session": {
              "eid:ID": sessionId,
            },
            "eid:RequestCounter": requestCounter,
          },
        },
      },
    };

    return this.builder.build(request);
  }

  async callUseID(config: AuthenticationConfig): Promise<UseIDResponse> {
    let soapRequest = this.buildUseIDRequest(config);

    // Apply WS-Security if enabled
    if (this.wsSecurityEnabled && this.wsSecurityUtils) {
      try {
        soapRequest = this.wsSecurityUtils.signSOAPEnvelope(soapRequest);
        console.log("🔏 useID request signed with WS-Security");
      } catch (error: any) {
        console.error("❌ Failed to sign useID request:", error.message);
        throw new Error(`WS-Security signing failed: ${error.message}`);
      }
    }

    console.log("Sending useID request:", soapRequest);

    try {
      const response = await this.client.post(this.eidServerUrl, soapRequest);
      const parsed = this.parser.parse(response.data);

      // Verify WS-Security signature if enabled and not a SOAP fault
      if (
        this.wsSecurityEnabled &&
        this.wsSecurityUtils &&
        !parsed.Envelope?.Body?.ResultMajor?.includes("error")
      ) {
        try {
          const isVerified = this.wsSecurityUtils.verifySOAPEnvelope(
            response.data,
          );
          if (!isVerified) {
            throw new WSSecurityError(
              "useID response signature verification failed.",
            );
          }
          console.log("✅ useID response signature verified.");
        } catch (error: any) {
          console.error(
            "❌ Failed to verify useID response signature:",
            error.message,
          );
          throw new Error(`WS-Security verification failed: ${error.message}`);
        }
      }

      console.log("Received useID response:", JSON.stringify(parsed, null, 2));

      const useIDResponse = parsed.Envelope?.Body?.useIDResponse;

      if (!useIDResponse) {
        throw new Error("Invalid useID response structure");
      }

      return {
        Session: {
          ID: useIDResponse.Session.ID,
        },
        PSK: {
          ID: useIDResponse.PSK.ID,
          Key: useIDResponse.PSK.Key,
        },
        eCardServerAddress: useIDResponse.eCardServerAddress,
        Result: {
          ResultMajor:
            useIDResponse.Result?.ResultMajor ||
            "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok",
          ResultMinor: useIDResponse.Result?.ResultMinor,
          ResultMessage: useIDResponse.Result?.ResultMessage,
        },
      };
    } catch (error: any) {
      console.error("Error calling useID:", error.message);
      if (error.response) {
        console.error("Response data:", error.response.data);
      }
      throw new Error(`Failed to call useID: ${error.message}`);
    }
  }

  async callGetResult(
    sessionId: string,
    requestCounter: number = 1,
  ): Promise<GetResultResponse> {
    let soapRequest = this.buildGetResultRequest(sessionId, requestCounter);

    // Apply WS-Security if enabled
    if (this.wsSecurityEnabled && this.wsSecurityUtils) {
      try {
        soapRequest = this.wsSecurityUtils.signSOAPEnvelope(soapRequest);
        console.log("🔏 getResult request signed with WS-Security");
      } catch (error: any) {
        console.error("❌ Failed to sign getResult request:", error.message);
        throw new Error(`WS-Security signing failed: ${error.message}`);
      }
    }

    console.log("Sending getResult request:", soapRequest);

    try {
      const response = await this.client.post(this.eidServerUrl, soapRequest);
      const parsed = this.parser.parse(response.data);

      // Verify WS-Security signature if enabled and not a SOAP fault
      if (
        this.wsSecurityEnabled &&
        this.wsSecurityUtils &&
        !parsed.Envelope?.Body?.ResultMajor?.includes("error")
      ) {
        try {
          const isVerified = this.wsSecurityUtils.verifySOAPEnvelope(
            response.data,
          );
          if (!isVerified) {
            throw new WSSecurityError(
              "getResult response signature verification failed.",
            );
          }
          console.log("✅ getResult response signature verified.");
        } catch (error: any) {
          console.error(
            "❌ Failed to verify getResult response signature:",
            error.message,
          );
          throw new Error(`WS-Security verification failed: ${error.message}`);
        }
      }

      console.log(
        "Received getResult response:",
        JSON.stringify(parsed, null, 2),
      );

      const getResultResponse = parsed.Envelope?.Body?.getResultResponse;
      const soapBody = parsed.Envelope?.Body;

      // Handle cases where the eID-Server returns a direct error in the SOAP body
      if (!getResultResponse && soapBody && soapBody.ResultMajor) {
        console.warn("Received direct SOAP error from eID-Server");
        throw new SOAPError(
          "eID-Server returned a direct error",
          soapBody.ResultMajor,
          soapBody.ResultMinor,
          soapBody.ResultMessage,
        );
      }

      if (!getResultResponse) {
        throw new Error("Invalid getResult response structure");
      }

      // Manually construct the response to ensure only returned fields are included
      const result: GetResultResponse = {
        Result: getResultResponse.Result,
      };

      if (getResultResponse.PersonalData) {
        result.PersonalData = getResultResponse.PersonalData;
      }
      if (getResultResponse.FulfilsAgeVerification) {
        result.FulfilsAgeVerification =
          getResultResponse.FulfilsAgeVerification;
      }
      if (getResultResponse.FulfilsPlaceVerification) {
        result.FulfilsPlaceVerification =
          getResultResponse.FulfilsPlaceVerification;
      }
      if (getResultResponse.OperationsAllowedByUser) {
        result.OperationsAllowedByUser =
          getResultResponse.OperationsAllowedByUser;
      }
      if (getResultResponse.TransactionAttestationResponse) {
        result.TransactionAttestationResponse =
          getResultResponse.TransactionAttestationResponse;
      }
      if (getResultResponse.LevelOfAssuranceResult) {
        result.LevelOfAssuranceResult =
          getResultResponse.LevelOfAssuranceResult;
      }
      if (getResultResponse.EIDTypeResponse) {
        result.EIDTypeResponse = getResultResponse.EIDTypeResponse;
      }

      return result;
    } catch (error: any) {
      console.error("Error calling getResult:", error.message);
      if (error.response) {
        console.error("Response data:", error.response.data);
      }
      // Re-throw custom SOAP errors
      if (error instanceof SOAPError) {
        throw error;
      }
      throw new Error(`Failed to call getResult: ${error.message}`);
    }
  }

  private buildGetServerInfoRequest(): string {
    const request = {
      "?xml": {
        "@_version": "1.0",
        "@_encoding": "UTF-8",
      },
      "soapenv:Envelope": {
        "@_xmlns:soapenv": "http://schemas.xmlsoap.org/soap/envelope/",
        "@_xmlns:eid": "http://bsi.bund.de/eID/",
        "soapenv:Header": {},
        "soapenv:Body": {
          "eid:getServerInfoRequest": {},
        },
      },
    };

    return this.builder.build(request);
  }

  async callGetServerInfo(): Promise<GetServerInfoResponse> {
    let soapRequest = this.buildGetServerInfoRequest();

    // Apply WS-Security if enabled
    if (this.wsSecurityEnabled && this.wsSecurityUtils) {
      try {
        soapRequest = this.wsSecurityUtils.signSOAPEnvelope(soapRequest);
        console.log("🔏 getServerInfo request signed with WS-Security");
      } catch (error: any) {
        console.error(
          "❌ Failed to sign getServerInfo request:",
          error.message,
        );
        throw new Error(`WS-Security signing failed: ${error.message}`);
      }
    }

    console.log("Sending getServerInfo request:", soapRequest);

    try {
      const response = await this.client.post(this.eidServerUrl, soapRequest);
      const parsed = this.parser.parse(response.data);

      // Verify WS-Security signature if enabled and not a SOAP fault
      if (
        this.wsSecurityEnabled &&
        this.wsSecurityUtils &&
        !parsed.Envelope?.Body?.ResultMajor?.includes("error")
      ) {
        try {
          const isVerified = this.wsSecurityUtils.verifySOAPEnvelope(
            response.data,
          );
          if (!isVerified) {
            throw new WSSecurityError(
              "getServerInfo response signature verification failed.",
            );
          }
          console.log("✅ getServerInfo response signature verified.");
        } catch (error: any) {
          console.error(
            "❌ Failed to verify getServerInfo response signature:",
            error.message,
          );
          throw new Error(`WS-Security verification failed: ${error.message}`);
        }
      }

      console.log(
        "Received getServerInfo response:",
        JSON.stringify(parsed, null, 2),
      );

      const getServerInfoResponse =
        parsed.Envelope?.Body?.getServerInfoResponse;
      const soapBody = parsed.Envelope?.Body;

      // Handle cases where the eID-Server returns a direct error in the SOAP body
      if (!getServerInfoResponse && soapBody && soapBody.ResultMajor) {
        console.warn("Received direct SOAP error from eID-Server");
        throw new SOAPError(
          "eID-Server returned a direct error",
          soapBody.ResultMajor,
          soapBody.ResultMinor,
          soapBody.ResultMessage,
        );
      }

      if (!getServerInfoResponse) {
        throw new Error("Invalid getServerInfo response structure");
      }

      // Filter out empty/null rights from the response
      const rights = getServerInfoResponse.DocumentVerificationRights;
      if (rights) {
        Object.keys(rights).forEach((key) => {
          if (rights[key] === null || rights[key] === "") {
            delete rights[key];
          }
        });
      }

      return getServerInfoResponse as GetServerInfoResponse;
    } catch (error: any) {
      console.error("Error calling getServerInfo:", error.message);
      if (error.response) {
        console.error("Response data:", error.response.data);
      }
      // Re-throw custom SOAP errors
      if (error instanceof SOAPError) {
        throw error;
      }
      throw new Error(`Failed to call getServerInfo: ${error.message}`);
    }
  }
}
