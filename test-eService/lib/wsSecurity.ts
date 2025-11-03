import * as crypto from "crypto";
import * as fs from "fs";
import { SignedXml } from "xml-crypto";
import { DOMParser, XMLSerializer } from "xmldom";
import * as forge from "node-forge";

export interface WSSecurityOptions {
  privateKey: string | Buffer;
  certificate: string | Buffer;
  verificationCertificate?: string | Buffer;
  trustedCertsDir?: string;
  algorithm?: string;
  keyIdentifier?: string;
  includeTimestamp?: boolean;
  signatureAlgorithm?: string;
  digestAlgorithm?: string;
}

export interface WSSecurityPolicy {
  asymmetricBinding?: {
    initiatorToken?: {
      x509Token?: {
        includeToken: string;
        requireIssuerSerialReference: boolean;
        wssX509V3Token10: boolean;
      };
    };
    recipientToken?: {
      x509Token?: {
        includeToken: string;
        requireIssuerSerialReference: boolean;
        wssX509V3Token10: boolean;
      };
    };
    algorithmSuite?: string;
    layout?: string;
    includeTimestamp?: boolean;
    onlySignEntireHeadersAndBody?: boolean;
  };
  wss10?: {
    mustSupportRefIssuerSerial?: boolean;
  };
  signedParts?: string[];
}

export class WSSecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WSSecurityError";
  }
}

export class WSSecurityUtils {
  private privateKey: string;
  private certificate: string;
  private verificationCertificate?: string;
  private trustedCertsDir?: string;
  private policy: WSSecurityPolicy;
  private soapenvNamespace = "http://schemas.xmlsoap.org/soap/envelope/";
  private utilityNamespace =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

  constructor(options: WSSecurityOptions & { policy?: WSSecurityPolicy }) {
    this.privateKey =
      typeof options.privateKey === "string"
        ? options.privateKey
        : options.privateKey.toString();

    this.certificate =
      typeof options.certificate === "string"
        ? options.certificate
        : options.certificate.toString();

    if (options.verificationCertificate) {
      this.verificationCertificate =
        typeof options.verificationCertificate === "string"
          ? options.verificationCertificate
          : options.verificationCertificate.toString();
    }

    this.trustedCertsDir = options.trustedCertsDir;

    this.policy = options.policy || this.getDefaultPolicy();
  }

  private getDefaultPolicy(): WSSecurityPolicy {
    return {
      asymmetricBinding: {
        initiatorToken: {
          x509Token: {
            includeToken:
              "http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/Never",
            requireIssuerSerialReference: true,
            wssX509V3Token10: true,
          },
        },
        recipientToken: {
          x509Token: {
            includeToken:
              "http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/Never",
            requireIssuerSerialReference: true,
            wssX509V3Token10: true,
          },
        },
        algorithmSuite: "Basic256Sha256",
        layout: "Strict",
        includeTimestamp: true,
        onlySignEntireHeadersAndBody: true,
      },
      wss10: {
        mustSupportRefIssuerSerial: true,
      },
      signedParts: ["Body"],
    };
  }

  /**
   * Sign a SOAP envelope according to WS-Security policy
   */
  signSOAPEnvelope(soapEnvelope: string): string {
    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString(soapEnvelope, "text/xml");

      if (!doc) {
        throw new WSSecurityError("Failed to parse SOAP envelope");
      }

      const envelope = doc.documentElement;
      if (
        envelope.tagName !== "soapenv:Envelope" &&
        envelope.tagName !== "Envelope"
      ) {
        throw new WSSecurityError("Invalid SOAP envelope structure");
      }

      // Create Security header if it doesn't exist
      let header = this.getOrCreateHeader(doc, envelope);
      let security = this.getOrCreateSecurityHeader(doc, header);

      // Add timestamp if required by policy
      let timestampId: string | undefined;
      if (this.policy.asymmetricBinding?.includeTimestamp) {
        const timestampElement = this.addTimestamp(doc, security);
        timestampId = timestampElement.getAttribute("wsu:Id") || undefined;
      }

      const signedXml = new SignedXml({
        privateKey: this.privateKey,
        signatureAlgorithm: this.getSignatureAlgorithm(),
        canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
        publicCert: this.certificate,
      });

      // Configure signature algorithm based on policy
      const digestAlgorithm = this.getDigestAlgorithm();

      // Add reference to the SOAP Body
      doc.documentElement.setAttribute("xmlns:wsu", this.utilityNamespace);

      const body = doc.documentElement.getElementsByTagNameNS(
        this.soapenvNamespace,
        "Body"
      )[0];
      if (!body) {
        throw new WSSecurityError("SOAP Body not found in the envelope.");
      }
      const bodyId = `Body-${this.generateId()}`;
      body.setAttributeNS(this.utilityNamespace, "wsu:Id", bodyId);

      signedXml.addReference({
        xpath: `//*[local-name()='Body']`,
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
        digestAlgorithm: digestAlgorithm,
        uri: `#${bodyId}`,
        inclusiveNamespacesPrefixList: ["wsu"],
      });

      // Add reference to the Timestamp if it exists
      if (timestampId) {
        signedXml.addReference({
          xpath: `//*[local-name()='Timestamp' and namespace-uri()='${this.utilityNamespace}']`,
          transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
          digestAlgorithm: digestAlgorithm,
          uri: `#${timestampId}`,
        });
      }

      signedXml.getKeyInfoContent = () => {
        // Get issuer and serial from the certificate
        const { issuer, serialNumber } = this.getCertificateIssuerSerial();

        return `<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
          <wsse:SecurityTokenReference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <X509Data>
              <X509IssuerSerial>
                <X509IssuerName>${issuer}</X509IssuerName>
                <X509SerialNumber>${serialNumber}</X509SerialNumber>
              </X509IssuerSerial>
            </X509Data>
          </wsse:SecurityTokenReference>
        </KeyInfo>`;
      };

      // Compute signature - use the document directly
      const xmlString = new XMLSerializer().serializeToString(doc);
      signedXml.computeSignature(xmlString, {
        prefix: "ds",
        location: {
          reference: "//*[local-name()='Security']",
          action: "append",
        },
        attrs: {
          Id: `SIG-${this.generateId()}`,
        },
      });

      return signedXml.getSignedXml();
    } catch (error: any) {
      if (error instanceof WSSecurityError) {
        throw error;
      }
      throw new WSSecurityError(
        `Failed to sign SOAP envelope: ${error.message}`
      );
    }
  }

  private getSignatureAlgorithm(): string {
    const algorithmSuite =
      this.policy.asymmetricBinding?.algorithmSuite || "Basic256Sha256";

    switch (algorithmSuite) {
      case "Basic256Sha256":
        return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
      case "Basic128":
        return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
      default:
        return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    }
  }

  private getDigestAlgorithm(): string {
    const algorithmSuite =
      this.policy.asymmetricBinding?.algorithmSuite || "Basic256Sha256";

    switch (algorithmSuite) {
      case "Basic256Sha256":
        return "http://www.w3.org/2001/04/xmlenc#sha256";
      case "Basic128":
        return "http://www.w3.org/2000/09/xmldsig#sha1";
      default:
        return "http://www.w3.org/2001/04/xmlenc#sha256";
    }
  }

  private generateId(): string {
    return crypto.randomBytes(16).toString("hex");
  }

  /**
   * Verify a signed SOAP envelope
   */
  verifySOAPEnvelope(signedSoapEnvelope: string): boolean {
    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString(signedSoapEnvelope, "text/xml");

      if (!doc) {
        throw new WSSecurityError("Failed to parse signed SOAP envelope");
      }

      const signedXml = new SignedXml();

      // KeyInfo Provider for verification
      (signedXml as any).keyInfoProvider = {
        getKeyInfo: (keyInfo: Element) => {
          return keyInfo;
        },
        getKey: (keyInfo: Element) => {
          const x509IssuerSerialElement = keyInfo.getElementsByTagNameNS(
            "http://www.w3.org/2000/09/xmldsig#",
            "X509IssuerSerial"
          )[0];
          if (x509IssuerSerialElement) {
            const issuerName = x509IssuerSerialElement.getElementsByTagNameNS(
              "http://www.w3.org/2000/09/xmldsig#",
              "X509IssuerName"
            )[0]?.textContent;
            const serialNumber = x509IssuerSerialElement.getElementsByTagNameNS(
              "http://www.w3.org/2000/09/xmldsig#",
              "X509SerialNumber"
            )[0]?.textContent;

            if (issuerName && serialNumber && this.trustedCertsDir) {
              try {
                const trustedCert = this.loadCertificateByIssuerSerial(
                  issuerName,
                  serialNumber
                );
                if (trustedCert) {
                  return trustedCert; // Return the public key of the trusted certificate
                }
              } catch (error) {
                console.warn(
                  `Failed to load trusted certificate for IssuerSerial: ${issuerName}, ${serialNumber}`,
                  error
                );
              }
            }
          }
          // Fallback: if dynamic loading fails, use the pre-configured verificationCertificate or client's own cert
          return this.verificationCertificate || this.certificate;
        },
      };

      // Verify signature
      const signatureElement = doc.documentElement.getElementsByTagNameNS(
        "http://www.w3.org/2000/09/xmldsig#",
        "Signature"
      )[0];
      if (!signatureElement) {
        throw new WSSecurityError(
          "No XML Signature found in the SOAP envelope for verification."
        );
      }
      signedXml.loadSignature(signatureElement);
      const result = signedXml.checkSignature(signedSoapEnvelope);

      if (!result) {
        // Explicitly cast signedXml to any to access validationErrors if TypeScript complains
        console.error(
          "Signature verification failed:",
          (signedXml as any).validationErrors
        );
        return false;
      }

      return true;
    } catch (error) {
      console.error("Error verifying signature:", error);
      return false;
    }
  }

  private getOrCreateHeader(doc: Document, envelope: Element): Element {
    const soapenvNamespace = "http://schemas.xmlsoap.org/soap/envelope/";
    let header = envelope.getElementsByTagNameNS(soapenvNamespace, "Header")[0];

    if (!header) {
      header = doc.createElementNS(soapenvNamespace, "soapenv:Header");
      if (envelope.firstChild) {
        envelope.insertBefore(header, envelope.firstChild);
      } else {
        envelope.appendChild(header);
      }
    }

    return header;
  }

  private getOrCreateSecurityHeader(doc: Document, header: Element): Element {
    const securityNamespace =
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    const utilityNamespace =
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    const soapenvNamespace = "http://schemas.xmlsoap.org/soap/envelope/";

    let security = header.getElementsByTagNameNS(
      securityNamespace,
      "Security"
    )[0];

    if (!security) {
      security = doc.createElementNS(securityNamespace, "wsse:Security");
      security.setAttributeNS(soapenvNamespace, "soapenv:mustUnderstand", "1");
      header.appendChild(security);
    }

    return security;
  }

  private addTimestamp(doc: Document, security: Element): Element {
    const utilityNamespace =
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    const timestamp = doc.createElementNS(utilityNamespace, "wsu:Timestamp");
    const timestampId = `TS-${this.generateId()}`;
    timestamp.setAttributeNS(utilityNamespace, "wsu:Id", timestampId);

    const created = doc.createElementNS(utilityNamespace, "wsu:Created");
    created.textContent = new Date().toISOString();

    const expires = doc.createElementNS(utilityNamespace, "wsu:Expires");
    const expiresDate = new Date();
    expiresDate.setMinutes(expiresDate.getMinutes() + 5);
    expires.textContent = expiresDate.toISOString();

    timestamp.appendChild(created);
    timestamp.appendChild(expires);
    security.appendChild(timestamp);

    return timestamp;
  }

  private getCertificateIssuerSerial(): {
    issuer: string;
    serialNumber: string;
  } {
    try {
      const pki = forge.pki;
      const cert = pki.certificateFromPem(this.certificate);

      const issuer = (cert.issuer.attributes as forge.pki.Attribute[])
        .map((attr) => {
          const name = attr.shortName || attr.type || "";
          const value = attr.value || "";
          return `${name.toUpperCase()}=${value}`;
        })
        .join(", ");

      // Convert hex serial number to decimal for XML Digital Signature compliance
      const hexSerialNumber = cert.serialNumber;
      const decimalSerialNumber = BigInt("0x" + hexSerialNumber).toString();

      return { issuer, serialNumber: decimalSerialNumber };
    } catch (error: any) {
      throw new WSSecurityError(
        `Failed to parse certificate for issuer serial: ${error.message}`
      );
    }
  }

  private loadCertificateByIssuerSerial(
    issuerName: string,
    serialNumber: string
  ): string | undefined {
    if (!this.trustedCertsDir) {
      console.warn(
        "No trustedCertsDir configured for certificate verification."
      );
      return undefined;
    }

    try {
      const files = fs.readdirSync(this.trustedCertsDir);
      for (const file of files) {
        if (file.endsWith(".pem") || file.endsWith(".crt")) {
          const certPath = `${this.trustedCertsDir}/${file}`;
          const certContent = fs.readFileSync(certPath, "utf-8");
          try {
            const pki = forge.pki;
            const cert = pki.certificateFromPem(certContent);
            const certIssuer = (cert.issuer.attributes as forge.pki.Attribute[])
              .map((attr) => {
                const name = attr.shortName || attr.type || "";
                const value = attr.value || "";
                return `${name.toUpperCase()}=${value}`;
              })
              .join(", ");

            // Convert hex serial number to decimal for comparison
            const certHexSerialNumber = cert.serialNumber;
            const certDecimalSerialNumber = BigInt(
              "0x" + certHexSerialNumber
            ).toString();

            if (
              certIssuer === issuerName &&
              certDecimalSerialNumber === serialNumber
            ) {
              console.log(`✅ Found matching trusted certificate: ${file}`);
              return certContent; // Return the PEM encoded certificate
            }
          } catch (parseError) {
            console.warn(`Failed to parse certificate ${file}:`, parseError);
          }
        }
      }
    } catch (error) {
      console.error(
        `Error reading trusted certificates from ${this.trustedCertsDir}:`,
        error
      );
    }
    console.warn(
      `❌ No trusted certificate found for Issuer: ${issuerName}, Serial: ${serialNumber}`
    );
    return undefined;
  }
}
