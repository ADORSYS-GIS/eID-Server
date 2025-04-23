# eID Server (SOAP-based Implementation)

This project implements a secure and specification-compliant **eID Server** that facilitates electronic identity authentication via SOAP. It supports the German eID card (nPA) and follows the **TR-03130** guidelines for secure middleware services.

## 📌 Features

- 🧾 **SOAP-based Authentication Flow**  
- 🔐 **Extended Access Control (EAC)** via smartcard  
- 📄 **SAML Assertion Generation** for service providers  
- 🧩 Modular architecture supporting custom clients  
- 🛡️ Standards-compliant security and cryptographic flow

## 🧱 Architecture Overview

The eID Server enables identity verification using a SOAP-based flow between the following key components:

### 🔁 Flow Overview

1. User initiates login via the Service Provider (SP).
2. SP redirects to eID-Server with a SAML AuthnRequest.
3. eID-Server returns a redirect/POST to initiate a SOAP/PAOS session.
4. eID-Client (AusweisApp2 or custom app) connects and initiates authentication.
5. eID-Server interacts via EAC protocol with the eID card through the client.
6. On success, SAML Assertion is sent back to the SP.

![interaction](/assets/interaction.png)
🖇️ *Currently implemented interface:* **SOAP (PAOS over HTTP)**  
🧩 *Alternative (not yet active):* **SAML Binding (HTTP Redirect or POST)**

### Documentation

- [PART1: Functional Specification ](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03130/TR-03130_TR-eID-Server_Part1.pdf%3F__blob%3DpublicationFile%26v%3D3&ved=2ahUKEwi8h_6JmfOLAxVyh_0HHTUBDGQQFnoECBcQAQ&usg=AOvVaw2B5V0hVmpZOFd66L2rIZma)
- [PART2: Security Framework]( https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03130/TR-03130_TR-eID-Server_Part2.pdf%3F__blob%3DpublicationFile%26v%3D1&ved=2ahUKEwjVjKPll_OLAxV4h_0HHZwILwIQFnoECBIQAQ&usg=AOvVaw2aqgwqEugxgDRt5vKJPYbA)
- [PART3: eIDAS Middleware Service](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03130/TR-03130_TR-eID-Server_Part3.pdf%3F__blob%3DpublicationFile%26v%3D3&ved=2ahUKEwi05svemfOLAxWq9QIHHbULA7cQFnoECBQQAQ&usg=AOvVaw2dKYFkKYEft2YHrgvPpoEs)
- [PART4: Conformance Test Specification](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03130/TR-03130_TR-eID-Server_Part4.pdf%3F__blob%3DpublicationFile%26v%3D3&ved=2ahUKEwjz5LeBmvOLAxWA1QIHHeaaOs0QFnoECBIQAQ&usg=AOvVaw2H0mqv1Vbwug876oGm7WD-)