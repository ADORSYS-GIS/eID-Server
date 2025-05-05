# eID Server (SOAP-based Implementation)

This project implements a secure and specification-compliant **eID Server** that facilitates electronic identity authentication via SOAP. It supports the German eID card (nPA) and follows the **TR-03130** guidelines for secure middleware services.

## Features

- SOAP-based Authentication Flow
- Extended Access Control (EAC) via smartcard
- SAML Assertion Generation for service providers
- Modular architecture supporting custom clients
- Standards-compliant security and cryptographic flow

## Architecture Overview

The eID Server enables identity verification using a SOAP-based flow between the following key components:

### Flow Overview

1. User initiates login via the Service Provider (SP).
2. SP redirects to eID-Server with a SAML AuthnRequest.
3. eID-Server returns a redirect/POST to initiate a SOAP/PAOS session.
4. eID-Client (AusweisApp2 or custom app) connects and initiates authentication.
5. eID-Server interacts via EAC protocol with the eID card through the client.
6. On success, SAML Assertion is sent back to the SP.

### Functional Diagram

![functional](/assets/functional.png)

### Interaction Diagram

![interaction](/assets/interaction.png)

🖇️ _Currently implemented interface:_ **SOAP (PAOS over HTTP)**  
🧩 _Alternative (not yet active):_ **SAML Binding (HTTP Redirect or POST)**

### Documentation

- [PART1: Functional Specification](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03130/TR-03130_TR-eID-Server_Part1.pdf?__blob=publicationFile&v=3)
- [PART2: Security Framework](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03130/TR-03130_TR-eID-Server_Part2.pdf?__blob=publicationFile&v=1)
- [PART3: eIDAS Middleware Service](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03130/TR-03130_TR-eID-Server_Part3.pdf?__blob=publicationFile&v=3)
- [PART4: Conformance Test Specification](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03130/TR-03130_TR-eID-Server_Part4.pdf?__blob=publicationFile&v=3)

## Getting Started

### Prerequisites

- [Rust & Cargo](https://www.rust-lang.org/tools/install) (latest stable version)

### Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/ADORSYS-GIS/eID-Server.git
   cd eID-Server
   ```

2. Create a configuration file:

   ```bash
   mkdir -p config
   touch config/settings.toml
   ```

   Add basic configuration:

   ```toml
   [server]
   host = "127.0.0.1"
   port = 8080
   ```

   You can also use environment variables to configure the server:

   ```sh
   export APP_SERVER_HOST=127.0.0.1
   export APP_SERVER_PORT=8080
   ```

3. Build and run the project:

   ```bash
   cargo run
   ```

### Running Tests

```bash
cargo test
```
