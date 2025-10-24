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

Before running the server, ensure you have the following tools installed:

- [Rust & Cargo](https://www.rust-lang.org/tools/install) (Latest stable version recommended).
- [Redis](https://redis.io/download) (Optional): Used for persistent session management. The server defaults to a temporary in-memory store if Redis is not configured.

**Clone the Repository:**

```bash
git clone https://github.com/ADORSYS-GIS/eID-Server.git
cd eID-Server
```

### Configuration

The server needs some configuration to run. You can either use a configuration file or environment variables.

**Configuration file:**

```bash
mkdir -p config
touch config/settings.toml
```

Add basic configuration. By default, the server will use a temporary in-memory session store.

```toml
[server]
host = "127.0.0.1"
port = 8080
```

To enable persistent sessions with Redis, uncomment the following section.

```toml
#[redis]
#uri = "redis://127.0.0.1:6379"
```

**Environment Variables:**

You can also configure the server using environment variables. By default, no Redis connection is needed. To enable it, set the **APP_REDIS\_\_URI** variable. See the [.env.example](.env.example) file for more details.

### Running with Docker Compose

The simplest way to run the project is with [docker compose](https://docs.docker.com/compose/):

- Execute the command below at the root of the project

```sh
docker compose up --build -d
```

This command will pull all required images and start the server.

### Running Manually

You can run the server directly with `Cargo`. If you have configured a Redis URI, ensure the Redis server is running first.

```bash
cargo run
```

By default, the server will listen on `https://localhost:3000`. You can modify the host and port in the configuration settings.

### Running Tests

```bash
cargo test
```

## Testing the Online Authentication Flow

A test eService is available in the [`test-eService`](test-eService) directory. It can be used to set up a test environment with the eID-Server and an eID-Client, allowing to test different behaviors of the online authentication flow.

For setup and usage instructions, please refer to the [`README.md`](test-eService/README.md:1) in the `test-eService` directory.
