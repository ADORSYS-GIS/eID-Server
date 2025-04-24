# eID-Server

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
