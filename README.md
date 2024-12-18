# Ombrac

**Ombrac** is a high-performance, Rust-based TCP tunneling solution designed for secure communication between clients and servers.

## Features
- Optionally pass through SOCKS
- Encryption is ensured by the built-in TLS layer of QUIC
- Employs QUIC multiplexing with bidirectional streams for efficient transmission

[![Apache 2.0 Licensed][license-badge]][license-url]
[![Build Status][actions-badge]][actions-url]

## Architecture
Ombrac is organized into three main crates

- `ombrac`: Core library implementing the tunnel protocol
- `ombrac-client`: Ombrac client implementation
- `ombrac-server`: Ombrac server implementation


## Install
### From Binary Releases
Download the latest release from the [releases page](https://github.com/ombrac/ombrac/releases).

### From Source
```shell
cargo build --bin ombrac-client --bin ombrac-server --features binary
```
**NOTE**: On linux systems, [`aws-lc-rs`](https://github.com/aws/aws-lc-rs) will be used for cryptographic operations. A C compiler and CMake may be required on these systems for installation.

## Quick Start
### ServerSetup
```shell
ombrac-server --listen "[::]:443" --tls-cert "./cert.pem" --tls-key "./key.pem"
```
This command starts the Ombrac server listening on port 443, using the provided TLS certificate and key for encrypted communication.

### ClientSetup
```shell
ombrac-client --socks "127.0.0.1:1080" --server-address "example.com:443"
```
Will sets up a SOCKS5 server on 127.0.0.1:1080, forwarding traffic to example.com:443.

When using a self-signed certificate, the client requires both the `--server-name` parameter and the `--tls-cert` path to be explicitly configured.

## Usage
### Server

```shell
Usage: ombrac-server [OPTIONS] --listen <ADDR> --tls-cert <FILE> --tls-key <FILE>

Options:
  -h, --help     Print help
  -V, --version  Print version

Transport QUIC:
      --listen <ADDR>
          Transport server listening address
      --tls-cert <FILE>
          Path to the TLS certificate file for secure connections
      --tls-key <FILE>
          Path to the TLS private key file for secure connections
      --initial-congestion-window <NUM>
          Initial congestion window in bytes
      --max-handshake-duration <TIME>
          Handshake timeout in millisecond
      --max-idle-timeout <TIME>
          Connection idle timeout in millisecond
      --max-keep-alive-period <TIME>
          Connection keep alive period in millisecond
      --max-open-bidirectional-streams <NUM>
          Connection max open bidirectional streams
      --bidirectional-local-data-window <NUM>
          Bidirectional stream local data window
      --bidirectional-remote-data-window <NUM>
          Bidirectional stream remote data window

Logging:
      --tracing-level <TRACE>  Logging level e.g., INFO, WARN, ERROR [default: WARN]
```

### Client
```shell
Usage: ombrac-client [OPTIONS] --server-address <ADDR>
Options:
  -h, --help     Print help
  -V, --version  Print version

Endpoint SOCKS:
      --socks <ADDR>  Listening address for the SOCKS server [default: 127.0.0.1:1080]

Transport QUIC:
      --bind <ADDR>
          Bind local address
      --server-name <STR>
          Name of the server to connect
      --server-address <ADDR>
          Address of the server to connect
      --tls-cert <FILE>
          Path to the TLS certificate file for secure connections
      --initial-congestion-window <NUM>
          Initial congestion window in bytes
      --max-handshake-duration <TIME>
          Handshake timeout in millisecond
      --max-idle-timeout <TIME>
          Connection idle timeout in millisecond
      --max-keep-alive-period <TIME>
          Connection keep alive period in millisecond
      --max-open-bidirectional-streams <NUM>
          Connection max open bidirectional streams
      --bidirectional-local-data-window <NUM>
          Bidirectional stream local data window
      --bidirectional-remote-data-window <NUM>
          Bidirectional stream remote data window

Logging:
      --tracing-level <TRACE>  Logging level e.g., INFO, WARN, ERROR [default: WARN]
```

## Contributing
Contributions are welcome! Feel free to fork the repository, submit issues, or send pull requests to help improve Ombrac.

## License
This project is licensed under the [Apache-2.0 License](./LICENSE).

[license-badge]: https://img.shields.io/badge/license-apache-blue.svg
[license-url]: https://github.com/ombrac/ombrac/blob/main/LICENSE
[actions-badge]: https://github.com/ombrac/ombrac/workflows/CI/badge.svg
[actions-url]: https://github.com/ombrac/ombrac/actions/workflows/ci.yml?query=branch%3Amain