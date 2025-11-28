# Nim Nostr Relay

A lightweight Nostr relay implementation in Nim.

## NIP Support

This relay supports the following Nostr Implementation Possibilities (NIPs):

- **NIP-01**: Basic protocol flow
- **NIP-11**: Relay Information Document
- **NIP-20**: Command results (OK messages)

## Usage

```bash
nim c -r main.nim
```

Or with environment variables:

```bash
DATABASE_URL='postgres://user:pass@localhost:5432/nostr' ./main
```

The relay will start on `ws://localhost:9001` by default.

## Docker

Build and run with Docker:

```bash
docker build -t nim-nostr-relay .
docker run -p 9001:9001 -e DATABASE_URL='postgres://user:pass@host:5432/nostr' nim-nostr-relay
```

## Installation

```bash
git clone <repository-url>
cd nim-nostr-relay
```

## Requirements

- Nim 2.x
- PostgreSQL
- libsecp256k1

Required Nim packages (automatically loaded via nimble):
- ws
- jsony
- secp256k1
- nimcrypto
- db_connector

## Notes

**Signature Verification**: Full Schnorr signature verification is implemented using libsecp256k1.

## Configuration

Set the following environment variables:

- `DATABASE_URL`: PostgreSQL connection string (e.g., `postgres://user:pass@host:5432/nostr`)
- Or use individual variables: `DB_HOST`, `DB_USER`, `DB_PASS`, `DB_NAME`

## License

MIT License

## Author

Yasuhiro Matsumoto (a.k.a. mattn)
