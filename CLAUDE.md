# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Run

```bash
# Build
go build .

# Run (requires specifying peer identity)
go run . --id alice   # Terminal 1
go run . --id bob     # Terminal 2
go run . --id carol   # Terminal 3

# Format code
gofmt -w .

# Run tests (none currently exist)
go test ./...
```

## Project Overview

This is a demo implementation of two-way encrypted messaging using the `github.com/openpcc/twoway` library. It demonstrates:

- Ed25519-signed HELLO with challenge/response authentication
- HPKE (Hybrid Public Key Encryption) for message encryption
- TCP connection pooling with multiplexed requests
- Interactive REPL for sending messages between peers

## Architecture

### Identity and Key Management

Three hardcoded peers (alice, bob, carol) with deterministic key derivation from seeds in `peer.go`. Each peer has:
- Ed25519 keypair for signing HELLO messages
- X25519 HPKE keypair for encryption
- A unique KeyID and TCP port (9201-9203)

### Connection Flow

1. **Server** (`server.go`): Listens for incoming connections, sends challenge, verifies signed HELLO, then loops receiving encrypted requests and prompting for replies
2. **Client** (`conn-pool.go`): Manages outgoing connections with `connPool`. On first message to a peer, dials, receives challenge, sends signed HELLO, then reuses the connection for subsequent requests
3. **Session** (`peer.go`): `peerSession` handles multiplexing - multiple in-flight requests share one TCP connection, matched by `RequestID`

### Wire Protocol (`wire-format.go`)

Messages use length-prefixed framing:
- `u32(length) || type(1 byte) || payload`
- Message types: Challenge (1), Hello (2), Request (3), Response (4)
- Nested blobs also use `u32(length) || bytes` format

### Console (`console.go`)

Thread-safe REPL that handles both sending messages and receiving reply prompts. Commands:
- `@peer message` - Send to specific peer
- Plain text - Broadcast to all peers
- `/peers` - List peers
- `/quit` - Exit
