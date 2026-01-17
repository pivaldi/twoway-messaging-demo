# Twoway Messaging Demo

A demonstration of secure two-way encrypted messaging using the
[openpcc/twoway](https://github.com/openpcc/twoway) library. This project
showcases authenticated, encrypted peer-to-peer communication over TCP.

## Features

- **Ed25519-signed HELLO**: Challenge/response authentication prevents replay
  attacks. Each peer's identity is verified against pinned public keys derived
  from hardcoded seeds.
- **HPKE Encryption**: Messages are encrypted using Hybrid Public Key Encryption
  (X25519 + AES-128-GCM).
- **Connection Reuse**: One outgoing TCP connection per peer, kept open for the
  session lifetime.
- **Request Multiplexing**: Multiple in-flight requests share the same TCP
  connection, matched by RequestID.
- **Interactive REPL**: Send messages and receive replies through an interactive
  console.

## Quick Start

Run three peers in separate terminals:

```bash
# Terminal 1
go run . --id alice

# Terminal 2
go run . --id bob

# Terminal 3
go run . --id carol
```

Each peer listens on a different port (alice: 9201, bob: 9202, carol: 9203).

## Usage

Once running, use the REPL to send messages:

```
# Send to a specific peer
> @bob Hello from alice!
[reply from bob] Hi alice!

# Broadcast to all other peers
> Hello everyone!
[reply from bob] Hey!
[reply from carol] Hi there!

# List available peers
> /peers
- alice (127.0.0.1:9201) keyID=1
- bob (127.0.0.1:9202) keyID=2
- carol (127.0.0.1:9203) keyID=3

# Exit
> /quit
```

When you receive a message, you'll be prompted to reply:

```
[from alice] Hello from alice!
reply> Hi alice!
```

## How It Works

### Connection Handshake

1. Client connects to server via TCP
2. Server sends a 32-byte random challenge
3. Client sends a signed HELLO containing:
   - Sender ID and KeyID
   - Ed25519 public key
   - HPKE public key
   - Ed25519 signature over (challenge + identity data)
4. Server verifies the signature and public keys against pinned values
5. Connection is established for encrypted message exchange

### Message Exchange

- Requests are encrypted with the recipient's HPKE public key
- Responses are encrypted using the same HPKE context
- Each request carries a unique RequestID for multiplexing
- The twoway library handles the cryptographic envelope

## Dependencies

- [cloudflare/circl](https://github.com/cloudflare/circl): Cryptographic primitives (HPKE, Ed25519)
- [openpcc/twoway](https://github.com/openpcc/twoway): Two-way encrypted messaging protocol
