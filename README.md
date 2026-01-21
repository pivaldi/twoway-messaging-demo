# Twoway Messaging Demo

A demonstration of secure two-way encrypted messaging using the
[openpcc/twoway](https://github.com/openpcc/twoway) library and
[libp2p](https://github.com/libp2p/go-libp2p) for peer discovery and transport.

## Features

- **Dynamic Peer Discovery**: Peers register with discovery nodes and receive
  real-time updates when other peers come online or go offline.
- **libp2p Transport**: NAT traversal, connection multiplexing, and secure
  channels via libp2p.
- **Ed25519-signed HELLO**: Challenge/response authentication prevents replay
  attacks.
- **HPKE Encryption**: Messages are encrypted using Hybrid Public Key Encryption
  (X25519 + AES-128-GCM) via the twoway library.
- **Single Seed Identity**: All keys (Ed25519, HPKE, libp2p) derived from a
  single 32-byte seed.
- **Interactive TUI**: Send messages and see peer activity through a terminal
  user interface.

## Components

- **tmd**: The messaging client
- **tmd-node**: Discovery node service that tracks online peers

## Quick Start

### 1. Build

```bash
go build .
go build ./cmd/tmd-node
```

### 2. Generate Seeds

```bash
./tmd keygen --out alice.key
./tmd keygen --out bob.key
```

### 3. Configure Discovery Node

Create `node.json`:

```json
{
  "listen": "/ip4/0.0.0.0/tcp/9200",
  "peers": {
    "alice": "secret-alice",
    "bob": "secret-bob"
  }
}
```

### 4. Start Discovery Node

```bash
./tmd-node --config node.json
```

Note the node's address printed at startup (e.g., `/ip4/127.0.0.1/tcp/9200/p2p/12D3KooW...`).

### 5. Start Clients

```bash
# Terminal 1
./tmd --seed alice.key --nick alice --token secret-alice \
      --nodes /ip4/127.0.0.1/tcp/9200/p2p/<node-peer-id>

# Terminal 2
./tmd --seed bob.key --nick bob --token secret-bob \
      --nodes /ip4/127.0.0.1/tcp/9200/p2p/<node-peer-id>
```

## Usage

Once running, use the TUI to send messages:

```
# Send to a specific peer
@bob Hello from alice!

# Broadcast to all online peers
Hello everyone!

# List online peers
/peers

# Exit
/quit
```

## Command Reference

### tmd (client)

```
Usage: tmd --seed <file> --nick <name> --token <token> [options]

Required:
  --seed   Path to seed file (create with 'tmd keygen')
  --nick   Your nickname
  --token  Authentication token for node registration

Optional:
  --nodes  Comma-separated discovery node addresses
  --port   Port to listen on (default: random)
```

### tmd keygen

```
Usage: tmd keygen --out <file>

Generates a new 32-byte random seed file.
```

### tmd-node (discovery server)

```
Usage: tmd-node --config <file> [--seed <file>]

Options:
  --config  Path to JSON config file (required)
  --seed    Path to seed file (optional, generates new if not provided)
```

Config file format:
```json
{
  "listen": "/ip4/0.0.0.0/tcp/9200",
  "peers": {
    "nickname": "auth-token"
  }
}
```

## Architecture

### Discovery Flow

1. Client connects to discovery node via libp2p
2. Client sends registration with nickname, token, and HPKE public key
3. Node validates token and broadcasts peer info to other connected clients
4. Clients receive real-time join/leave notifications

### Messaging Flow

1. Client looks up peer in local table (populated by discovery)
2. Client opens libp2p stream to peer
3. Challenge/response handshake with Ed25519 signatures
4. Messages encrypted with recipient's HPKE public key via twoway
5. Responses encrypted using same HPKE context

### Key Derivation

All keys are derived from a single 32-byte seed:
- **Ed25519**: For signing HELLO messages
- **X25519 HPKE**: For message encryption
- **libp2p Ed25519**: For transport identity

## Dependencies

- [libp2p/go-libp2p](https://github.com/libp2p/go-libp2p): Peer-to-peer networking
- [cloudflare/circl](https://github.com/cloudflare/circl): Cryptographic primitives (HPKE, Ed25519)
- [openpcc/twoway](https://github.com/openpcc/twoway): Two-way encrypted messaging protocol

## License

MIT License. See [LICENSE](LICENSE) for details.
