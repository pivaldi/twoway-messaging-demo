package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	"github.com/cloudflare/circl/kem"
)

// Signed HELLO verification
type Hello struct {
	SenderID      PeerID
	SenderKeyID   []byte // 8-byte key fingerprint
	SenderEdPub   []byte // 32 bytes
	SenderHPKEPub []byte // 32 bytes for X25519 KEM public key
	Signature     []byte // 64 bytes
}

// verifySignedHello verifies the signature on a Hello message.
// In the new architecture, keys are received from the discovery node.
// This function verifies the signature matches the Ed25519 public key in the Hello.
// If peerTable is provided, it also verifies against known peer info.
func verifySignedHello(kemScheme kem.Scheme, challenge []byte, h Hello) error {
	// Basic validation
	if len(h.SenderEdPub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 pubkey size: %d", len(h.SenderEdPub))
	}
	if len(h.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("bad signature length")
	}

	// Verify signature against the public key in the Hello
	if !ed25519.Verify(ed25519.PublicKey(h.SenderEdPub), helloSignInput(challenge, h), h.Signature) {
		return fmt.Errorf("invalid signature for %s", h.SenderID)
	}

	return nil
}

// verifySignedHelloWithTable verifies the signature and cross-checks with the peer table.
func verifySignedHelloWithTable(kemScheme kem.Scheme, challenge []byte, h Hello, peerTable *PeerTable) error {
	// First do basic signature verification
	if err := verifySignedHello(kemScheme, challenge, h); err != nil {
		return err
	}

	// If we have a peer table, verify against known peer info
	if peerTable != nil {
		peer, ok := peerTable.Get(h.SenderID)
		if ok {
			// Verify key ID matches
			if !bytes.Equal(h.SenderKeyID, peer.KeyID) {
				return fmt.Errorf("keyID mismatch for %s: got %x want %x", h.SenderID, h.SenderKeyID, peer.KeyID)
			}
			// Verify HPKE public key matches
			if !bytes.Equal(h.SenderHPKEPub, peer.HPKEPub) {
				return fmt.Errorf("HPKE pubkey mismatch for %s", h.SenderID)
			}
		}
	}

	return nil
}

func helloSignInput(challenge []byte, h Hello) []byte {
	// signed bytes = challenge || senderID || 0 || keyID (8 bytes) || edPub || hpkePub
	var b bytes.Buffer
	b.Write(challenge)
	b.Write([]byte(h.SenderID))
	b.WriteByte(0)
	b.Write(h.SenderKeyID) // 8-byte key fingerprint
	b.Write(h.SenderEdPub)
	b.Write(h.SenderHPKEPub)
	return b.Bytes()
}
