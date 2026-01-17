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
	SenderKeyID   byte
	SenderEdPub   []byte // 32 bytes
	SenderHPKEPub []byte // 32 bytes for X25519 KEM public key
	Signature     []byte // 64 bytes
}

func verifySignedHello(kemScheme kem.Scheme, challenge []byte, h Hello) error {
	p := mustPeer(h.SenderID)
	if h.SenderKeyID != p.KeyID {
		return fmt.Errorf("keyID mismatch for %s: got %d want %d", h.SenderID, h.SenderKeyID, p.KeyID)
	}

	_, expectedEdPub := deriveEd25519(p.Seed)
	if !bytes.Equal(h.SenderEdPub, expectedEdPub) {
		return fmt.Errorf("Ed25519 pubkey mismatch for %s", h.SenderID)
	}

	expectedHPKEPub, _ := deriveHPKEX25519(kemScheme, p.Seed)
	expectedHPKEPubBytes := mustMarshalHPKEPub(expectedHPKEPub)
	if !bytes.Equal(h.SenderHPKEPub, expectedHPKEPubBytes) {
		return fmt.Errorf("HPKE pubkey mismatch for %s", h.SenderID)
	}

	if len(h.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("bad signature length")
	}
	if !ed25519.Verify(ed25519.PublicKey(h.SenderEdPub), helloSignInput(challenge, h), h.Signature) {
		return fmt.Errorf("invalid signature for %s", h.SenderID)
	}
	return nil
}

func helloSignInput(challenge []byte, h Hello) []byte {
	// signed bytes = challenge || senderID || keyID || edPub || hpkePub
	var b bytes.Buffer
	b.Write(challenge)
	b.Write([]byte(h.SenderID))
	b.WriteByte(0)
	b.WriteByte(h.SenderKeyID)
	b.Write(h.SenderEdPub)
	b.Write(h.SenderHPKEPub)
	return b.Bytes()
}
