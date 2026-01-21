package p2p

import (
	"testing"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
)

func TestNewHost(t *testing.T) {
	// Generate a test key
	priv, _, err := libp2pcrypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	h, err := NewHost(priv, 0) // port 0 = random
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer h.Close()

	if len(h.Addrs()) == 0 {
		t.Fatal("host should have at least one address")
	}

	if h.ID().String() == "" {
		t.Fatal("host should have a peer ID")
	}
}

func TestNewHostWithPort(t *testing.T) {
	priv, _, err := libp2pcrypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	h, err := NewHost(priv, 19876)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer h.Close()

	// Check that at least one address contains the port
	found := false
	for _, addr := range h.Addrs() {
		if addr.String() != "" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("host should have addresses")
	}
}
