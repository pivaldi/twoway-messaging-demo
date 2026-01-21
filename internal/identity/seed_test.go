package identity

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateSeed(t *testing.T) {
	seed, err := GenerateSeed()
	if err != nil {
		t.Fatalf("GenerateSeed failed: %v", err)
	}
	if len(seed) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(seed))
	}
}

func TestSaveSeed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seed.key")

	seed, _ := GenerateSeed()
	if err := SaveSeed(path, seed); err != nil {
		t.Fatalf("SaveSeed failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("file not created: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}
}

func TestLoadSeed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seed.key")

	original, _ := GenerateSeed()
	_ = SaveSeed(path, original)

	loaded, err := LoadSeed(path)
	if err != nil {
		t.Fatalf("LoadSeed failed: %v", err)
	}
	if string(loaded) != string(original) {
		t.Fatal("loaded seed doesn't match original")
	}
}

func TestDeriveKeys(t *testing.T) {
	seed, _ := GenerateSeed()
	keys, err := DeriveKeys(seed)
	if err != nil {
		t.Fatalf("DeriveKeys failed: %v", err)
	}

	// Check Ed25519 key
	if len(keys.Ed25519Pub) != ed25519.PublicKeySize {
		t.Fatal("invalid Ed25519 public key size")
	}

	// Check libp2p key generates valid PeerID
	if keys.PeerID.String() == "" {
		t.Fatal("invalid PeerID")
	}

	// Check HPKE key
	if len(keys.HPKEPubBytes) == 0 {
		t.Fatal("invalid HPKE public key")
	}

	// Check KeyID is derived
	if keys.KeyID == 0 {
		t.Fatal("KeyID should not be zero")
	}
}

func TestDeriveKeysDeterministic(t *testing.T) {
	seed, _ := GenerateSeed()
	keys1, _ := DeriveKeys(seed)
	keys2, _ := DeriveKeys(seed)

	if keys1.PeerID != keys2.PeerID {
		t.Fatal("same seed should produce same PeerID")
	}
}
