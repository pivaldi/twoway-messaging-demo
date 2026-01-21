package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

const SeedSize = 32

// GenerateSeed creates a new 32-byte random seed.
func GenerateSeed() ([]byte, error) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate seed: %w", err)
	}
	return seed, nil
}

// SaveSeed writes a seed to file with 0600 permissions.
func SaveSeed(path string, seed []byte) error {
	if len(seed) != SeedSize {
		return fmt.Errorf("invalid seed size: %d", len(seed))
	}
	return os.WriteFile(path, seed, 0600)
}

// LoadSeed reads a seed from file.
func LoadSeed(path string) ([]byte, error) {
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load seed: %w", err)
	}
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("invalid seed size: %d", len(seed))
	}
	return seed, nil
}

// DerivedKeys holds all keys derived from a seed.
type DerivedKeys struct {
	Ed25519Priv  ed25519.PrivateKey
	Ed25519Pub   ed25519.PublicKey
	HPKEPub      kem.PublicKey
	HPKEPriv     kem.PrivateKey
	HPKEPubBytes []byte
	KeyID        byte
	Libp2pPriv   libp2pcrypto.PrivKey
	Libp2pPub    libp2pcrypto.PubKey
	PeerID       peer.ID
}

// DeriveKeys derives all cryptographic keys from a seed.
func DeriveKeys(seed []byte) (*DerivedKeys, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("invalid seed size: %d", len(seed))
	}

	// Ed25519 for Hello signing
	ed25519Priv := ed25519.NewKeyFromSeed(seed)
	ed25519Pub := ed25519Priv.Public().(ed25519.PublicKey)

	// HPKE X25519 for message encryption
	kemScheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	hpkePub, hpkePriv := kemScheme.DeriveKeyPair(seed)
	hpkePubBytes, err := hpkePub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal HPKE pub: %w", err)
	}

	// KeyID from first byte of HPKE public key hash
	hash := sha256.Sum256(hpkePubBytes)
	keyID := hash[0]
	if keyID == 0 {
		keyID = 1 // avoid zero KeyID
	}

	// libp2p Ed25519 for transport (convert from std lib key)
	libp2pPriv, libp2pPub, err := libp2pcrypto.KeyPairFromStdKey(&ed25519Priv)
	if err != nil {
		return nil, fmt.Errorf("derive libp2p key: %w", err)
	}

	peerID, err := peer.IDFromPublicKey(libp2pPub)
	if err != nil {
		return nil, fmt.Errorf("derive peer ID: %w", err)
	}

	return &DerivedKeys{
		Ed25519Priv:  ed25519Priv,
		Ed25519Pub:   ed25519Pub,
		HPKEPub:      hpkePub,
		HPKEPriv:     hpkePriv,
		HPKEPubBytes: hpkePubBytes,
		KeyID:        keyID,
		Libp2pPriv:   libp2pPriv,
		Libp2pPub:    libp2pPub,
		PeerID:       peerID,
	}, nil
}
