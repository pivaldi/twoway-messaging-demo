// Key derivation (demo deterministic)
package main

import (
	"crypto/ed25519"

	"github.com/cloudflare/circl/kem"
)

func deriveEd25519(seed []byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub
}

func deriveHPKEX25519(s kem.Scheme, seed []byte) (kem.PublicKey, kem.PrivateKey) {
	pub, priv := s.DeriveKeyPair(seed)
	return pub, priv
}

func mustMarshalHPKEPub(pub kem.PublicKey) []byte {
	b, err := pub.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}
