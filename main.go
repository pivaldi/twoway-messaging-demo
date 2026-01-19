package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/cloudflare/circl/hpke"
)

func main() {
	var idStr string
	flag.StringVar(&idStr, "id", "", "peer id: alice|bob|carol")
	flag.Parse()

	if idStr == "" {
		fmt.Println("usage: go run . --id alice|bob|carol")
		os.Exit(2)
	}
	self := mustPeer(PeerID(idStr))

	// HPKE suite used by twoway.
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kemScheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()

	// Derive our keys.
	selfEdPriv, selfEdPub := deriveEd25519(self.Seed)
	selfHPKEPub, selfHPKEPriv := deriveHPKEX25519(kemScheme, self.Seed)
	selfHPKEPubBytes := mustMarshalHPKEPub(selfHPKEPub)

	// Console manager with TUI.
	console, err := newConsole()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize TUI: %v\n", err)
		os.Exit(1)
	}
	defer console.Close()

	// Start server to receive requests.
	go func() {
		if err := runServer(console, suite, kemScheme, self, selfHPKEPriv); err != nil {
			console.Printf("[%s] server error: %v\n", self.ID, err)
		}
	}()

	time.Sleep(150 * time.Millisecond)

	console.Usage(self, selfEdPub, selfHPKEPubBytes)

	// Connection pool for outgoing connections (reused).
	pool := newConnPool(console, suite, kemScheme, self, selfEdPriv, selfHPKEPubBytes)

	// Announce presence to all other peers on startup
	go func() {
		time.Sleep(200 * time.Millisecond) // Give other peers time to start their servers
		pool.AnnouncePresence(self)
	}()

	console.RPEL(self, pool)
}
