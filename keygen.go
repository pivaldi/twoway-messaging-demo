package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/pivaldi/tmd/internal/identity"
)

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	outPath := fs.String("out", "", "output path for seed file (required)")
	fs.Parse(args)

	if *outPath == "" {
		return fmt.Errorf("--out is required")
	}

	// Check if file exists
	if _, err := os.Stat(*outPath); err == nil {
		return fmt.Errorf("file already exists: %s", *outPath)
	}

	// Generate seed
	seed, err := identity.GenerateSeed()
	if err != nil {
		return fmt.Errorf("generate seed: %w", err)
	}

	// Save seed
	if err := identity.SaveSeed(*outPath, seed); err != nil {
		return fmt.Errorf("save seed: %w", err)
	}

	// Derive keys to show PeerID
	keys, err := identity.DeriveKeys(seed)
	if err != nil {
		return fmt.Errorf("derive keys: %w", err)
	}

	fmt.Printf("Seed written to %s\n", *outPath)
	fmt.Printf("PeerID: %s\n", keys.PeerID)
	fmt.Printf("HPKE KeyID: %x\n", keys.KeyID)

	return nil
}
