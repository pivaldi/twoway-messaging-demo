package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/pivaldi/tmd/internal/identity"
	"github.com/pivaldi/tmd/internal/node"
	"github.com/pivaldi/tmd/internal/p2p"
)

func main() {
	configPath := flag.String("config", "node.json", "path to config file")
	seedPath := flag.String("seed", "", "path to seed file (optional, generates new if not provided)")
	flag.Parse()

	// Load config
	cfg, err := node.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	// Load or generate seed
	var seed []byte
	if *seedPath != "" {
		seed, err = identity.LoadSeed(*seedPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load seed: %v\n", err)
			os.Exit(1)
		}
	} else {
		seed, _ = identity.GenerateSeed()
		fmt.Println("Generated new node identity (use --seed to persist)")
	}

	// Derive keys
	keys, err := identity.DeriveKeys(seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "derive keys: %v\n", err)
		os.Exit(1)
	}

	// Parse listen address to get port
	// cfg.Listen is like "/ip4/0.0.0.0/tcp/9200"
	port := 9200 // default
	fmt.Sscanf(cfg.Listen, "/ip4/0.0.0.0/tcp/%d", &port)

	// Create libp2p host
	h, err := p2p.NewHost(keys.Libp2pPriv, port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create host: %v\n", err)
		os.Exit(1)
	}
	defer h.Close()

	// Create server
	srv := node.NewServer(h, cfg)

	fmt.Printf("Node started\n")
	fmt.Printf("PeerID: %s\n", srv.ID())
	for _, addr := range srv.Addrs() {
		fmt.Printf("Address: %s/p2p/%s\n", addr, srv.ID())
	}
	fmt.Printf("Allowed peers: %v\n", getKeys(cfg.Peers))

	// Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down...")
}

func getKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
