package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/pivaldi/tmd/internal/identity"
	"github.com/pivaldi/tmd/internal/node"
	"github.com/pivaldi/tmd/internal/p2p"
)

func main() {
	// Handle keygen subcommand
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		if err := runKeygen(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "keygen error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	var (
		seedPath  string
		nickname  string
		token     string
		nodesStr  string
		port      int
	)
	flag.StringVar(&seedPath, "seed", "", "path to seed file (required)")
	flag.StringVar(&nickname, "nick", "", "nickname for this peer (required)")
	flag.StringVar(&token, "token", "", "authentication token (required)")
	flag.StringVar(&nodesStr, "nodes", "", "comma-separated list of discovery node addresses")
	flag.IntVar(&port, "port", 0, "port to listen on (0 = random)")
	flag.Parse()

	if seedPath == "" || nickname == "" || token == "" {
		fmt.Println("usage: tmd --seed <seed.key> --nick <nickname> --token <token> --nodes <node1,node2,...>")
		fmt.Println("       tmd keygen --out seed.key")
		fmt.Println("")
		fmt.Println("Required flags:")
		fmt.Println("  --seed   path to seed file (create with 'tmd keygen')")
		fmt.Println("  --nick   your nickname")
		fmt.Println("  --token  authentication token for node registration")
		fmt.Println("")
		fmt.Println("Optional flags:")
		fmt.Println("  --nodes  comma-separated discovery node addresses")
		fmt.Println("  --port   port to listen on (default: random)")
		os.Exit(2)
	}

	// Load seed
	seed, err := identity.LoadSeed(seedPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load seed: %v\n", err)
		os.Exit(1)
	}

	// Derive keys
	keys, err := identity.DeriveKeys(seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "derive keys: %v\n", err)
		os.Exit(1)
	}

	// Create libp2p host
	h, err := p2p.NewHost(keys.Libp2pPriv, port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create host: %v\n", err)
		os.Exit(1)
	}
	defer h.Close()

	// HPKE suite used by twoway.
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kemScheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()

	// Create peer table for discovered peers
	peerTable := NewPeerTable()

	// Create self info for console
	selfInfo := PeerInfo{
		Nickname: PeerID(nickname),
		PeerID:   keys.PeerID,
		Addrs:    h.Addrs(),
		HPKEPub:  keys.HPKEPubBytes,
		KeyID:    keys.KeyID,
	}

	// Connection pool for outgoing connections (reused).
	pool := newConnPool(h, peerTable, suite, kemScheme, PeerID(nickname), keys.KeyID, keys.Ed25519Priv, keys.HPKEPubBytes)

	// Console manager with TUI.
	console, err := newConsole(selfInfo, pool)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize TUI: %v\n", err)
		os.Exit(1)
	}
	defer console.Close()

	pool.setConsole(console)

	// Setup stream handler for incoming connections
	if err := pool.SetupStreamHandler(keys.HPKEPriv); err != nil {
		console.Printf("[%s] setup handler error: %v\n", nickname, err)
	}

	// Show startup info
	console.Usage(PeerID(nickname), keys.KeyID, keys.Ed25519Pub, keys.HPKEPubBytes, keys.PeerID.String())

	// Connect to discovery nodes if specified
	if nodesStr != "" {
		nodeAddrs := strings.Split(nodesStr, ",")
		nodeClient := node.NewClient(h, nickname, token, keys.HPKEPubBytes, keys.KeyID, &peerHandler{
			peerTable: peerTable,
			console:   console,
			pool:      pool,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := nodeClient.ConnectAll(ctx, nodeAddrs); err != nil {
			console.Printf("[node] warning: %v\n", err)
		}
		cancel()

		// Show connected peers
		for _, p := range nodeClient.GetAllPeers() {
			console.AddHistory(fmt.Sprintf("[node] peer online: %s", p.Nickname))
		}
	} else {
		console.AddHistory("[node] no discovery nodes specified, running in standalone mode")
	}

	defer pool.AnnounceDisconnexion() // Announce disconnection to all peers before exiting

	console.REPL(pool)
}

// peerHandler implements node.PeerHandler to receive peer events
type peerHandler struct {
	peerTable *PeerTable
	console   *console
	pool      *connPool
}

func (h *peerHandler) OnPeerJoined(info node.PeerInfo, nodeID peer.ID) {
	// Convert node.PeerInfo to main.PeerInfo
	addrs := make([]multiaddr.Multiaddr, len(info.Addrs))
	copy(addrs, info.Addrs)

	peerInfo := PeerInfo{
		Nickname: PeerID(info.Nickname),
		PeerID:   info.PeerID,
		Addrs:    addrs,
		HPKEPub:  info.HPKEPub,
		KeyID:    info.KeyID,
	}
	h.peerTable.Add(peerInfo)
	h.console.AddHistory(fmt.Sprintf("[node] peer joined: %s", info.Nickname))
}

func (h *peerHandler) OnPeerLeft(nickname string, nodeID peer.ID) {
	h.peerTable.Remove(PeerID(nickname))
	h.pool.RemoveSession(PeerID(nickname))
	h.console.AddHistory(fmt.Sprintf("[node] peer left: %s", nickname))
}

func (h *peerHandler) OnNodeConnected(nodeID peer.ID) {
	h.console.AddHistory(fmt.Sprintf("[node] connected to node: %s", nodeID.ShortString()))
}

func (h *peerHandler) OnNodeDisconnected(nodeID peer.ID) {
	h.console.AddHistory(fmt.Sprintf("[node] disconnected from node: %s", nodeID.ShortString()))
}
