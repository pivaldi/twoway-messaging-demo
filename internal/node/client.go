package node

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// Client connects to one or more discovery nodes.
type Client struct {
	host     host.Host
	nickname string
	token    string
	hpkePub  []byte
	keyID    []byte // 8-byte key fingerprint

	mu      sync.RWMutex
	nodes   map[peer.ID]*nodeConn    // node PeerID -> connection
	peers   map[string]*TrackedPeer  // nickname -> peer info
	handler PeerHandler
}

// TrackedPeer tracks which nodes have reported a peer online.
type TrackedPeer struct {
	PeerInfo
	SeenBy map[peer.ID]bool // node PeerIDs that reported this peer
}

// PeerHandler receives peer events.
type PeerHandler interface {
	OnPeerJoined(info PeerInfo, nodeID peer.ID)
	OnPeerLeft(nickname string, nodeID peer.ID)
	OnNodeConnected(nodeID peer.ID)
	OnNodeDisconnected(nodeID peer.ID)
}

type nodeConn struct {
	nodeID peer.ID
	stream network.Stream
	cancel context.CancelFunc
}

// NewClient creates a new node client.
func NewClient(h host.Host, nickname, token string, hpkePub []byte, keyID []byte, handler PeerHandler) *Client {
	return &Client{
		host:     h,
		nickname: nickname,
		token:    token,
		hpkePub:  hpkePub,
		keyID:    keyID,
		nodes:    make(map[peer.ID]*nodeConn),
		peers:    make(map[string]*TrackedPeer),
		handler:  handler,
	}
}

// Connect connects to a discovery node.
func (c *Client) Connect(ctx context.Context, nodeAddr string) error {
	// Parse multiaddr
	maddr, err := multiaddr.NewMultiaddr(nodeAddr)
	if err != nil {
		return fmt.Errorf("parse node address: %w", err)
	}

	// Extract peer ID from multiaddr
	addrInfo, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return fmt.Errorf("extract peer info: %w", err)
	}

	// Connect to node
	if err := c.host.Connect(ctx, *addrInfo); err != nil {
		return fmt.Errorf("connect to node: %w", err)
	}

	// Open stream
	stream, err := c.host.NewStream(ctx, addrInfo.ID, ProtocolID)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}

	// Send Register
	reg := &Register{
		Nickname: c.nickname,
		Token:    c.token,
		HPKEPub:  c.hpkePub,
		KeyID:    c.keyID,
	}
	if err := WriteMsg(stream, MsgRegister, EncodeRegister(reg)); err != nil {
		stream.Close()
		return fmt.Errorf("send register: %w", err)
	}

	// Read response
	typ, payload, err := ReadMsg(stream)
	if err != nil {
		stream.Close()
		return fmt.Errorf("read response: %w", err)
	}

	if typ == MsgRegisterFail {
		fail, _ := DecodeRegisterFail(payload)
		stream.Close()
		return fmt.Errorf("registration failed: %s", fail.Reason)
	}

	if typ != MsgRegisterOK {
		stream.Close()
		return fmt.Errorf("unexpected message type: %d", typ)
	}

	// Read PeerList
	typ, payload, err = ReadMsg(stream)
	if err != nil {
		stream.Close()
		return fmt.Errorf("read peer list: %w", err)
	}
	if typ != MsgPeerList {
		stream.Close()
		return fmt.Errorf("expected PeerList, got %d", typ)
	}

	peerList, err := DecodePeerList(payload)
	if err != nil {
		stream.Close()
		return fmt.Errorf("decode peer list: %w", err)
	}

	// Store connection
	connCtx, cancel := context.WithCancel(context.Background())
	nc := &nodeConn{
		nodeID: addrInfo.ID,
		stream: stream,
		cancel: cancel,
	}

	c.mu.Lock()
	c.nodes[addrInfo.ID] = nc
	c.mu.Unlock()

	// Add peers from list
	for _, p := range peerList.Peers {
		c.addPeer(p, addrInfo.ID)
	}

	// Notify handler
	if c.handler != nil {
		c.handler.OnNodeConnected(addrInfo.ID)
	}

	// Start read loop
	go c.readLoop(connCtx, nc)

	return nil
}

func (c *Client) addPeer(info PeerInfo, nodeID peer.ID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	existing, ok := c.peers[info.Nickname]
	if ok {
		existing.SeenBy[nodeID] = true
		// Update addresses if newer
		existing.Addrs = info.Addrs
	} else {
		c.peers[info.Nickname] = &TrackedPeer{
			PeerInfo: info,
			SeenBy:   map[peer.ID]bool{nodeID: true},
		}
	}

	if c.handler != nil {
		c.handler.OnPeerJoined(info, nodeID)
	}
}

func (c *Client) removePeerFromNode(nickname string, nodeID peer.ID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	tracked, ok := c.peers[nickname]
	if !ok {
		return
	}

	delete(tracked.SeenBy, nodeID)

	// Remove peer only if no nodes track it
	if len(tracked.SeenBy) == 0 {
		delete(c.peers, nickname)
	}

	if c.handler != nil {
		c.handler.OnPeerLeft(nickname, nodeID)
	}
}

func (c *Client) readLoop(ctx context.Context, nc *nodeConn) {
	defer func() {
		nc.stream.Close()
		c.mu.Lock()
		delete(c.nodes, nc.nodeID)
		c.mu.Unlock()

		if c.handler != nil {
			c.handler.OnNodeDisconnected(nc.nodeID)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		typ, payload, err := ReadMsg(nc.stream)
		if err != nil {
			return
		}

		switch typ {
		case MsgPeerJoined:
			joined, err := DecodePeerJoined(payload)
			if err != nil {
				continue
			}
			c.addPeer(PeerInfo{
				Nickname: joined.Nickname,
				PeerID:   joined.PeerID,
				Addrs:    joined.Addrs,
				HPKEPub:  joined.HPKEPub,
				KeyID:    joined.KeyID,
			}, nc.nodeID)

		case MsgPeerLeft:
			left, err := DecodePeerLeft(payload)
			if err != nil {
				continue
			}
			c.removePeerFromNode(left.Nickname, nc.nodeID)
		}
	}
}

// GetPeer returns info for a peer by nickname.
func (c *Client) GetPeer(nickname string) (PeerInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	tracked, ok := c.peers[nickname]
	if !ok {
		return PeerInfo{}, false
	}
	return tracked.PeerInfo, true
}

// GetAllPeers returns all known peers.
func (c *Client) GetAllPeers() []PeerInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	peers := make([]PeerInfo, 0, len(c.peers))
	for _, p := range c.peers {
		peers = append(peers, p.PeerInfo)
	}
	return peers
}

// Close disconnects from all nodes.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, nc := range c.nodes {
		nc.cancel()
		nc.stream.Close()
	}
}

// ConnectAll connects to multiple nodes in parallel.
func (c *Client) ConnectAll(ctx context.Context, nodeAddrs []string) error {
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	connected := 0

	for _, addr := range nodeAddrs {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()

			connCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			if err := c.Connect(connCtx, addr); err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("node %s: %w", addr, err)
				}
				errMu.Unlock()
			} else {
				errMu.Lock()
				connected++
				errMu.Unlock()
			}
		}(addr)
	}

	wg.Wait()

	if connected == 0 {
		return fmt.Errorf("failed to connect to any node: %w", firstErr)
	}

	return nil
}
