package main

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// PeerID is now the nickname (string identifier for the peer)
type PeerID string

// PeerInfo holds information about a discovered peer
type PeerInfo struct {
	Nickname PeerID
	PeerID   peer.ID               // libp2p peer ID
	Addrs    []multiaddr.Multiaddr // peer's addresses
	HPKEPub  []byte                // HPKE public key for encryption
	KeyID    []byte                // 8-byte key fingerprint
}

// PeerTable manages dynamically discovered peers
type PeerTable struct {
	mu    sync.RWMutex
	peers map[PeerID]*PeerInfo
}

// NewPeerTable creates a new peer table
func NewPeerTable() *PeerTable {
	return &PeerTable{
		peers: make(map[PeerID]*PeerInfo),
	}
}

// Add adds or updates a peer in the table
func (pt *PeerTable) Add(info PeerInfo) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.peers[info.Nickname] = &info
}

// Remove removes a peer from the table
func (pt *PeerTable) Remove(nickname PeerID) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	delete(pt.peers, nickname)
}

// Get retrieves a peer by nickname
func (pt *PeerTable) Get(nickname PeerID) (PeerInfo, bool) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	p, ok := pt.peers[nickname]
	if !ok {
		return PeerInfo{}, false
	}
	return *p, true
}

// All returns all peers in the table
func (pt *PeerTable) All() []PeerInfo {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	result := make([]PeerInfo, 0, len(pt.peers))
	for _, p := range pt.peers {
		result = append(result, *p)
	}
	return result
}

type peerSession struct {
	to     PeerInfo
	stream network.Stream

	writeMu sync.Mutex

	nextID uint64

	pendingMu sync.Mutex
	pending   map[uint64]chan Response

	dead atomic.Bool
}

func (ps *peerSession) isAlive() bool {
	return ps != nil && !ps.dead.Load()
}

func (ps *peerSession) failAll() {
	if ps.dead.CompareAndSwap(false, true) {
		_ = ps.stream.Close()
	}

	ps.pendingMu.Lock()
	defer ps.pendingMu.Unlock()
	for id, ch := range ps.pending {
		delete(ps.pending, id)
		close(ch) // best-effort unblock waiters
	}
}

func (ps *peerSession) readLoop() {
	for {
		typ, payload, err := readMsg(ps.stream)
		if err != nil {
			ps.failAll()
			return
		}
		if typ != msgResponse {
			// For this demo, outbound sessions only expect responses.
			continue
		}
		resp, err := decodeResponse(payload)
		if err != nil {
			continue
		}

		ps.pendingMu.Lock()
		ch := ps.pending[resp.RequestID]
		delete(ps.pending, resp.RequestID)
		ps.pendingMu.Unlock()

		if ch != nil {
			ch <- resp
			close(ch)
		}
	}
}

func (ps *peerSession) DoRequest(req Request) (Response, error) {
	if ps.dead.Load() {
		return Response{}, fmt.Errorf("session is closed")
	}

	id := atomic.AddUint64(&ps.nextID, 1)
	req.RequestID = id

	ch := make(chan Response, 1)
	ps.pendingMu.Lock()
	ps.pending[id] = ch
	ps.pendingMu.Unlock()

	ps.writeMu.Lock()
	err := writeMsg(ps.stream, msgRequest, encodeRequest(req))
	ps.writeMu.Unlock()
	if err != nil {
		ps.pendingMu.Lock()
		delete(ps.pending, id)
		ps.pendingMu.Unlock()
		return Response{}, err
	}

	resp, ok := <-ch
	if !ok {
		return Response{}, fmt.Errorf("connection closed")
	}
	return resp, nil
}

// -------------------- Helpers --------------------

func splitFirstWord(s string) (first string, rest string, ok bool) {
	before, after, ok0 := strings.Cut(s, " ")
	if !ok0 {
		return "", "", false
	}

	first = strings.TrimSpace(before)
	rest = strings.TrimSpace(after)
	if first == "" || rest == "" {
		return "", "", false
	}

	return first, rest, true
}
