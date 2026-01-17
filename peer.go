package main

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
)

// For a demo, we make identities stable across runs by deriving keys from seeds.
// In real systems, you'd generate keys randomly and distribute public keys out-of-band.

type PeerID string

type PeerInfo struct {
	ID    PeerID
	KeyID byte
	Addr  string
	Seed  []byte // 32 bytes: used to derive both Ed25519 and HPKE keys deterministically
}

var peers = []PeerInfo{
	{ID: "alice", KeyID: 1, Addr: "127.0.0.1:9201", Seed: bytes.Repeat([]byte{0xA1}, 32)},
	{ID: "bob", KeyID: 2, Addr: "127.0.0.1:9202", Seed: bytes.Repeat([]byte{0xB2}, 32)},
	{ID: "carol", KeyID: 3, Addr: "127.0.0.1:9203", Seed: bytes.Repeat([]byte{0xC3}, 32)},
}

type peerSession struct {
	to PeerInfo
	c  net.Conn

	writeMu sync.Mutex

	nextID uint64

	pendingMu sync.Mutex
	pending   map[uint64]chan Response

	dead atomic.Bool
}

func (ps *peerSession) isAlive() bool { return !ps.dead.Load() }

func (ps *peerSession) failAll(err error) {
	if ps.dead.CompareAndSwap(false, true) {
		_ = ps.c.Close()
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
		typ, payload, err := readMsg(ps.c)
		if err != nil {
			ps.failAll(err)
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
	err := writeMsg(ps.c, msgRequest, encodeRequest(req))
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

// -------------------- Peer table helpers --------------------

func mustPeer(id PeerID) PeerInfo {
	for _, p := range peers {
		if p.ID == id {
			return p
		}
	}
	panic("unknown peer: " + string(id))
}

func splitFirstWord(s string) (first string, rest string, ok bool) {
	i := strings.IndexByte(s, ' ')
	if i < 0 {
		return "", "", false
	}
	first = strings.TrimSpace(s[:i])
	rest = strings.TrimSpace(s[i+1:])
	if first == "" || rest == "" {
		return "", "", false
	}
	return first, rest, true
}
