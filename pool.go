package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/openpcc/twoway"
	"golang.org/x/sync/errgroup"
)

// -------------------- Connection reuse + multiplexing --------------------
type connPool struct {
	console          *console
	suite            hpke.Suite
	kemScheme        kem.Scheme
	self             PeerInfo
	selfEdPriv       ed25519.PrivateKey
	selfHPKEPubBytes []byte

	mu       sync.Mutex
	sessions map[PeerID]*peerSession
}

func newConnPool(suite hpke.Suite, kemScheme kem.Scheme, self PeerInfo, selfEdPriv ed25519.PrivateKey, selfHPKEPubBytes []byte) *connPool {
	return &connPool{
		suite:            suite,
		kemScheme:        kemScheme,
		self:             self,
		selfEdPriv:       selfEdPriv,
		selfHPKEPubBytes: selfHPKEPubBytes,
		sessions:         make(map[PeerID]*peerSession),
	}
}

func (p *connPool) setConsole(c *console) {
	p.console = c
}

func (p *connPool) NewSession(to PeerInfo) (*peerSession, error) {
	// Create a new session if does not exists or not alive.
	ps, ok := p.GetSession(to)
	if ok {
		return ps, nil
	}

	ps, err := p.dialAndHandshake(to)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.sessions[to.ID] = ps
	p.mu.Unlock()

	return ps, nil
}

func (p *connPool) GetSession(to PeerInfo) (*peerSession, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if s := p.sessions[to.ID]; s.isAlive() {
		return s, true
	}

	return nil, false
}

func (p *connPool) RemoveSession(peerID PeerID) {
	p.mu.Lock()
	s := p.sessions[peerID]
	delete(p.sessions, peerID)
	p.mu.Unlock()

	if s != nil {
		s.failAll()
	}

	if p.console != nil {
		p.console.AddHistory(fmt.Sprintf("[net] disconnected from %s", peerID))
	}
}

func (p *connPool) SendRequest(to PeerInfo, msg string) (string, error) {
	psession, ok := p.GetSession(to)
	if !ok {
		return "", fmt.Errorf("%s does not seem connected", to.ID)
	}

	// Build one request ciphertext (twoway request/response).
	sender := twoway.NewMultiRequestSender(p.suite, rand.Reader)
	reqMediaType := []byte("text/plain; purpose=req")
	reqSealer, err := sender.NewRequestSealer(strings.NewReader(msg), reqMediaType)
	if err != nil {
		return "", fmt.Errorf("NewRequestSealer: %w", err)
	}
	reqCiphertext, err := io.ReadAll(reqSealer)
	if err != nil {
		return "", fmt.Errorf("read request ciphertext: %w", err)
	}

	// Receiver's pinned HPKE public key (from seed table in this demo).
	toHPKEPub, _ := deriveHPKEX25519(p.kemScheme, to.Seed)

	encapKey, respOpenFn, err := reqSealer.EncapsulateKey(to.KeyID, toHPKEPub)
	if err != nil {
		return "", fmt.Errorf("EncapsulateKey(to=%s): %w", to.ID, err)
	}

	req := Request{
		RequestID:      0, // set inside DoRequest
		RecipientKeyID: to.KeyID,
		EncapKey:       encapKey,
		MediaType:      reqMediaType,
		Ciphertext:     reqCiphertext,
	}

	resp, err := psession.DoRequest(req)
	if err != nil {
		return "", err
	}

	// Open response using respOpenFn returned by EncapsulateKey.
	respOpener, err := respOpenFn(bytes.NewReader(resp.Ciphertext), resp.MediaType)
	if err != nil {
		return "", err
	}
	respPlain, err := io.ReadAll(respOpener)
	if err != nil {
		return "", err
	}

	return string(respPlain), nil
}

func (p *connPool) Broadcast(self PeerInfo, msg string) error {
	var g errgroup.Group

	// Tag broadcast messages with a special prefix
	broadcastMsg := "[BROADCAST]" + msg

	for _, peer := range peers {
		if peer.ID == self.ID {
			continue
		}

		to := peer
		g.Go(func() error {
			_, err := p.SendRequest(to, broadcastMsg)
			if err != nil {
				return fmt.Errorf("to %s: %w", to.ID, err)
			}

			return nil
		})
	}

	return g.Wait()
}

func (p *connPool) dialAndHandshake(to PeerInfo) (*peerSession, error) {
	c, err := net.DialTimeout("tcp", to.Addr, 2*time.Second)
	if err != nil {
		return nil, err
	}

	// 1) Read CHALLENGE from receiver.
	typ, chal, err := readMsg(c)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if typ != msgChallenge {
		_ = c.Close()
		return nil, fmt.Errorf("expected CHALLENGE, got %d", typ)
	}
	if len(chal) != 32 {
		_ = c.Close()
		return nil, fmt.Errorf("bad challenge length: %d", len(chal))
	}

	// 2) Send signed HELLO (identity).
	hello := Hello{
		SenderID:      p.self.ID,
		SenderKeyID:   p.self.KeyID,
		SenderEdPub:   p.selfEdPriv.Public().(ed25519.PublicKey),
		SenderHPKEPub: p.selfHPKEPubBytes,
		Signature:     nil,
	}
	hello.Signature = ed25519.Sign(p.selfEdPriv, helloSignInput(chal, hello))
	if err := writeMsg(c, msgHello, encodeHello(hello)); err != nil {
		_ = c.Close()
		return nil, err
	}

	ps := &peerSession{
		to:      to,
		c:       c,
		pending: make(map[uint64]chan Response),
	}
	go ps.readLoop()

	if p.console != nil {
		p.console.AddHistory(fmt.Sprintf("[net] connected to %s (%s)", to.ID, to.Addr))
	}

	return ps, nil
}

// AnnouncePresence establishes connections to all other peers to announce this peer is online
func (p *connPool) AnnouncePresence() {
	for _, peer := range peers {
		if peer.ID == p.self.ID {
			continue
		}

		// Establish connection by getting a session (this triggers handshake)
		_, err := p.NewSession(peer)
		if err != nil {
			// Silently ignore connection failures during announcement
			// Peer might not be online yet
			continue
		}
	}
}

// AnnounceDisconnexion sends goodbye to all connected peers and closes sessions
func (p *connPool) AnnounceDisconnexion() {
	p.mu.Lock()
	// Copy session list to avoid holding lock while sending
	sessions := make(map[PeerID]*peerSession)
	for id, s := range p.sessions {
		sessions[id] = s
	}
	p.mu.Unlock()

	goodbye := Goodbye{SenderID: p.self.ID}
	encoded := encodeGoodbye(goodbye)

	for peerID, s := range sessions {
		if s.isAlive() {
			// Send goodbye message before closing
			s.writeMu.Lock()
			_ = writeMsg(s.c, msgGoodbye, encoded)
			s.writeMu.Unlock()
		}
		p.RemoveSession(peerID)
	}
}
