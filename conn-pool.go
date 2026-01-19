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

func newConnPool(c *console, suite hpke.Suite, kemScheme kem.Scheme, self PeerInfo, selfEdPriv ed25519.PrivateKey, selfHPKEPubBytes []byte) *connPool {
	return &connPool{
		console:          c,
		suite:            suite,
		kemScheme:        kemScheme,
		self:             self,
		selfEdPriv:       selfEdPriv,
		selfHPKEPubBytes: selfHPKEPubBytes,
		sessions:         make(map[PeerID]*peerSession),
	}
}

func (p *connPool) get(to PeerInfo) (*peerSession, error) {
	p.mu.Lock()
	if s := p.sessions[to.ID]; s != nil && s.isAlive() {
		p.mu.Unlock()
		return s, nil
	}
	p.mu.Unlock()

	// Create a new session.
	ps, err := dialAndHandshake(p.console, p.kemScheme, p.self, to, p.selfEdPriv, p.selfHPKEPubBytes)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.sessions[to.ID] = ps
	p.mu.Unlock()
	return ps, nil
}

func (p *connPool) SendRequest(to PeerInfo, msg string) (string, error) {
	ps, err := p.get(to)
	if err != nil {
		return "", err
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

	resp, err := ps.DoRequest(req)
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

	for _, peer := range peers {
		if peer.ID == self.ID {
			continue
		}
		to := peer
		g.Go(func() error {
			respText, err := p.SendRequest(to, msg)
			if err != nil {
				return fmt.Errorf("to %s: %w", to.ID, err)
			}

			p.console.Printf("[reply from %s] %s\n", to.ID, respText)
			return nil
		})
	}

	return g.Wait()
}

func dialAndHandshake(console *console, kemScheme kem.Scheme, self PeerInfo, to PeerInfo, selfEdPriv ed25519.PrivateKey, selfHPKEPubBytes []byte) (*peerSession, error) {
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
		SenderID:      self.ID,
		SenderKeyID:   self.KeyID,
		SenderEdPub:   selfEdPriv.Public().(ed25519.PublicKey),
		SenderHPKEPub: selfHPKEPubBytes,
		Signature:     nil,
	}
	hello.Signature = ed25519.Sign(selfEdPriv, helloSignInput(chal, hello))
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

	console.Printf("[net] connected to %s (%s)\n", to.ID, to.Addr)
	_ = kemScheme // kept for symmetry / future use
	return ps, nil
}
