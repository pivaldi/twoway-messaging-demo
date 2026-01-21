package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"strings"

	"github.com/cloudflare/circl/kem"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/openpcc/twoway"
)

type Response struct {
	RequestID  uint64
	MediaType  []byte
	Ciphertext []byte
}

// SetupStreamHandler sets up the libp2p stream handler for incoming messages
func (p *connPool) SetupStreamHandler(selfHPKEPriv kem.PrivateKey) error {
	// Use first byte of KeyID for twoway library compatibility
	receiver, err := twoway.NewMultiRequestReceiver(p.suite, p.keyID[0], selfHPKEPriv, rand.Reader)
	if err != nil {
		return fmt.Errorf("error in NewMultiRequestReceiver: %w", err)
	}

	p.host.SetStreamHandler(ProtocolID, func(stream network.Stream) {
		p.handleStream(stream, receiver)
	})

	return nil
}

func (p *connPool) handleStream(stream network.Stream, receiver *twoway.MultiRequestReceiver) {
	defer func() {
		_ = stream.Close()
	}()

	// Challenge -> sender (prevents replay of a signed HELLO).
	chal := make([]byte, 32)
	if _, err := rand.Read(chal); err != nil {
		p.console.Printf("[%s] rand: %v\n", p.nickname, err)
		return
	}

	if err := writeMsg(stream, msgChallenge, chal); err != nil && p.console != nil {
		p.console.Printf("[%s] write challenge: %v\n", p.nickname, err)
		return
	}

	// Read signed HELLO.
	typ, helloPayload, err := readMsg(stream)
	if err != nil {
		return
	}
	if typ != msgHello && p.console != nil {
		p.console.Printf("[%s] expected HELLO, got %d\n", p.nickname, typ)
		return
	}
	hello, err := decodeHello(helloPayload)
	if err != nil {
		p.console.Errorf("[%s] decode hello: %v\n", p.nickname, err)
		return
	}
	if err := verifySignedHello(p.kemScheme, chal, hello); err != nil {
		p.console.Errorf("[%s] identity verify failed: %v\n", p.nickname, err)
		return
	}

	p.console.AddHistory(fmt.Sprintf("[net] inbound connection from %s", hello.SenderID))

	// Get peer info from table if available, or create minimal entry
	peerInfo, ok := p.peerTable.Get(hello.SenderID)
	if ok {
		_, _ = p.NewSession(peerInfo)
	}

	// Loop: handle multiple requests on the same stream.
	for {
		typ, reqPayload, err := readMsg(stream)
		if err != nil {
			return
		}

		// Handle goodbye message
		if typ == msgGoodbye {
			goodbye, err := decodeGoodbye(reqPayload)
			if err != nil {
				p.console.Errorf("[%s] decode goodbye: %v", p.nickname, err)
				return
			}
			p.RemoveSession(goodbye.SenderID)
			return
		}

		if typ != msgRequest {
			continue
		}
		req, err := decodeRequest(reqPayload)
		if err != nil {
			p.console.Printf("[%s] decode request: %v\n", p.nickname, err)
			return
		}

		if !bytes.Equal(req.RecipientKeyID, p.keyID) {
			p.console.Printf("[%s] request for keyID=%x (expected %x)\n", p.nickname, req.RecipientKeyID, p.keyID)
			return
		}

		reqOpener, err := receiver.NewRequestOpener(req.EncapKey, bytes.NewReader(req.Ciphertext), req.MediaType)
		if err != nil {
			p.console.Printf("[%s] NewRequestOpener: %v\n", p.nickname, err)
			return
		}

		plain, err := io.ReadAll(reqOpener)
		if err != nil {
			p.console.Printf("[%s] read opened request: %v\n", p.nickname, err)
			return
		}

		// Check if this is a broadcast or direct message
		msgText := string(plain)
		if after, ok := strings.CutPrefix(msgText, "[BROADCAST]"); ok {
			// Broadcast message - only add to history, not queue
			actualMsg := after
			p.console.AddHistory(fmt.Sprintf("[broadcast from %s] %s", hello.SenderID, actualMsg))
		} else {
			// Direct message - add to both queue and history
			p.console.AddDirectMessage(PeerID(hello.SenderID), msgText)
		}

		// Auto-respond with "message received" to satisfy protocol
		reply := "message received"

		respMediaType := []byte("text/plain; purpose=resp")
		respSealer, err := reqOpener.NewResponseSealer(strings.NewReader(reply), respMediaType)
		if err != nil {
			p.console.Printf("[%s] NewResponseSealer: %v\n", p.nickname, err)
			return
		}

		respCipher, err := io.ReadAll(respSealer)
		if err != nil {
			p.console.Printf("[%s] read response cipher: %v\n", p.nickname, err)
			return
		}

		resp := Response{RequestID: req.RequestID, MediaType: respMediaType, Ciphertext: respCipher}
		if err := writeMsg(stream, msgResponse, encodeResponse(resp)); err != nil {
			p.console.Printf("[%s] write response: %v\n", p.nickname, err)
			return
		}
	}
}
