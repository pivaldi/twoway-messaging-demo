package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/cloudflare/circl/kem"
	"github.com/openpcc/twoway"
)

type Response struct {
	RequestID  uint64
	MediaType  []byte
	Ciphertext []byte
}

// runServer: signed hello + loop requests + stdin reply
// func runServer(console *console, suite hpke.Suite, kemScheme kem.Scheme, self PeerInfo, selfHPKEPriv kem.PrivateKey) error {
func (p *connPool) RunServer(selfHPKEPriv kem.PrivateKey) error {

	ln, err := net.Listen("tcp", p.self.Addr)
	if err != nil {
		return err
	}
	defer func() {
		_ = ln.Close()
	}()

	receiver, err := twoway.NewMultiRequestReceiver(p.suite, p.self.KeyID, selfHPKEPriv, rand.Reader)
	if err != nil {
		return fmt.Errorf("error in NewMultiRequestReceiver: %w", err)
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}

		go func(conn net.Conn) {
			defer func() {
				_ = conn.Close()
			}()

			// Challenge -> sender (prevents replay of a signed HELLO).
			chal := make([]byte, 32)
			if _, err := rand.Read(chal); err != nil {
				p.console.Printf("[%s] rand: %v\n", p.self.ID, err)

				return
			}

			if err := writeMsg(conn, msgChallenge, chal); err != nil && p.console != nil {
				p.console.Printf("[%s] write challenge: %v\n", p.self.ID, err)
				return
			}

			// Read signed HELLO.
			typ, helloPayload, err := readMsg(conn)
			if err != nil {
				return
			}
			if typ != msgHello && p.console != nil {
				p.console.Printf("[%s] expected HELLO, got %d\n", p.self.ID, typ)
				return
			}
			hello, err := decodeHello(helloPayload)
			if err != nil {
				p.console.Errorf("[%s] decode hello: %v\n", p.self.ID, err)
				return
			}
			if err := verifySignedHello(p.kemScheme, chal, hello); err != nil {
				p.console.Errorf("[%s] identity verify failed: %v\n", p.self.ID, err)
				return
			}

			p.console.AddHistory(fmt.Sprintf("[net] inbound connection from %s", hello.SenderID))
			_, _ = p.NewSession(mustPeer(hello.SenderID))

			// Loop: handle multiple requests on the same TCP connection.
			for {
				typ, reqPayload, err := readMsg(conn)
				if err != nil {
					return
				}

				// Handle goodbye message
				if typ == msgGoodbye {
					goodbye, err := decodeGoodbye(reqPayload)
					if err != nil {
						p.console.Errorf("[%s] decode goodbye: %v", p.self.ID, err)
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
					p.console.Printf("[%s] decode request: %v\n", p.self.ID, err)
					return
				}

				if req.RecipientKeyID != p.self.KeyID {
					p.console.Printf("[%s] request for keyID=%d (expected %d)\n", p.self.ID, req.RecipientKeyID, p.self.KeyID)
					return
				}

				reqOpener, err := receiver.NewRequestOpener(req.EncapKey, bytes.NewReader(req.Ciphertext), req.MediaType)
				if err != nil {
					p.console.Printf("[%s] NewRequestOpener: %v\n", p.self.ID, err)
					return
				}

				plain, err := io.ReadAll(reqOpener)
				if err != nil {
					p.console.Printf("[%s] read opened request: %v\n", p.self.ID, err)
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
					p.console.Printf("[%s] NewResponseSealer: %v\n", p.self.ID, err)
					return
				}

				respCipher, err := io.ReadAll(respSealer)
				if err != nil {
					p.console.Printf("[%s] read response cipher: %v\n", p.self.ID, err)
					return
				}

				resp := Response{RequestID: req.RequestID, MediaType: respMediaType, Ciphertext: respCipher}
				if err := writeMsg(conn, msgResponse, encodeResponse(resp)); err != nil {
					p.console.Printf("[%s] write response: %v\n", p.self.ID, err)
					return
				}
			}
		}(c)
	}
}
