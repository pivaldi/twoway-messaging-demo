package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/openpcc/twoway"
)

type Response struct {
	RequestID  uint64
	MediaType  []byte
	Ciphertext []byte
}

// runServer: signed hello + loop requests + stdin reply
func runServer(console *console, suite hpke.Suite, kemScheme kem.Scheme, self PeerInfo, selfHPKEPriv kem.PrivateKey) error {
	ln, err := net.Listen("tcp", self.Addr)
	if err != nil {
		return err
	}
	defer func() {
		_ = ln.Close()
	}()

	receiver, err := twoway.NewMultiRequestReceiver(suite, self.KeyID, selfHPKEPriv, rand.Reader)
	if err != nil {
		return fmt.Errorf("NewMultiRequestReceiver: %w", err)
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
				console.Printf("[%s] rand: %v\n", self.ID, err)
				return
			}
			if err := writeMsg(conn, msgChallenge, chal); err != nil {
				console.Printf("[%s] write challenge: %v\n", self.ID, err)
				return
			}

			// Read signed HELLO.
			typ, helloPayload, err := readMsg(conn)
			if err != nil {
				return
			}
			if typ != msgHello {
				console.Printf("[%s] expected HELLO, got %d\n", self.ID, typ)
				return
			}
			hello, err := decodeHello(helloPayload)
			if err != nil {
				console.Printf("[%s] decode hello: %v\n", self.ID, err)
				return
			}
			if err := verifySignedHello(kemScheme, chal, hello); err != nil {
				console.Printf("[%s] identity verify failed: %v\n", self.ID, err)
				return
			}

			console.AddHistory(fmt.Sprintf("[net] inbound connection from %s", hello.SenderID))

			// Loop: handle multiple requests on the same TCP connection.
			for {
				typ, reqPayload, err := readMsg(conn)
				if err != nil {
					return
				}
				if typ != msgRequest {
					continue
				}
				req, err := decodeRequest(reqPayload)
				if err != nil {
					console.Printf("[%s] decode request: %v\n", self.ID, err)
					return
				}
				if req.RecipientKeyID != self.KeyID {
					console.Printf("[%s] request for keyID=%d (expected %d)\n", self.ID, req.RecipientKeyID, self.KeyID)
					return
				}

				reqOpener, err := receiver.NewRequestOpener(req.EncapKey, bytes.NewReader(req.Ciphertext), req.MediaType)
				if err != nil {
					console.Printf("[%s] NewRequestOpener: %v\n", self.ID, err)
					return
				}
				plain, err := io.ReadAll(reqOpener)
				if err != nil {
					console.Printf("[%s] read opened request: %v\n", self.ID, err)
					return
				}

				// Check if this is a broadcast or direct message
				msgText := string(plain)
				if strings.HasPrefix(msgText, "[BROADCAST]") {
					// Broadcast message - only add to history, not queue
					actualMsg := strings.TrimPrefix(msgText, "[BROADCAST]")
					console.AddHistory(fmt.Sprintf("[broadcast from %s] %s", hello.SenderID, actualMsg))
				} else {
					// Direct message - add to both queue and history
					console.AddDirectMessage(PeerID(hello.SenderID), msgText)
				}

				// Auto-respond with "message received" to satisfy protocol
				reply := "message received"

				respMediaType := []byte("text/plain; purpose=resp")
				respSealer, err := reqOpener.NewResponseSealer(strings.NewReader(reply), respMediaType)
				if err != nil {
					console.Printf("[%s] NewResponseSealer: %v\n", self.ID, err)
					return
				}
				respCipher, err := io.ReadAll(respSealer)
				if err != nil {
					console.Printf("[%s] read response cipher: %v\n", self.ID, err)
					return
				}

				resp := Response{RequestID: req.RequestID, MediaType: respMediaType, Ciphertext: respCipher}
				if err := writeMsg(conn, msgResponse, encodeResponse(resp)); err != nil {
					console.Printf("[%s] write response: %v\n", self.ID, err)
					return
				}
			}
		}(c)
	}
}
