// Console manager
package main

import (
	"bufio"
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"
	"sync"
)

type consoleRequest struct {
	prompt string
	resp   chan string
}

type console struct {
	reqCh   chan consoleRequest
	printMu sync.Mutex
}

func newConsole() *console {
	c := &console{
		reqCh: make(chan consoleRequest),
	}
	lines := make(chan string)

	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()

	go func() {
		for req := range c.reqCh {
			c.Printf("%s", req.prompt)
			line, ok := <-lines
			if !ok {
				close(req.resp)
				continue
			}
			req.resp <- line
			close(req.resp)
		}
	}()

	return c
}

func (c *console) Ask(prompt string) (string, bool) {
	ch := make(chan string, 1)
	c.reqCh <- consoleRequest{prompt: prompt, resp: ch}
	line, ok := <-ch
	return line, ok
}

func (c *console) Usage(p PeerInfo, selfEdPub ed25519.PublicKey, selfHPKEPubBytes []byte) {
	c.Printf("[%s] up at %s (keyID=%d)\n", p.ID, p.Addr, p.KeyID)
	c.Printf("[%s] pinned Ed25519 pub: %x\n", p.ID, selfEdPub)
	c.Printf("[%s] pinned HPKE pub:     %x\n\n", p.ID, selfHPKEPubBytes)
	c.Printf("Commands:\n")
	c.Printf("  <peer> <message>   send a request (expects a response)\n")
	c.Printf("  /peers             list peers\n")
	c.Printf("  /quit              exit\n\n")
}

// REPL broadcasts to all by default; "@peer ..." = send to one peer.
func (c *console) RPEL(p PeerInfo, pool *connPool) {
	for {
		line, ok := c.Ask("> ")
		if !ok {
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		switch line {
		case "/quit", "/exit":
			return
		case "/peers":
			for _, p := range peers {
				c.Printf("- %s (%s) keyID=%d\n", p.ID, p.Addr, p.KeyID)
			}

			continue
		}

		// Direct message if line starts with @peer
		if strings.HasPrefix(line, "@") {
			toTag, msg, ok := splitFirstWord(line)
			if !ok {
				c.Printf("usage: @peer <message>\n")
				continue
			}

			toTag = strings.TrimPrefix(toTag, "@")
			to := mustPeer(PeerID(toTag))
			if to.ID == p.ID {
				c.Printf("can't send to self\n")
				continue
			}

			respText, err := pool.SendRequest(to, msg)
			if err != nil {
				c.Printf("send failed: %v\n", err)
				continue
			}

			c.Printf("[reply from %s] %s\n", to.ID, respText)

			continue
		}

		// Otherwise: broadcast to everyone else.
		if err := pool.Broadcast(p, line); err != nil {
			c.Printf("broadcast failed: %v\n", err)
		}
	}
}

func (c *console) Printf(format string, args ...any) {
	c.printMu.Lock()
	defer c.printMu.Unlock()
	fmt.Printf(format, args...)
}
