// Console manager with TUI
package main

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
)

type queuedMessage struct {
	from      PeerID
	message   string
	timestamp time.Time
}

type historyMessage struct {
	text      string
	timestamp time.Time
}

type console struct {
	screen tcell.Screen
	self   PeerInfo
	pool   *connPool

	// Message storage
	queueMu   sync.Mutex
	queue     map[PeerID][]queuedMessage // Unreplied messages per peer
	historyMu sync.Mutex
	history   []historyMessage // All messages

	// Input state
	inputMu     sync.Mutex
	inputBuffer string
	cursorPos   int

	// Render lock (tcell is not thread-safe)
	renderMu sync.Mutex

	// Channels
	inputCh chan string
	quitCh  chan struct{}
}

func newConsole(me PeerInfo, pool *connPool) (*console, error) {
	screen, err := tcell.NewScreen()
	if err != nil {
		return nil, err
	}
	if err := screen.Init(); err != nil {
		return nil, err
	}

	// Enable mouse and set style
	screen.EnableMouse()
	screen.Clear()

	c := &console{
		screen:  screen,
		self:    me,
		pool:    pool,
		queue:   make(map[PeerID][]queuedMessage),
		history: make([]historyMessage, 0),
		inputCh: make(chan string, 10),
		quitCh:  make(chan struct{}),
	}

	// Start event handler
	go c.handleEvents()

	// Initial render
	c.render()

	return c, nil
}

func (c *console) Close() {
	close(c.quitCh)
	c.screen.Fini()
}

func (c *console) handleEvents() {
	for {
		select {
		case <-c.quitCh:
			return
		default:
		}

		ev := c.screen.PollEvent()
		if ev == nil {
			continue
		}
		switch ev := ev.(type) {
		case *tcell.EventKey:
			c.handleKeyEvent(ev)
		case *tcell.EventResize:
			c.screen.Sync()
			c.render()
		}
	}
}

func (c *console) handleKeyEvent(ev *tcell.EventKey) {
	c.inputMu.Lock()

	switch ev.Key() {
	case tcell.KeyEnter:
		if c.inputBuffer != "" {
			line := c.inputBuffer
			c.inputBuffer = ""
			c.cursorPos = 0
			c.inputMu.Unlock()
			c.inputCh <- line
			c.render()
			return
		}
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		if c.cursorPos > 0 {
			c.inputBuffer = c.inputBuffer[:c.cursorPos-1] + c.inputBuffer[c.cursorPos:]
			c.cursorPos--
		}
	case tcell.KeyLeft:
		if c.cursorPos > 0 {
			c.cursorPos--
		}
	case tcell.KeyRight:
		if c.cursorPos < len(c.inputBuffer) {
			c.cursorPos++
		}
	case tcell.KeyCtrlC:
		c.inputMu.Unlock()
		c.inputCh <- "/quit"
		return
	case tcell.KeyRune:
		r := ev.Rune()
		c.inputBuffer = c.inputBuffer[:c.cursorPos] + string(r) + c.inputBuffer[c.cursorPos:]
		c.cursorPos++
	default:
		// Check if it's a printable rune
		if ev.Key() == tcell.KeyRune {
			r := ev.Rune()
			c.inputBuffer = c.inputBuffer[:c.cursorPos] + string(r) + c.inputBuffer[c.cursorPos:]
			c.cursorPos++
		}
	}

	c.inputMu.Unlock()
	c.render()
}

func (c *console) render() {
	c.renderMu.Lock()
	defer c.renderMu.Unlock()

	c.screen.Clear()
	width, height := c.screen.Size()

	// Calculate pane dimensions
	leftWidth := width * 30 / 100
	rightWidth := width - leftWidth - 1
	inputHeight := 1
	rightTopHeight := height - inputHeight - 1

	// Draw vertical separator
	for y := 0; y < height-inputHeight; y++ {
		c.screen.SetContent(leftWidth, y, '│', nil, tcell.StyleDefault)
	}

	// Draw horizontal separator
	for x := leftWidth + 1; x < width; x++ {
		c.screen.SetContent(x, height-inputHeight-1, '─', nil, tcell.StyleDefault)
	}
	c.screen.SetContent(leftWidth, height-inputHeight-1, '┼', nil, tcell.StyleDefault)

	// Render left pane (queue)
	c.renderQueue(0, 0, leftWidth, height-inputHeight-1)

	// Render right-top pane (history)
	c.renderHistory(leftWidth+1, 0, rightWidth, rightTopHeight)

	// Render input line
	c.renderInput(leftWidth+1, height-1, rightWidth)

	c.screen.Show()
}

func (c *console) renderQueue(x, y, width, height int) {
	c.queueMu.Lock()
	defer c.queueMu.Unlock()

	// Title
	c.drawText(x, y, width, "Direct Queue", tcell.StyleDefault.Bold(true))
	currentY := y + 1

	if len(c.queue) == 0 {
		c.drawText(x, currentY, width, "(no unreplied messages)", tcell.StyleDefault.Dim(true))
		return
	}

	// Render queued messages by peer
	for peerID, messages := range c.queue {
		if len(messages) == 0 {
			continue
		}

		if currentY >= y+height {
			break
		}

		// Peer header with count
		header := fmt.Sprintf("%s (%d):", peerID, len(messages))
		c.drawText(x, currentY, width, header, tcell.StyleDefault.Bold(true))
		currentY++

		// Show messages (truncated)
		for _, msg := range messages {
			if currentY >= y+height {
				break
			}

			text := msg.message
			if len(text) > 50 {
				text = text[:47] + "..."
			}
			c.drawText(x+2, currentY, width-2, text, tcell.StyleDefault)
			currentY++
		}

		currentY++ // Blank line between peers
	}
}

func (c *console) renderHistory(x, y, width, height int) {
	c.historyMu.Lock()
	defer c.historyMu.Unlock()

	// Title
	c.drawText(x, y, width, "General Messages", tcell.StyleDefault.Bold(true))

	if len(c.history) == 0 {
		c.drawText(x, y+1, width, "(no messages yet)", tcell.StyleDefault.Dim(true))
		return
	}

	// Calculate visible messages (show most recent)
	startIdx := 0
	if len(c.history) > height-1 {
		startIdx = len(c.history) - (height - 1)
	}

	currentY := y + 1
	for i := startIdx; i < len(c.history) && currentY < y+height; i++ {
		c.drawText(x, currentY, width, c.history[i].text, tcell.StyleDefault)
		currentY++
	}
}

func (c *console) renderInput(x, y, width int) {
	c.inputMu.Lock()
	defer c.inputMu.Unlock()

	prompt := "> "
	c.drawText(x, y, len(prompt), prompt, tcell.StyleDefault)

	// Draw input buffer
	displayText := c.inputBuffer
	displayOffset := 0
	maxInputWidth := width - len(prompt) - 1

	if len(displayText) > maxInputWidth {
		// Scroll to keep cursor visible
		if c.cursorPos > maxInputWidth {
			displayOffset = c.cursorPos - maxInputWidth
		}
		displayText = displayText[displayOffset:]
		if len(displayText) > maxInputWidth {
			displayText = displayText[:maxInputWidth]
		}
	}

	c.drawText(x+len(prompt), y, width-len(prompt), displayText, tcell.StyleDefault)

	// Position cursor
	cursorX := x + len(prompt) + c.cursorPos - displayOffset
	if cursorX >= x+width {
		cursorX = x + width - 1
	}
	if cursorX < x+len(prompt) {
		cursorX = x + len(prompt)
	}
	c.screen.ShowCursor(cursorX, y)
}

func (c *console) drawText(x, y, maxWidth int, text string, style tcell.Style) {
	for i, r := range text {
		if i >= maxWidth {
			break
		}
		c.screen.SetContent(x+i, y, r, nil, style)
	}
}

func (c *console) Usage(nickname PeerID, keyID byte, selfEdPub ed25519.PublicKey, selfHPKEPubBytes []byte, peerID string) {
	c.AddHistory(fmt.Sprintf("[%s] up with peerID=%s (keyID=%d)", nickname, peerID, keyID))
	c.AddHistory(fmt.Sprintf("[%s] pinned Ed25519 pub: %x", nickname, selfEdPub))
	c.AddHistory(fmt.Sprintf("[%s] pinned HPKE pub:    %x", nickname, selfHPKEPubBytes))
	c.AddHistory("")
	c.AddHistory("Commands:")
	c.AddHistory("  @peer message   send a request")
	c.AddHistory("  /peers          list online peers")
	c.AddHistory("  /quit           exit")
	c.AddHistory("")
}

// AddDirectMessage adds a message to both queue and history
func (c *console) AddDirectMessage(from PeerID, message string) {
	c.queueMu.Lock()
	c.queue[from] = append(c.queue[from], queuedMessage{
		from:      from,
		message:   message,
		timestamp: time.Now(),
	})
	c.queueMu.Unlock()

	c.AddHistory(fmt.Sprintf("[from %s] %s", from, message))
}

// ClearQueue clears all queued messages from a specific peer
func (c *console) ClearQueue(peerID PeerID) int {
	c.queueMu.Lock()
	defer c.queueMu.Unlock()

	count := len(c.queue[peerID])
	delete(c.queue, peerID)
	return count
}

// AddHistory adds a message to the general history pane
func (c *console) AddHistory(text string) {
	if c == nil {
		return
	}

	c.historyMu.Lock()
	// Strip trailing newlines
	text = strings.TrimRight(text, "\n")
	c.history = append(c.history, historyMessage{
		text:      text,
		timestamp: time.Now(),
	})
	c.historyMu.Unlock()

	c.render()
}

// Printf adds a formatted message to history
func (c *console) Printf(format string, args ...any) {
	if c == nil {
		return
	}

	c.AddHistory(fmt.Sprintf(format, args...))
}

// Errorf adds a formatted error message to history
func (c *console) Errorf(format string, args ...any) {
	if c == nil {
		return
	}

	c.AddHistory(fmt.Sprintf("[error] "+format, args...))
}

// ReadLine reads a line of input (blocking)
func (c *console) ReadLine() (string, bool) {
	if c == nil {
		return "", false
	}

	select {
	case line := <-c.inputCh:
		return line, true
	case <-c.quitCh:
		return "", false
	}
}

// REPL runs the main input loop
func (c *console) REPL(pool *connPool) {
	for {
		line, ok := c.ReadLine()
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
			c.listPeers()
			continue
		}

		// Direct message if line starts with @peer
		if strings.HasPrefix(line, "@") {
			toTag, msg, ok := splitFirstWord(line)
			if !ok {
				c.Errorf("usage: @peer <message>")
				continue
			}

			toTag = strings.TrimPrefix(toTag, "@")
			to, found := pool.peerTable.Get(PeerID(toTag))
			if !found {
				c.Errorf("unknown peer: %s", toTag)
				continue
			}
			c.sendTo(to, msg)
			continue
		}

		// Otherwise: broadcast to everyone else.
		count := len(pool.peerTable.All())
		if err := pool.Broadcast(line); err != nil {
			c.Errorf("broadcast failed: %v", err)
		} else {
			c.Printf("[broadcast] %s sent to %d peers: %s", c.self.Nickname, count, line)
		}
	}
}

func (c *console) listPeers() {
	peers := c.pool.peerTable.All()
	if len(peers) == 0 {
		c.Printf("No online peers")
		return
	}
	for _, p := range peers {
		c.Printf("- %s (peerID=%s) keyID=%d", p.Nickname, p.PeerID.ShortString(), p.KeyID)
	}
}

func (c *console) sendTo(to PeerInfo, msg string) {
	if c == nil {
		return
	}

	if to.Nickname == c.self.Nickname {
		c.Errorf("can't send to self")
		return
	}

	// Clear queue for this peer
	_ = c.ClearQueue(to.Nickname)
	_, err := c.pool.SendRequest(to, msg)
	if err != nil {
		c.Errorf("send failed: %v", err)
		return
	}

	c.Printf("[%s to %s] %s", c.self.Nickname, to.Nickname, msg)
}
