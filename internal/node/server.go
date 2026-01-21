package node

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// Config for the node server.
type Config struct {
	Listen string            `json:"listen"`
	Peers  map[string]string `json:"peers"` // nickname -> token
}

// LoadConfig loads config from a JSON file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// Server is the node discovery server.
type Server struct {
	host   host.Host
	config *Config

	mu      sync.RWMutex
	online  map[string]*onlinePeer       // nickname -> peer info
	streams map[string]network.Stream    // nickname -> stream for push
}

type onlinePeer struct {
	Nickname string
	PeerID   peer.ID
	Addrs    []multiaddr.Multiaddr
	HPKEPub  []byte
	KeyID    byte
}

// NewServer creates a new node server.
func NewServer(h host.Host, cfg *Config) *Server {
	s := &Server{
		host:    h,
		config:  cfg,
		online:  make(map[string]*onlinePeer),
		streams: make(map[string]network.Stream),
	}

	h.SetStreamHandler(ProtocolID, s.handleStream)

	return s
}

func (s *Server) handleStream(stream network.Stream) {
	defer stream.Close()

	// Read Register message
	typ, payload, err := ReadMsg(stream)
	if err != nil {
		return
	}
	if typ != MsgRegister {
		s.sendFail(stream, "expected Register message")
		return
	}

	reg, err := DecodeRegister(payload)
	if err != nil {
		s.sendFail(stream, "invalid Register message")
		return
	}

	// Validate token
	expectedToken, ok := s.config.Peers[reg.Nickname]
	if !ok {
		s.sendFail(stream, "unknown nickname")
		return
	}
	if reg.Token != expectedToken {
		s.sendFail(stream, "invalid token")
		return
	}

	// Check if already online
	s.mu.Lock()
	if _, exists := s.online[reg.Nickname]; exists {
		s.mu.Unlock()
		s.sendFail(stream, "nickname already in use")
		return
	}

	// Get peer's addresses from the connection
	peerID := stream.Conn().RemotePeer()
	addrs := s.host.Peerstore().Addrs(peerID)

	newPeer := &onlinePeer{
		Nickname: reg.Nickname,
		PeerID:   peerID,
		Addrs:    addrs,
		HPKEPub:  reg.HPKEPub,
		KeyID:    reg.KeyID,
	}

	// Build peer list before adding new peer
	peerList := s.buildPeerList()

	// Add to online peers
	s.online[reg.Nickname] = newPeer
	s.streams[reg.Nickname] = stream
	s.mu.Unlock()

	// Send RegisterOK
	if err := WriteMsg(stream, MsgRegisterOK, EncodeRegisterOK(&RegisterOK{PeerID: peerID})); err != nil {
		s.removePeer(reg.Nickname)
		return
	}

	// Send PeerList
	if err := WriteMsg(stream, MsgPeerList, EncodePeerList(&PeerList{Peers: peerList})); err != nil {
		s.removePeer(reg.Nickname)
		return
	}

	// Broadcast PeerJoined to others
	s.broadcastJoined(newPeer)

	// Keep stream open for push messages, wait for close
	buf := make([]byte, 1)
	for {
		_, err := stream.Read(buf)
		if err != nil {
			break
		}
	}

	// Peer disconnected
	s.removePeer(reg.Nickname)
	s.broadcastLeft(reg.Nickname)
}

func (s *Server) sendFail(stream network.Stream, reason string) {
	WriteMsg(stream, MsgRegisterFail, EncodeRegisterFail(&RegisterFail{Reason: reason}))
}

func (s *Server) buildPeerList() []PeerInfo {
	var list []PeerInfo
	for _, p := range s.online {
		list = append(list, PeerInfo{
			Nickname: p.Nickname,
			PeerID:   p.PeerID,
			Addrs:    p.Addrs,
			HPKEPub:  p.HPKEPub,
			KeyID:    p.KeyID,
		})
	}
	return list
}

func (s *Server) removePeer(nickname string) {
	s.mu.Lock()
	delete(s.online, nickname)
	delete(s.streams, nickname)
	s.mu.Unlock()
}

func (s *Server) broadcastJoined(p *onlinePeer) {
	msg := &PeerJoined{
		Nickname: p.Nickname,
		PeerID:   p.PeerID,
		Addrs:    p.Addrs,
		HPKEPub:  p.HPKEPub,
		KeyID:    p.KeyID,
	}
	encoded := EncodePeerJoined(msg)

	s.mu.RLock()
	defer s.mu.RUnlock()

	for nickname, stream := range s.streams {
		if nickname != p.Nickname {
			WriteMsg(stream, MsgPeerJoined, encoded)
		}
	}
}

func (s *Server) broadcastLeft(nickname string) {
	msg := &PeerLeft{Nickname: nickname}
	encoded := EncodePeerLeft(msg)

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, stream := range s.streams {
		WriteMsg(stream, MsgPeerLeft, encoded)
	}
}

// Addrs returns the node's multiaddrs for clients to connect to.
func (s *Server) Addrs() []multiaddr.Multiaddr {
	return s.host.Addrs()
}

// ID returns the node's peer ID.
func (s *Server) ID() peer.ID {
	return s.host.ID()
}

// OnlinePeers returns the count of online peers.
func (s *Server) OnlinePeers() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.online)
}
