package node

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func TestEncodeDecodeRegister(t *testing.T) {
	orig := &Register{
		Nickname: "alice",
		Token:    "secret-token",
		HPKEPub:  []byte{1, 2, 3, 4},
		KeyID:    []byte{0x7a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71},
	}

	data := EncodeRegister(orig)
	decoded, err := DecodeRegister(data)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.Nickname != orig.Nickname {
		t.Fatalf("nickname mismatch: %s != %s", decoded.Nickname, orig.Nickname)
	}
	if decoded.Token != orig.Token {
		t.Fatalf("token mismatch")
	}
	if string(decoded.KeyID) != string(orig.KeyID) {
		t.Fatalf("keyID mismatch")
	}
}

func TestEncodeDecodePeerJoined(t *testing.T) {
	addr, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/9000")
	orig := &PeerJoined{
		Nickname: "bob",
		PeerID:   peer.ID("12D3KooWtest"),
		Addrs:    []multiaddr.Multiaddr{addr},
		HPKEPub:  []byte{5, 6, 7, 8},
		KeyID:    []byte{0x42, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
	}

	data := EncodePeerJoined(orig)
	decoded, err := DecodePeerJoined(data)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.Nickname != orig.Nickname {
		t.Fatalf("nickname mismatch")
	}
	if decoded.PeerID != orig.PeerID {
		t.Fatalf("peer ID mismatch")
	}
	if len(decoded.Addrs) != 1 {
		t.Fatalf("expected 1 addr, got %d", len(decoded.Addrs))
	}
	if string(decoded.KeyID) != string(orig.KeyID) {
		t.Fatalf("keyID mismatch")
	}
}

func TestEncodeDecodePeerList(t *testing.T) {
	addr1, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/9001")
	addr2, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/9002")

	orig := &PeerList{
		Peers: []PeerInfo{
			{
				Nickname: "alice",
				PeerID:   peer.ID("12D3KooWalice"),
				Addrs:    []multiaddr.Multiaddr{addr1},
				HPKEPub:  []byte{1, 2, 3},
				KeyID:    []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			},
			{
				Nickname: "bob",
				PeerID:   peer.ID("12D3KooWbob"),
				Addrs:    []multiaddr.Multiaddr{addr2},
				HPKEPub:  []byte{4, 5, 6},
				KeyID:    []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18},
			},
		},
	}

	data := EncodePeerList(orig)
	decoded, err := DecodePeerList(data)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if len(decoded.Peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(decoded.Peers))
	}
	if decoded.Peers[0].Nickname != "alice" {
		t.Fatalf("first peer nickname mismatch")
	}
	if decoded.Peers[1].Nickname != "bob" {
		t.Fatalf("second peer nickname mismatch")
	}
}

func TestEncodeDecodePeerLeft(t *testing.T) {
	orig := &PeerLeft{Nickname: "carol"}

	data := EncodePeerLeft(orig)
	decoded, err := DecodePeerLeft(data)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.Nickname != orig.Nickname {
		t.Fatalf("nickname mismatch")
	}
}

func TestEncodeDecodeRegisterOK(t *testing.T) {
	orig := &RegisterOK{PeerID: peer.ID("12D3KooWtest")}

	data := EncodeRegisterOK(orig)
	decoded, err := DecodeRegisterOK(data)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.PeerID != orig.PeerID {
		t.Fatalf("peerID mismatch")
	}
}

func TestEncodeDecodeRegisterFail(t *testing.T) {
	orig := &RegisterFail{Reason: "invalid token"}

	data := EncodeRegisterFail(orig)
	decoded, err := DecodeRegisterFail(data)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.Reason != orig.Reason {
		t.Fatalf("reason mismatch")
	}
}
