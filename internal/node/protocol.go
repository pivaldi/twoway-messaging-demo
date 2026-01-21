package node

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// ProtocolID for node discovery
const ProtocolID = "/tmd/node/1.0.0"

// Message types
const (
	MsgRegister     byte = 1
	MsgRegisterOK   byte = 2
	MsgRegisterFail byte = 3
	MsgPeerList     byte = 4
	MsgPeerJoined   byte = 5
	MsgPeerLeft     byte = 6
)

// Register is sent by peer to node to authenticate.
type Register struct {
	Nickname string
	Token    string
	HPKEPub  []byte
	KeyID    byte
}

// RegisterOK confirms successful registration.
type RegisterOK struct {
	PeerID peer.ID
}

// RegisterFail indicates registration failure.
type RegisterFail struct {
	Reason string
}

// PeerInfo describes an online peer.
type PeerInfo struct {
	Nickname string
	PeerID   peer.ID
	Addrs    []multiaddr.Multiaddr
	HPKEPub  []byte
	KeyID    byte
}

// PeerList is sent to new peers with all online peers.
type PeerList struct {
	Peers []PeerInfo
}

// PeerJoined is broadcast when a peer comes online.
type PeerJoined struct {
	Nickname string
	PeerID   peer.ID
	Addrs    []multiaddr.Multiaddr
	HPKEPub  []byte
	KeyID    byte
}

// PeerLeft is broadcast when a peer goes offline.
type PeerLeft struct {
	Nickname string
}

// Wire format helpers
func writeBlob(w io.Writer, b []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readBlob(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func writeString(w io.Writer, s string) error {
	return writeBlob(w, []byte(s))
}

func readString(r io.Reader) (string, error) {
	b, err := readBlob(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// WriteMsg writes a typed message to the stream.
func WriteMsg(w io.Writer, typ byte, payload []byte) error {
	total := uint32(1 + len(payload))
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], total)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.Write([]byte{typ}); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadMsg reads a typed message from the stream.
func ReadMsg(r io.Reader) (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 1 {
		return 0, nil, fmt.Errorf("bad msg length")
	}
	var typ [1]byte
	if _, err := io.ReadFull(r, typ[:]); err != nil {
		return 0, nil, err
	}
	payload := make([]byte, n-1)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return typ[0], payload, nil
}

// Encode/Decode Register
func EncodeRegister(r *Register) []byte {
	var b bytes.Buffer
	writeString(&b, r.Nickname)
	writeString(&b, r.Token)
	writeBlob(&b, r.HPKEPub)
	b.WriteByte(r.KeyID)
	return b.Bytes()
}

func DecodeRegister(data []byte) (*Register, error) {
	r := bytes.NewReader(data)
	nickname, err := readString(r)
	if err != nil {
		return nil, err
	}
	token, err := readString(r)
	if err != nil {
		return nil, err
	}
	hpkePub, err := readBlob(r)
	if err != nil {
		return nil, err
	}
	keyID, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	return &Register{
		Nickname: nickname,
		Token:    token,
		HPKEPub:  hpkePub,
		KeyID:    keyID,
	}, nil
}

// Encode/Decode RegisterOK
func EncodeRegisterOK(r *RegisterOK) []byte {
	return []byte(r.PeerID)
}

func DecodeRegisterOK(data []byte) (*RegisterOK, error) {
	return &RegisterOK{PeerID: peer.ID(data)}, nil
}

// Encode/Decode RegisterFail
func EncodeRegisterFail(r *RegisterFail) []byte {
	return []byte(r.Reason)
}

func DecodeRegisterFail(data []byte) (*RegisterFail, error) {
	return &RegisterFail{Reason: string(data)}, nil
}

// Encode/Decode PeerJoined
func EncodePeerJoined(p *PeerJoined) []byte {
	var b bytes.Buffer
	writeString(&b, p.Nickname)
	writeString(&b, string(p.PeerID))
	// Encode addrs count + each addr
	binary.Write(&b, binary.BigEndian, uint32(len(p.Addrs)))
	for _, addr := range p.Addrs {
		writeBlob(&b, addr.Bytes())
	}
	writeBlob(&b, p.HPKEPub)
	b.WriteByte(p.KeyID)
	return b.Bytes()
}

func DecodePeerJoined(data []byte) (*PeerJoined, error) {
	r := bytes.NewReader(data)
	nickname, err := readString(r)
	if err != nil {
		return nil, err
	}
	peerIDStr, err := readString(r)
	if err != nil {
		return nil, err
	}
	var addrCount uint32
	if err := binary.Read(r, binary.BigEndian, &addrCount); err != nil {
		return nil, err
	}
	addrs := make([]multiaddr.Multiaddr, addrCount)
	for i := range addrs {
		addrBytes, err := readBlob(r)
		if err != nil {
			return nil, err
		}
		addr, err := multiaddr.NewMultiaddrBytes(addrBytes)
		if err != nil {
			return nil, err
		}
		addrs[i] = addr
	}
	hpkePub, err := readBlob(r)
	if err != nil {
		return nil, err
	}
	keyID, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	return &PeerJoined{
		Nickname: nickname,
		PeerID:   peer.ID(peerIDStr),
		Addrs:    addrs,
		HPKEPub:  hpkePub,
		KeyID:    keyID,
	}, nil
}

// Encode/Decode PeerLeft
func EncodePeerLeft(p *PeerLeft) []byte {
	return []byte(p.Nickname)
}

func DecodePeerLeft(data []byte) (*PeerLeft, error) {
	return &PeerLeft{Nickname: string(data)}, nil
}

// Encode/Decode PeerList
func EncodePeerList(p *PeerList) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(len(p.Peers)))
	for _, peer := range p.Peers {
		joined := &PeerJoined{
			Nickname: peer.Nickname,
			PeerID:   peer.PeerID,
			Addrs:    peer.Addrs,
			HPKEPub:  peer.HPKEPub,
			KeyID:    peer.KeyID,
		}
		encoded := EncodePeerJoined(joined)
		writeBlob(&b, encoded)
	}
	return b.Bytes()
}

func DecodePeerList(data []byte) (*PeerList, error) {
	r := bytes.NewReader(data)
	var count uint32
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, err
	}
	peers := make([]PeerInfo, count)
	for i := range peers {
		peerData, err := readBlob(r)
		if err != nil {
			return nil, err
		}
		joined, err := DecodePeerJoined(peerData)
		if err != nil {
			return nil, err
		}
		peers[i] = PeerInfo{
			Nickname: joined.Nickname,
			PeerID:   joined.PeerID,
			Addrs:    joined.Addrs,
			HPKEPub:  joined.HPKEPub,
			KeyID:    joined.KeyID,
		}
	}
	return &PeerList{Peers: peers}, nil
}
