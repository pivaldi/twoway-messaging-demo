package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Wire format
const (
	msgChallenge byte = 1
	msgHello     byte = 2
	msgRequest   byte = 3
	msgResponse  byte = 4
	msgGoodbye   byte = 5
)

// KeyIDSize is the size of key fingerprints in bytes.
const KeyIDSize = 8

// Message format: u32(len(type+payload)) || type(1) || payload
func writeMsg(w io.Writer, typ byte, payload []byte) error {
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

func readMsg(r io.Reader) (byte, []byte, error) {
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

// Blob format: u32(len) || bytes
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

func encodeHello(h Hello) []byte {
	var b bytes.Buffer
	_ = writeBlob(&b, []byte(h.SenderID))
	_ = writeBlob(&b, h.SenderKeyID) // 8-byte key fingerprint
	_ = writeBlob(&b, h.SenderEdPub)
	_ = writeBlob(&b, h.SenderHPKEPub)
	_ = writeBlob(&b, h.Signature)
	return b.Bytes()
}

func decodeHello(p []byte) (Hello, error) {
	r := bytes.NewReader(p)

	id, err := readBlob(r)
	if err != nil {
		return Hello{}, err
	}
	keyID, err := readBlob(r)
	if err != nil {
		return Hello{}, err
	}
	if len(keyID) != KeyIDSize {
		return Hello{}, fmt.Errorf("bad keyID length: %d", len(keyID))
	}
	edPub, err := readBlob(r)
	if err != nil {
		return Hello{}, err
	}
	hpkePub, err := readBlob(r)
	if err != nil {
		return Hello{}, err
	}
	sig, err := readBlob(r)
	if err != nil {
		return Hello{}, err
	}

	return Hello{
		SenderID:      PeerID(id),
		SenderKeyID:   keyID,
		SenderEdPub:   edPub,
		SenderHPKEPub: hpkePub,
		Signature:     sig,
	}, nil
}

type Request struct {
	RequestID      uint64
	RecipientKeyID []byte // 8-byte key fingerprint
	EncapKey       []byte
	MediaType      []byte
	Ciphertext     []byte
}

func encodeRequest(req Request) []byte {
	var b bytes.Buffer
	var id [8]byte
	binary.BigEndian.PutUint64(id[:], req.RequestID)
	_ = writeBlob(&b, id[:])
	_ = writeBlob(&b, req.RecipientKeyID) // 8-byte key fingerprint
	_ = writeBlob(&b, req.EncapKey)
	_ = writeBlob(&b, req.MediaType)
	_ = writeBlob(&b, req.Ciphertext)
	return b.Bytes()
}

func decodeRequest(p []byte) (Request, error) {
	r := bytes.NewReader(p)
	idb, err := readBlob(r)
	if err != nil {
		return Request{}, err
	}
	if len(idb) != 8 {
		return Request{}, fmt.Errorf("bad request id")
	}
	id := binary.BigEndian.Uint64(idb)

	keyID, err := readBlob(r)
	if err != nil {
		return Request{}, err
	}
	if len(keyID) != KeyIDSize {
		return Request{}, fmt.Errorf("bad recipient keyID length: %d", len(keyID))
	}
	encap, err := readBlob(r)
	if err != nil {
		return Request{}, err
	}
	mt, err := readBlob(r)
	if err != nil {
		return Request{}, err
	}
	ct, err := readBlob(r)
	if err != nil {
		return Request{}, err
	}

	return Request{RequestID: id, RecipientKeyID: keyID, EncapKey: encap, MediaType: mt, Ciphertext: ct}, nil
}

func encodeResponse(resp Response) []byte {
	var b bytes.Buffer
	var id [8]byte
	binary.BigEndian.PutUint64(id[:], resp.RequestID)
	_ = writeBlob(&b, id[:])
	_ = writeBlob(&b, resp.MediaType)
	_ = writeBlob(&b, resp.Ciphertext)
	return b.Bytes()
}

func decodeResponse(p []byte) (Response, error) {
	r := bytes.NewReader(p)
	idb, err := readBlob(r)
	if err != nil {
		return Response{}, err
	}
	if len(idb) != 8 {
		return Response{}, fmt.Errorf("bad response id")
	}
	id := binary.BigEndian.Uint64(idb)

	mt, err := readBlob(r)
	if err != nil {
		return Response{}, err
	}
	ct, err := readBlob(r)
	if err != nil {
		return Response{}, err
	}
	return Response{RequestID: id, MediaType: mt, Ciphertext: ct}, nil
}

// Goodbye message: just the sender ID
type Goodbye struct {
	SenderID PeerID
}

func encodeGoodbye(g Goodbye) []byte {
	var b bytes.Buffer
	_ = writeBlob(&b, []byte(g.SenderID))
	return b.Bytes()
}

func decodeGoodbye(p []byte) (Goodbye, error) {
	r := bytes.NewReader(p)
	id, err := readBlob(r)
	if err != nil {
		return Goodbye{}, err
	}
	return Goodbye{SenderID: PeerID(id)}, nil
}
