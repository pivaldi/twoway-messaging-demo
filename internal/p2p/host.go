package p2p

import (
	"fmt"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
)

// NewHost creates a libp2p host with the given private key.
// If port is 0, a random available port is used.
func NewHost(priv crypto.PrivKey, port int) (host.Host, error) {
	listenAddr := fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port)

	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings(listenAddr),
	)
	if err != nil {
		return nil, fmt.Errorf("create libp2p host: %w", err)
	}

	return h, nil
}
