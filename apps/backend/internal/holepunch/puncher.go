// Package holepunch implements QUIC-based NAT hole punching.
//
// Strategy (simultaneous open):
//  1. Both peers learn each other's public address from the rendezvous server.
//  2. Both peers call HolePunch at the same time (coordinated via the
//     rendezvous server's punch endpoint).
//  3. Each peer sends a small UDP probe to the other, which punches a hole
//     in each NAT's mapping table.
//  4. The first peer to successfully dial the other over QUIC wins.
//     The established connection is returned to the caller.
//
// Fallback: if both peers are behind symmetric NAT or the punching window
// is missed, the caller should fall back to the relay (already implemented
// in Deliverer).
package holepunch

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	// probePayload is sent as a UDP probe to open the NAT pinhole.
	probePayload = "vault-punch"
	// punchWindow is how long we keep trying before giving up.
	punchWindow = 5 * time.Second
	// probeInterval is how often we send UDP probes during the window.
	probeInterval = 100 * time.Millisecond
)

var ErrPunchFailed = errors.New("NAT hole punch failed: could not establish direct QUIC connection")

// Puncher performs NAT hole punching against a remote peer.
type Puncher struct {
	// LocalAddr is the UDP address this node listens on for the probe.
	// Use ":0" to let the OS pick an ephemeral port.
	LocalAddr string

	// tlsConf is the QUIC TLS config for the dialling side.
	tlsConf *tls.Config
}

// NewPuncher creates a Puncher.  tlsConf may be nil; a permissive default
// (InsecureSkipVerify) is used since app-level auth is handled by
// Ed25519 capability tokens.
func NewPuncher(localAddr string, tlsConf *tls.Config) *Puncher {
	if tlsConf == nil {
		tlsConf = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // deliberate; see package doc
			NextProtos:         []string{"vault-p2p/1"},
		}
	}
	return &Puncher{LocalAddr: localAddr, tlsConf: tlsConf}
}

// Punch attempts to establish a direct QUIC connection to remoteAddr using
// simultaneous-open NAT hole punching.
//
// It returns the established *quic.Conn on success, or ErrPunchFailed
// if the window expires.  The caller must call conn.CloseWithError when done.
func (p *Puncher) Punch(ctx context.Context, remoteAddr string) (*quic.Conn, error) {
	punchCtx, cancel := context.WithTimeout(ctx, punchWindow)
	defer cancel()

	// Resolve the remote address once.
	rAddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve remote addr %q: %w", remoteAddr, err)
	}

	// Bind a local UDP socket for probing.
	lAddr, err := net.ResolveUDPAddr("udp", p.LocalAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve local addr %q: %w", p.LocalAddr, err)
	}
	conn, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		return nil, fmt.Errorf("bind local UDP: %w", err)
	}
	defer conn.Close()

	actualLocal := conn.LocalAddr().String()
	log.Printf("[holepunch] punching %s → %s from %s", p.LocalAddr, remoteAddr, actualLocal)

	// Send UDP probes in the background to keep the pinhole open.
	go p.sendProbes(punchCtx, conn, rAddr)

	// Attempt QUIC dial repeatedly until the window expires or we succeed.
	return p.dialLoop(punchCtx, remoteAddr)
}

// sendProbes fires small UDP datagrams to remoteAddr to open the NAT mapping.
func (p *Puncher) sendProbes(ctx context.Context, conn *net.UDPConn, remote *net.UDPAddr) {
	probe := []byte(probePayload)
	tick := time.NewTicker(probeInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			_, _ = conn.WriteToUDP(probe, remote)
		}
	}
}

// dialLoop tries quic.DialAddr repeatedly until success or context expiry.
func (p *Puncher) dialLoop(ctx context.Context, remoteAddr string) (*quic.Conn, error) {
	tick := time.NewTicker(probeInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ErrPunchFailed
		case <-tick.C:
			qConn, err := quic.DialAddr(ctx, remoteAddr, p.tlsConf, &quic.Config{
				HandshakeIdleTimeout: 2 * time.Second,
			})
			if err == nil {
				log.Printf("[holepunch] direct connection established to %s", remoteAddr)
				return qConn, nil
			}
		}
	}
}
