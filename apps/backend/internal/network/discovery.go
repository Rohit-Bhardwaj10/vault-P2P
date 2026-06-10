package network

import (
	"context"
	"fmt"
	"log"
	"net"
	gosync "sync"

	vsync "vault-backend/internal/sync"

	"github.com/grandcat/zeroconf"
)	

// Discovery coordinates finding peers via mDNS and feeding their addresses
// to the sync Coordinator so WAL queues can be drained immediately.
type Discovery struct {
	mu    gosync.RWMutex
	addrs map[string]string // peerID → "host:port"
}

func NewDiscovery() *Discovery {
	return &Discovery{addrs: make(map[string]string)}
}

// PeerAddr returns the last-known address for peerID, or "" if unknown.
func (d *Discovery) PeerAddr(peerID string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.addrs[peerID]
}

// StartmDNS registers this node on the local network via mDNS.
// instanceName should be the local peer's ID so other nodes can identify it.
func (d *Discovery) StartmDNS(ctx context.Context, instanceName string, port int) (*zeroconf.Server, error) {
	server, err := zeroconf.Register(instanceName, "_vault._udp", "local.", port, []string{"txtv=1"}, nil)
	if err != nil {
		return nil, fmt.Errorf("register mdns: %w", err)
	}
	return server, nil
}

// BrowsePeers listens for mDNS peer-discovery events.
// When a peer is found it:
//  1. Stores the peer's address (host:port) in the Discovery table.
//  2. Calls coord.MarkOnline so the WAL queue for that peer is drained.
func (d *Discovery) BrowsePeers(ctx context.Context, coord *vsync.Coordinator) error {
	entries := make(chan *zeroconf.ServiceEntry)

	go func() {
		for entry := range entries {
			peerID := entry.Instance
			addr := d.resolveAddr(entry)
			if addr == "" {
				log.Printf("[discovery] mDNS found peer %s but could not resolve address", peerID)
				continue
			}

			d.mu.Lock()
			d.addrs[peerID] = addr
			d.mu.Unlock()

			log.Printf("[discovery] mDNS found peer: %s at %s", peerID, addr)
			coord.MarkOnline(ctx, peerID)
		}
	}()

	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return fmt.Errorf("create resolver: %w", err)
	}

	if err := resolver.Browse(ctx, "_vault._udp", "local.", entries); err != nil {
		return fmt.Errorf("browse mdns: %w", err)
	}
	return nil
}

// resolveAddr picks the best address from an mDNS ServiceEntry.
// Prefers IPv4; falls back to IPv6.
func (d *Discovery) resolveAddr(entry *zeroconf.ServiceEntry) string {
	port := entry.Port
	for _, ip := range entry.AddrIPv4 {
		if !ip.IsLoopback() {
			return fmt.Sprintf("%s:%d", ip.String(), port)
		}
	}
	// Accept loopback too (useful in tests / single-machine setups).
	if len(entry.AddrIPv4) > 0 {
		return fmt.Sprintf("%s:%d", entry.AddrIPv4[0].String(), port)
	}
	for _, ip := range entry.AddrIPv6 {
		return fmt.Sprintf("[%s]:%d", ip.String(), port)
	}
	// Last resort: parse the hostname.
	if entry.HostName != "" {
		ips, err := net.LookupHost(entry.HostName)
		if err == nil && len(ips) > 0 {
			return fmt.Sprintf("%s:%d", ips[0], port)
		}
	}
	return ""
}
