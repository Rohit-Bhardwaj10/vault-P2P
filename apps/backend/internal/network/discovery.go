package network

import (
	"context"
	"fmt"
	"log"

	"vault-backend/internal/sync"

	"github.com/grandcat/zeroconf"
)

// Discovery coordinates finding peers via mDNS, DHT, and Relay Fallback
type Discovery struct {
}

func NewDiscovery() *Discovery {
	return &Discovery{}
}

// StartmDNS starts local network discovery and registers this node
func (d *Discovery) StartmDNS(ctx context.Context, instanceName string, port int) (*zeroconf.Server, error) {
	server, err := zeroconf.Register(instanceName, "_vault._udp", "local.", port, []string{"txtv=1"}, nil)
	if err != nil {
		return nil, fmt.Errorf("register mdns: %w", err)
	}
	return server, nil
}

// BrowsePeers listens for mDNS peer discovery events and notifies the coordinator.
func (d *Discovery) BrowsePeers(ctx context.Context, coord *sync.Coordinator) error {
	entries := make(chan *zeroconf.ServiceEntry)
	
	go func() {
		for entry := range entries {
			// The instance name is the peer's ID.
			peerID := entry.Instance
			log.Printf("[discovery] mDNS found peer: %s at %v:%d", peerID, entry.AddrIPv4, entry.Port)
			// Trigger a WAL drain for this peer.
			coord.MarkOnline(ctx, peerID)
		}
	}()

	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return fmt.Errorf("create resolver: %w", err)
	}

	err = resolver.Browse(ctx, "_vault._udp", "local.", entries)
	
	if err != nil {
		return fmt.Errorf("browse mdns: %w", err)
	}
	return nil
}
