package network

import (
	"context"
	"github.com/grandcat/zeroconf"
)

// Discovery coordinates finding peers via mDNS, DHT, and Relay Fallback
type Discovery struct {
	// mdns, dht, etc
}

func NewDiscovery() *Discovery {
	return &Discovery{}
}

// StartmDNS starts local network discovery
func (d *Discovery) StartmDNS(ctx context.Context, instanceName string, port int) (*zeroconf.Server, error) {
	server, err := zeroconf.Register(instanceName, "_vault._udp", "local.", port, []string{"txtv=1"}, nil)
	if err != nil {
		return nil, err
	}
	// TODO: Listen for peers
	return server, nil
}
