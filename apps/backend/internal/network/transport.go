package network

import (
	"context"
)

type Transport struct {
	// quic connection management
}

func NewTransport() *Transport {
	return &Transport{}
}

func (t *Transport) Listen(addr string) error {
	// TODO: Setup QUIC listener
	return nil
}

func (t *Transport) Dial(ctx context.Context, addr string) (interface{}, error) {
	// TODO: Dial a peer via QUIC
	return nil, nil
}
