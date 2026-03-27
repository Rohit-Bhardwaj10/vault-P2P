package sync

// Coordinator manages sync queues for offline delivery and gossip
type Coordinator struct {
	// Sync queues, WAL interactions
}

func NewCoordinator() *Coordinator {
	return &Coordinator{}
}

func (c *Coordinator) Enqueue(peerID string, op []byte) error {
	// TODO: Enqueue in WAL
	return nil
}

func (c *Coordinator) ProcessQueue(peerID string) {
	// TODO: Send operations when peer is online
}
