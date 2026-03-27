package sync

// VectorClock implementation for tracking causal consistency
type VectorClock map[string]uint64

// Increment advances the clock for a specific node
func (vc VectorClock) Increment(nodeID string) {
	vc[nodeID]++
}

// Merge takes another vector clock and merges it (taking the max of each node)
func (vc VectorClock) Merge(other VectorClock) {
	for nodeID, time := range other {
		if vc[nodeID] < time {
			vc[nodeID] = time
		}
	}
}

// Compare checks causal relationship: return 1 if vc dominates, -1 if other dominates, 0 if concurrent/equal.
func (vc VectorClock) Compare(other VectorClock) int {
	// TODO: Complete vector clock comparison logic
	return 0
}
