package chunk

import (
	"io"
	"lukechampine.com/blake3"
)

// Chunk represents a single piece of a file after chunking
type Chunk struct {
	Hash   string
	Data   []byte
	Size   int64
	Offset int64
}

// Chunker is responsible for Content-Defined Chunking (CDC) using Rabin fingerprinting
type Chunker struct {
	// Configuration for chunk sizes (Min, Max, Avg)
}

func NewChunker() *Chunker {
	return &Chunker{}
}

// Split divides an io.Reader into chunks based on CDC
func (c *Chunker) Split(reader io.Reader) ([]Chunk, error) {
	// TODO: Implement Rabin fingerprinting CDC
	return nil, nil
}

// HashChunk calculates the blake3 hash of a chunk's data
func HashChunk(data []byte) string {
	sum := blake3.Sum256(data)
	return string(sum[:])
}
