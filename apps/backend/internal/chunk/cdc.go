package chunk

import (
	"encoding/hex"
	"io"

	"lukechampine.com/blake3"
)

const (
	WindowSize    = 64              // 64 bytes
	MinChunkSize  = 512 * 1024      // 512KB
	MaxChunkSize  = 8 * 1024 * 1024 // 8MB
	TargetAvgSize = 2 * 1024 * 1024 // 2MB

	Mask    = (1 << 21) - 1
	Pattern = 0
	// Rabin polynomial (irreducible over GF(2))
	Poly        = 0x3DA3358B4DC173
	readBufSize = 64 * 1024 // 64KB
)

// rabin hasher - implememts the rolling hash logic
type RabinHasher struct {
	window []byte
	pos    int
	hash   uint64
	tables [256]uint64
}

func NewRabinHasher() *RabinHasher {
	h := &RabinHasher{
		window: make([]byte, WindowSize),
		pos:    0,
		hash:   0,
	}
	// Precompute tables
	for i := 0; i < 256; i++ {
		h.tables[i] = uint64(i)
		for j := 0; j < 8; j++ {
			if h.tables[i]&1 == 1 {
				h.tables[i] = (h.tables[i] >> 1) ^ Poly
			} else {
				h.tables[i] >>= 1
			}
		}
	}
	return h
}

func (h *RabinHasher) Slide(b byte) uint64 {
	out := h.window[h.pos]
	h.window[h.pos] = b
	h.pos = (h.pos + 1) % WindowSize
	h.hash ^= h.tables[out]
	h.hash = (h.hash >> 1) ^ h.tables[b]
	return h.hash
}

func (h *RabinHasher) Reset() {
	h.hash = 0
	h.pos = 0
	for i := range h.window {
		h.window[i] = 0
	}
}

type Chunk struct {
	Hash   string
	Data   []byte
	Size   int64
	Offset int64
}

// HashChunk calculates the BLAKE3 hash of a chunk's data, returned as a hex string.
// Using hex ensures the hash is safe for SQLite storage, JSON serialisation, and DHT lookups.
func HashChunk(data []byte) string {
	sum := blake3.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// BufferedChunker splits an io.Reader into Chunks using the RabinHasher
type BufferedChunker struct {
	r       io.Reader
	hasher  *RabinHasher
	readBuf []byte
	pending []byte
	offset  int64
	done    bool
}

func NewBufferedChunker(r io.Reader) *BufferedChunker {
	return &BufferedChunker{
		r:       r,
		hasher:  NewRabinHasher(),
		readBuf: make([]byte, readBufSize),
	}
}

// Next reads and returns the next chunk from the reader.
// Returns (nil, io.EOF) when all chunks have been consumed.
func (c *BufferedChunker) Next() (*Chunk, error) {
	if c.done && len(c.pending) == 0 {
		return nil, io.EOF
	}
	startOffset := c.offset
	c.hasher.Reset()

	// scanned tracks how many bytes of c.pending have already been fed
	// into the hasher, so we never re-slide the same byte twice across
	// multiple reads from the underlying io.Reader.
	scanned := 0

	for {
		// 1. Scan only the NEW bytes appended since the last read
		for i := scanned; i < len(c.pending); i++ {
			fp := c.hasher.Slide(c.pending[i])
			chunkLen := i + 1

			// Emit chunk if: max size hit, OR min size passed and fingerprint matches
			if chunkLen >= MaxChunkSize || (chunkLen >= MinChunkSize && fp&Mask == Pattern) {
				data := make([]byte, chunkLen)
				copy(data, c.pending[:chunkLen])
				c.pending = c.pending[chunkLen:]
				c.offset += int64(chunkLen)
				return &Chunk{
					Data:   data,
					Size:   int64(chunkLen),
					Offset: startOffset,
					Hash:   HashChunk(data),
				}, nil
			}
		}
		// All current pending bytes have been scanned; advance cursor
		scanned = len(c.pending)

		// 2. No boundary found — check if source is exhausted
		if c.done {
			// Tail flush: emit whatever remains as the final chunk
			if len(c.pending) > 0 {
				data := c.pending
				chunkLen := len(data)
				c.pending = nil
				c.offset += int64(chunkLen)
				return &Chunk{
					Data:   data,
					Size:   int64(chunkLen),
					Offset: startOffset,
					Hash:   HashChunk(data),
				}, nil
			}
			return nil, io.EOF
		}

		// 3. Read more data from the source into pending
		n, err := c.r.Read(c.readBuf)
		if n > 0 {
			c.pending = append(c.pending, c.readBuf[:n]...)
		}
		if err == io.EOF {
			c.done = true
		} else if err != nil {
			return nil, err
		}
	}
}
