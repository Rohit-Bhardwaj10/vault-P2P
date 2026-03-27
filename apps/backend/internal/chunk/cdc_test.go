package chunk

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
)

// --- RabinHasher Tests ---

// TestRabinHasher_Deterministic ensures the same byte sequence always produces the same hash.
func TestRabinHasher_Deterministic(t *testing.T) {
	h1 := NewRabinHasher()
	h2 := NewRabinHasher()

	input := []byte("hello vault p2p")
	var fp1, fp2 uint64
	for _, b := range input {
		fp1 = h1.Slide(b)
		fp2 = h2.Slide(b)
	}

	if fp1 != fp2 {
		t.Errorf("non-deterministic: got %d and %d for same input", fp1, fp2)
	}
}

// TestRabinHasher_Reset ensures the hasher returns to a clean state after Reset().
func TestRabinHasher_Reset(t *testing.T) {
	h := NewRabinHasher()

	var fp1 uint64
	for _, b := range []byte("some data") {
		fp1 = h.Slide(b)
	}

	h.Reset()

	var fp2 uint64
	for _, b := range []byte("some data") {
		fp2 = h.Slide(b)
	}

	if fp1 != fp2 {
		t.Errorf("Reset() did not restore hasher: got %d and %d", fp1, fp2)
	}
}

// TestRabinHasher_SlidingWindow ensures different inputs produce different fingerprints.
func TestRabinHasher_SlidingWindow(t *testing.T) {
	h := NewRabinHasher()
	fp1 := h.Slide('A')
	fp2 := h.Slide('B')
	if fp1 == fp2 {
		t.Error("different bytes produced the same fingerprint (collision risk)")
	}
}

// --- HashChunk Tests ---

// TestHashChunk_IsHex ensures HashChunk returns a valid 64-char hex string.
func TestHashChunk_IsHex(t *testing.T) {
	hash := HashChunk([]byte("vault"))

	if len(hash) != 64 {
		t.Errorf("expected 64-char hex string, got length %d: %q", len(hash), hash)
	}

	if _, err := hex.DecodeString(hash); err != nil {
		t.Errorf("HashChunk returned non-hex string: %v", err)
	}
}

// TestHashChunk_Deterministic ensures the same data always gives the same hash.
func TestHashChunk_Deterministic(t *testing.T) {
	data := []byte("consistent input data")
	if HashChunk(data) != HashChunk(data) {
		t.Error("HashChunk is not deterministic")
	}
}

// TestHashChunk_Unique ensures different data gives different hashes.
func TestHashChunk_Unique(t *testing.T) {
	h1 := HashChunk([]byte("chunk one"))
	h2 := HashChunk([]byte("chunk two"))
	if h1 == h2 {
		t.Error("different data produced the same hash")
	}
}

// --- BufferedChunker Tests ---

func collectChunks(t *testing.T, r io.Reader) []*Chunk {
	t.Helper()
	chunker := NewBufferedChunker(r)
	var chunks []*Chunk
	for {
		c, err := chunker.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next() returned unexpected error: %v", err)
		}
		chunks = append(chunks, c)
	}
	return chunks
}

// TestBufferedChunker_Empty ensures an empty reader returns io.EOF immediately.
func TestBufferedChunker_Empty(t *testing.T) {
	chunker := NewBufferedChunker(bytes.NewReader(nil))
	c, err := chunker.Next()
	if err != io.EOF {
		t.Errorf("expected io.EOF for empty reader, got err=%v chunk=%v", err, c)
	}
}

// TestBufferedChunker_SmallFile ensures a file smaller than MinChunkSize is returned as one chunk.
func TestBufferedChunker_SmallFile(t *testing.T) {
	data := []byte("small file content that is definitely under 512KB")
	chunks := collectChunks(t, bytes.NewReader(data))

	if len(chunks) != 1 {
		t.Errorf("expected 1 chunk for small file, got %d", len(chunks))
	}
	if !bytes.Equal(chunks[0].Data, data) {
		t.Error("chunk data does not match original input")
	}
}

// TestBufferedChunker_Reassembly is the most critical test:
// it verifies that chunking and then concatenating all chunk data
// produces the exact original file byte-for-byte.
func TestBufferedChunker_Reassembly(t *testing.T) {
	// 6MB of random data — large enough to cross MinChunkSize (512KB)
	original := make([]byte, 6*1024*1024)
	if _, err := rand.Read(original); err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}

	chunks := collectChunks(t, bytes.NewReader(original))

	if len(chunks) == 0 {
		t.Fatal("got zero chunks for 6MB input")
	}

	var reassembled []byte
	for _, c := range chunks {
		reassembled = append(reassembled, c.Data...)
	}

	if !bytes.Equal(original, reassembled) {
		t.Errorf("reassembled data does not match original: got %d bytes, want %d bytes",
			len(reassembled), len(original))
	}
}

// TestBufferedChunker_Offsets ensures chunk offsets are contiguous and correct.
func TestBufferedChunker_Offsets(t *testing.T) {
	data := make([]byte, 3*1024*1024)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}

	chunks := collectChunks(t, bytes.NewReader(data))

	var expectedOffset int64 = 0
	for idx, c := range chunks {
		if c.Offset != expectedOffset {
			t.Errorf("chunk[%d]: expected offset %d, got %d", idx, expectedOffset, c.Offset)
		}
		expectedOffset += c.Size
	}

	if expectedOffset != int64(len(data)) {
		t.Errorf("total bytes from offsets (%d) != original size (%d)", expectedOffset, len(data))
	}
}

// TestBufferedChunker_ChunkSizeBounds verifies every chunk respects Min/Max size constraints
// (except the final tail chunk, which may be smaller than MinChunkSize).
func TestBufferedChunker_ChunkSizeBounds(t *testing.T) {
	data := make([]byte, 10*1024*1024) // 10MB
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}

	chunks := collectChunks(t, bytes.NewReader(data))

	for i, c := range chunks {
		isFinal := i == len(chunks)-1
		if c.Size > MaxChunkSize {
			t.Errorf("chunk[%d] exceeds MaxChunkSize: size=%d", i, c.Size)
		}
		if !isFinal && c.Size < MinChunkSize {
			t.Errorf("chunk[%d] (non-final) is below MinChunkSize: size=%d", i, c.Size)
		}
	}
}

// TestBufferedChunker_DeltaSync is the core CDC guarantee:
// inserting a few bytes in the MIDDLE of a file should only change the chunks
// at the insertion point — leaving all subsequent chunk hashes identical.
func TestBufferedChunker_DeltaSync(t *testing.T) {
	// Use 20MB of random data. Random bytes maximise Rabin boundary hits
	// (uniform bit distribution), ensuring we get many chunks to compare.
	const size = 20 * 1024 * 1024
	original := make([]byte, size)
	if _, err := rand.Read(original); err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}

	// Insert 16 bytes at the midpoint — simulating a real-world small edit
	mid := size / 2
	insertion := []byte("VAULT_INSERTED!!")
	modified := make([]byte, 0, size+len(insertion))
	modified = append(modified, original[:mid]...)
	modified = append(modified, insertion...)
	modified = append(modified, original[mid:]...)

	chunksOriginal := collectChunks(t, bytes.NewReader(original))
	chunksModified := collectChunks(t, bytes.NewReader(modified))

	if len(chunksOriginal) < 4 {
		t.Skipf("not enough chunks to test DeltaSync (got %d)", len(chunksOriginal))
	}

	// Build hash set from original
	originalHashes := make(map[string]bool, len(chunksOriginal))
	for _, c := range chunksOriginal {
		originalHashes[c.Hash] = true
	}

	// Count how many of the modified chunks are also present in the original
	shared := 0
	for _, c := range chunksModified {
		if originalHashes[c.Hash] {
			shared++
		}
	}

	// CDC guarantee: at least half the chunks should be shared.
	// A mid-file insertion should only disturb the ~1-2 chunks around it.
	threshold := len(chunksOriginal) / 2
	if shared < threshold {
		t.Errorf("CDC DeltaSync degraded: only %d/%d chunks shared (threshold: %d) — too many boundaries shifted",
			shared, len(chunksModified), threshold)
	}
	t.Logf("DeltaSync: %d/%d modified chunks matched originals ✓ (CDC property confirmed)",
		shared, len(chunksModified))
}

// TestBufferedChunker_HashValidity ensures every emitted chunk hash is a valid 64-char hex string.
func TestBufferedChunker_HashValidity(t *testing.T) {
	data := make([]byte, 2*1024*1024)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}

	chunks := collectChunks(t, bytes.NewReader(data))
	for i, c := range chunks {
		if len(c.Hash) != 64 {
			t.Errorf("chunk[%d] hash length is %d, want 64", i, len(c.Hash))
		}
		if _, err := hex.DecodeString(c.Hash); err != nil {
			t.Errorf("chunk[%d] hash is not valid hex: %v", i, err)
		}
	}
}
