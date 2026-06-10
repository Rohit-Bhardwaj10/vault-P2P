package network

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"vault-backend/internal/chunk"
	"vault-backend/internal/crypto"
	"vault-backend/internal/store"

	"github.com/quic-go/quic-go"
)

// quicProto is the ALPN protocol identifier negotiated during the TLS handshake.
const quicProto = "vault-p2p/1"

var errEndTransfer = errors.New("transfer complete")

// Transport sends and receives files over QUIC (RFC 9000).
//
// QUIC provides:
//   - Multiplexed streams over a single UDP connection
//   - Built-in TLS 1.3 (no extra round-trip for encryption)
//   - Connection migration (survives IP change mid-transfer)
//   - No head-of-line blocking at the transport layer
//
// Transport-layer identity uses a self-signed ephemeral TLS cert.
// App-level peer identity is verified separately via Ed25519 capability tokens.
type Transport struct{}

func NewTransport() *Transport { return &Transport{} }

// serverTLSConfig generates a fresh self-signed ECDSA certificate for each
// QUIC listener. The cert is ephemeral — app-level identity is handled by
// Ed25519 capability tokens, not TLS certificates.
func serverTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate TLS key: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vault-p2p"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	pub := key.Public()
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		return nil, fmt.Errorf("create TLS cert: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
		NextProtos: []string{quicProto},
	}, nil
}

// clientTLSConfig returns a TLS config for outgoing QUIC connections.
// InsecureSkipVerify is intentional: the receiver uses a self-signed cert, and
// we perform app-level authentication via Ed25519 capability tokens instead.
func clientTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // deliberate; app-level auth via Ed25519
		NextProtos:         []string{quicProto},
	}
}

// packet is the gob-encoded wire unit for the file transfer protocol.
type packet struct {
	Type        string // "start" | "resume" | "chunk" | "end"
	FileName    string // basename of the file being transferred
	Hash        string // BLAKE3 hex hash of the chunk data
	Data        []byte // raw chunk bytes
	Size        int64  // chunk length in bytes
	FileSize    int64  // total file size (sent in "start")
	FileMTime   int64  // file modification time nanoseconds (for resume matching)
	Index       int    // chunk sequence number (zero-based)
	ResumeIndex int    // last received chunk index sent back by receiver
}

// SendOptions controls parallelism and resume behaviour for outgoing transfers.
type SendOptions struct {
	Parallelism int  // number of goroutines that hash/persist chunks concurrently
	Resume      bool // perform the resume handshake on connect
	// AuthToken is sent before transfer; receiver must verify grantee.
	AuthToken *crypto.SignedToken
	// SpaceKey derives the per-transfer session key together with AuthToken.
	SpaceKey []byte
	// OnProgress is called after each chunk is written to the wire.
	// bytesSent is the cumulative raw (pre-encryption) bytes sent so far.
	// totalBytes is the full file size. May be nil.
	OnProgress func(bytesSent, totalBytes int64)
}

// ReceiveOptions controls resume behaviour and provides an optional ready hook.
type ReceiveOptions struct {
	Resume bool
	// RequireAuth rejects connections that do not present a valid capability token.
	RequireAuth bool
	// Identity is the local peer; used to verify AuthToken grantee.
	Identity *crypto.Identity
	// SpaceKey derives the session key after successful auth.
	SpaceKey []byte
	// OnListening is called once the QUIC listener is bound and accepting.
	// The argument is the actual listen address (e.g. "0.0.0.0:50234").
	// Useful in tests and callers that need to know the ephemeral port.
	OnListening func(addr string)
}

// resumeState is persisted as a JSON sidecar (filename + ".resume.json") so
// the receiver can tell the sender which chunks have already been written.
type resumeState struct {
	FileName  string `json:"file_name"`
	FileSize  int64  `json:"file_size"`
	FileMTime int64  `json:"file_mtime"`
	NextIndex int    `json:"next_index"`
}

// SendFile sends filePath to addr using default options (1 worker, resume on).
func (t *Transport) SendFile(ctx context.Context, addr, filePath string, engine *store.Engine) error {
	return t.SendFileWithOptions(ctx, addr, filePath, engine, SendOptions{Parallelism: 1, Resume: true})
}

// SendFileWithOptions dials addr over QUIC and streams filePath in CDC chunks.
//
// Protocol:
//  1. Client opens a stream and sends a "start" packet.
//  2. Server responds with a "resume" packet indicating the next chunk index.
//  3. Client streams "chunk" packets (parallel workers, in-order delivery).
//  4. Client sends "end" to signal completion.
func (t *Transport) SendFileWithOptions(ctx context.Context, addr, filePath string, engine *store.Engine, opts SendOptions) error {
	if opts.Parallelism < 1 {
		opts.Parallelism = 1
	}

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open source file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat source file: %w", err)
	}

	conn, err := quic.DialAddr(ctx, addr, clientTLSConfig(), nil)
	if err != nil {
		return fmt.Errorf("dial peer %s: %w", addr, err)
	}
	defer conn.CloseWithError(0, "done")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open QUIC stream: %w", err)
	}
	defer stream.Close()

	enc := gob.NewEncoder(stream)
	dec := gob.NewDecoder(stream)

	sessionKey, authErr := t.clientSessionKey(enc, dec, opts)
	if authErr != nil {
		return authErr
	}

	// --- Handshake: start → resume ---
	if err := enc.Encode(packet{
		Type:      "start",
		FileName:  filepath.Base(filePath),
		FileSize:  info.Size(),
		FileMTime: info.ModTime().UnixNano(),
	}); err != nil {
		return fmt.Errorf("send start packet: %w", err)
	}

	resumeIndex := 0
	if opts.Resume {
		var ack packet
		if err := dec.Decode(&ack); err != nil {
			return fmt.Errorf("read resume ack: %w", err)
		}
		if ack.Type != "resume" {
			return fmt.Errorf("unexpected handshake packet: %q", ack.Type)
		}
		if ack.ResumeIndex > 0 {
			resumeIndex = ack.ResumeIndex
		}
	}

	// --- Parallel chunk processing ---
	chunker := NewChunkStream(f)
	type job struct {
		index int
		chunk *chunk.Chunk
	}
	type result struct {
		index  int
		packet packet
		err    error
	}

	// stopped is closed when the sender exits (error or success) so worker
	// goroutines can detect abandonment and unblock from channel sends.
	stopped := make(chan struct{})
	jobs := make(chan job, opts.Parallelism*2)
	results := make(chan result, opts.Parallelism*2)

	var wg sync.WaitGroup
	for i := 0; i < opts.Parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if engine != nil {
					if _, err := engine.WriteChunk(filePath, j.chunk.Data); err != nil {
						select {
						case results <- result{err: fmt.Errorf("persist outgoing chunk: %w", err)}:
						case <-stopped:
						}
						return
					}
				}
				data := j.chunk.Data
				if len(sessionKey) > 0 {
					var encErr error
					data, encErr = ProtectChunk(sessionKey, data)
					if encErr != nil {
						select {
						case results <- result{err: fmt.Errorf("encrypt chunk: %w", encErr)}:
						case <-stopped:
						}
						return
					}
				}
				select {
				case results <- result{
					index: j.index,
					packet: packet{
						Type:  "chunk",
						Hash:  j.chunk.Hash,
						Data:  data,
						Size:  j.chunk.Size,
						Index: j.index,
					},
				}:
				case <-stopped:
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// sendErr signals workers to stop, drains remaining channel entries so no
	// goroutines are left blocked, then returns the provided error.
	var stopOnce sync.Once
	stopWorkers := func() {
		stopOnce.Do(func() { close(stopped) })
	}
	sendErr := func(err error) error {
		stopWorkers()
		// Drain results so the wg-closer goroutine can finish.
		for range results {
		}
		return err
	}

	idx := 0
	for {
		c, err := chunker.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			close(jobs)
			return sendErr(fmt.Errorf("chunk file: %w", err))
		}
		if idx < resumeIndex {
			idx++
			continue
		}
		select {
		case <-ctx.Done():
			close(jobs)
			return sendErr(ctx.Err())
		case jobs <- job{index: idx, chunk: c}:
		}
		idx++
	}
	close(jobs)

	// --- In-order delivery: buffer out-of-order results, send sequentially ---
	next := resumeIndex
	var bytesSent int64
	pendingPkts := make(map[int]packet)
	for r := range results {
		if r.err != nil {
			return sendErr(r.err)
		}
		pendingPkts[r.index] = r.packet
		for {
			p, ok := pendingPkts[next]
			if !ok {
				break
			}
			if err := enc.Encode(p); err != nil {
				return sendErr(fmt.Errorf("send chunk packet: %w", err))
			}
			bytesSent += p.Size
			if opts.OnProgress != nil {
				opts.OnProgress(bytesSent, info.Size())
			}
			delete(pendingPkts, next)
			next++
		}
	}
	stopWorkers() // normal completion: signal workers (all already done)

	if err := enc.Encode(packet{Type: "end"}); err != nil {
		return fmt.Errorf("send end packet: %w", err)
	}

	// Gracefully close the write side of the stream.
	if err := stream.Close(); err != nil {
		return fmt.Errorf("close stream: %w", err)
	}

	// Wait for the receiver to close its side of the stream to ensure it processed the 'end' packet.
	_, _ = io.ReadAll(stream)

	return nil
}

// ReceiveOnce listens for one incoming QUIC connection and receives one file.
func (t *Transport) ReceiveOnce(ctx context.Context, listenAddr, outputDir string, engine *store.Engine) error {
	return t.ReceiveOnceWithOptions(ctx, listenAddr, outputDir, engine, ReceiveOptions{Resume: true})
}

// ReceiveOnceWithOptions starts a QUIC listener, accepts exactly one connection,
// and receives one file transfer.
//
// Protocol (mirror of SendFileWithOptions):
//  1. Accept one QUIC connection.
//  2. Accept one bidirectional stream from that connection.
//  3. Receive "start" → send "resume" → receive "chunk"* → receive "end".
func (t *Transport) ReceiveOnceWithOptions(ctx context.Context, listenAddr, outputDir string, engine *store.Engine, opts ReceiveOptions) error {
	tlsConf, err := serverTLSConfig()
	if err != nil {
		return fmt.Errorf("create TLS config: %w", err)
	}

	listener, err := quic.ListenAddr(listenAddr, tlsConf, nil)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listenAddr, err)
	}

	// Notify caller of the actual bound address (useful when listenAddr is ":0").
	if opts.OnListening != nil {
		opts.OnListening(listener.Addr().String())
	}

	// Ensure the listener is closed if ctx is cancelled while waiting for Accept.
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	conn, err := listener.Accept(ctx)
	_ = listener.Close() // accept exactly one connection; ignore further dials
	if err != nil {
		return fmt.Errorf("accept QUIC connection: %w", err)
	}
	defer conn.CloseWithError(0, "done")

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept QUIC stream: %w", err)
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	dec := gob.NewDecoder(stream)
	enc := gob.NewEncoder(stream)

	_, sessionKey, pending, err := serverAuthHandshake(dec, enc, opts.Identity, opts.RequireAuth, opts.SpaceKey)
	if err != nil {
		return err
	}

	var outFile *os.File
	var resumePath string
	nextIndex := 0
	currentFileSize := int64(0)
	currentFileMTime := int64(0)

	persistState := func(state resumeState) error {
		b, err := json.Marshal(state)
		if err != nil {
			return err
		}
		return os.WriteFile(resumePath, b, 0o644)
	}

	loadState := func() (resumeState, error) {
		var s resumeState
		b, err := os.ReadFile(resumePath)
		if err != nil {
			return s, err
		}
		err = json.Unmarshal(b, &s)
		return s, err
	}

	processPacket := func(p packet) error {
		switch p.Type {

		case "start":
			safeName := filepath.Base(p.FileName)
			outPath := filepath.Join(outputDir, safeName)
			resumePath = outPath + ".resume.json"
			currentFileSize = p.FileSize
			currentFileMTime = p.FileMTime

			nextIndex = 0
			if opts.Resume {
				s, err := loadState()
				if err == nil && s.FileName == safeName && s.FileSize == p.FileSize && s.FileMTime == p.FileMTime {
					nextIndex = s.NextIndex
				}
			}

			flags := os.O_CREATE | os.O_WRONLY
			if nextIndex > 0 {
				flags |= os.O_APPEND
			} else {
				flags |= os.O_TRUNC
			}
			f, err := os.OpenFile(outPath, flags, 0o644)
			if err != nil {
				return fmt.Errorf("open output file: %w", err)
			}
			outFile = f

			if opts.Resume {
				if err := enc.Encode(packet{Type: "resume", ResumeIndex: nextIndex}); err != nil {
					return fmt.Errorf("send resume ack: %w", err)
				}
			}

		case "chunk":
			if outFile == nil {
				return fmt.Errorf("received chunk before start packet")
			}
			if p.Index < nextIndex {
				return nil
			}
			if p.Index > nextIndex {
				return fmt.Errorf("out-of-order chunk: got %d, expected %d", p.Index, nextIndex)
			}
			plain := p.Data
			if len(sessionKey) > 0 {
				var decErr error
				plain, decErr = UnprotectChunk(sessionKey, p.Data)
				if decErr != nil {
					return fmt.Errorf("decrypt chunk: %w", decErr)
				}
			}
			if chunk.HashChunk(plain) != p.Hash {
				return fmt.Errorf("chunk hash mismatch for %s", p.Hash)
			}
			if _, err := outFile.Write(plain); err != nil {
				return fmt.Errorf("write output file: %w", err)
			}
			if engine != nil {
				if _, err := engine.WriteChunk(outFile.Name(), plain); err != nil {
					return fmt.Errorf("persist incoming chunk: %w", err)
				}
			}
			nextIndex++
			if opts.Resume {
				if err := persistState(resumeState{
					FileName:  filepath.Base(outFile.Name()),
					FileSize:  currentFileSize,
					FileMTime: currentFileMTime,
					NextIndex: nextIndex,
				}); err != nil {
					return fmt.Errorf("persist resume state: %w", err)
				}
			}

		case "end":
			if outFile != nil {
				if err := outFile.Close(); err != nil {
					return fmt.Errorf("close output file: %w", err)
				}
				outFile = nil
			}
			if opts.Resume && resumePath != "" {
				_ = os.Remove(resumePath)
			}
			return errEndTransfer

		default:
			return fmt.Errorf("unknown packet type %q", p.Type)
		}
		return nil
	}

	if pending != nil {
		if err := processPacket(*pending); err != nil {
			if err == errEndTransfer {
				return nil
			}
			return err
		}
	}

	for {
		var p packet
		if err := dec.Decode(&p); err != nil {
			if err == io.EOF {
				break
			}
			if outFile != nil {
				_ = outFile.Close()
			}
			return fmt.Errorf("decode packet: %w", err)
		}

		if err := processPacket(p); err != nil {
			if err == errEndTransfer {
				return nil
			}
			return err
		}
	}

	if outFile != nil {
		if err := outFile.Close(); err != nil {
			return fmt.Errorf("close output file: %w", err)
		}
	}
	return nil
}

// NewChunkStream wraps r in a BufferedChunker for use by the transport.
func NewChunkStream(r io.Reader) *chunk.BufferedChunker {
	return chunk.NewBufferedChunker(r)
}

func (t *Transport) clientSessionKey(enc *gob.Encoder, dec *gob.Decoder, opts SendOptions) ([]byte, error) {
	if err := runClientAuth(enc, dec, opts.AuthToken); err != nil {
		return nil, err
	}
	if opts.AuthToken == nil || len(opts.SpaceKey) == 0 {
		return nil, nil
	}
	return DeriveTransferSessionKey(opts.SpaceKey, opts.AuthToken)
}

// SendFileOverConn streams filePath over an already-established QUIC connection.
// This is used by the hole-punch path: the puncher opens the connection, and
// this method runs the file-transfer protocol on top of it without dialling.
func (t *Transport) SendFileOverConn(ctx context.Context, conn *quic.Conn, filePath string, engine *store.Engine, opts SendOptions) error {
	if opts.Parallelism < 1 {
		opts.Parallelism = 1
	}

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open source file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat source file: %w", err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open QUIC stream over punched conn: %w", err)
	}
	defer stream.Close()

	enc := gob.NewEncoder(stream)
	dec := gob.NewDecoder(stream)

	sessionKey, authErr := t.clientSessionKey(enc, dec, opts)
	if authErr != nil {
		return authErr
	}

	if err := enc.Encode(packet{
		Type:      "start",
		FileName:  filepath.Base(filePath),
		FileSize:  info.Size(),
		FileMTime: info.ModTime().UnixNano(),
	}); err != nil {
		return fmt.Errorf("send start packet: %w", err)
	}

	resumeIndex := 0
	if opts.Resume {
		var ack packet
		if err := dec.Decode(&ack); err != nil {
			return fmt.Errorf("read resume ack: %w", err)
		}
		if ack.Type != "resume" {
			return fmt.Errorf("unexpected handshake packet: %q", ack.Type)
		}
		if ack.ResumeIndex > 0 {
			resumeIndex = ack.ResumeIndex
		}
	}

	// Reuse the same parallel-chunk machinery as SendFileWithOptions.
	chunker := NewChunkStream(f)
	type job struct {
		index int
		chunk *chunk.Chunk
	}
	type result struct {
		index  int
		packet packet
		err    error
	}

	stopped := make(chan struct{})
	jobs := make(chan job, opts.Parallelism*2)
	results := make(chan result, opts.Parallelism*2)

	var wg sync.WaitGroup
	for i := 0; i < opts.Parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if engine != nil {
					if _, err := engine.WriteChunk(filePath, j.chunk.Data); err != nil {
						select {
						case results <- result{err: fmt.Errorf("persist outgoing chunk: %w", err)}:
						case <-stopped:
						}
						return
					}
				}
				data := j.chunk.Data
				if len(sessionKey) > 0 {
					var encErr error
					data, encErr = ProtectChunk(sessionKey, data)
					if encErr != nil {
						select {
						case results <- result{err: fmt.Errorf("encrypt chunk: %w", encErr)}:
						case <-stopped:
						}
						return
					}
				}
				select {
				case results <- result{
					index: j.index,
					packet: packet{
						Type:  "chunk",
						Hash:  j.chunk.Hash,
						Data:  data,
						Size:  j.chunk.Size,
						Index: j.index,
					},
				}:
				case <-stopped:
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var stopOnce sync.Once
	stopWorkers := func() { stopOnce.Do(func() { close(stopped) }) }
	sendErr := func(err error) error {
		stopWorkers()
		for range results {
		}
		return err
	}

	idx := 0
	for {
		c, err := chunker.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			close(jobs)
			return sendErr(fmt.Errorf("chunk file: %w", err))
		}
		if idx < resumeIndex {
			idx++
			continue
		}
		select {
		case <-ctx.Done():
			close(jobs)
			return sendErr(ctx.Err())
		case jobs <- job{index: idx, chunk: c}:
		}
		idx++
	}
	close(jobs)

	next := resumeIndex
	pendingPkts := make(map[int]packet)
	for r := range results {
		if r.err != nil {
			return sendErr(r.err)
		}
		pendingPkts[r.index] = r.packet
		for {
			p, ok := pendingPkts[next]
			if !ok {
				break
			}
			if err := enc.Encode(p); err != nil {
				return sendErr(fmt.Errorf("send chunk packet: %w", err))
			}
			delete(pendingPkts, next)
			next++
		}
	}
	stopWorkers()

	if err := enc.Encode(packet{Type: "end"}); err != nil {
		return fmt.Errorf("send end packet: %w", err)
	}
	if err := stream.Close(); err != nil {
		return fmt.Errorf("close stream: %w", err)
	}
	_, _ = io.ReadAll(stream)
	return nil
}
