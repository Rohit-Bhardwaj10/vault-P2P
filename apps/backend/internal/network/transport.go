package network

import (
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"

	"vault-backend/internal/chunk"
	"vault-backend/internal/store"
)

type Transport struct {
	// Phase 1 uses direct TCP transfer; QUIC migration comes in Phase 3.
}

func NewTransport() *Transport {
	return &Transport{}
}

type packet struct {
	Type        string
	FileName    string
	Hash        string
	Data        []byte
	Size        int64
	FileSize    int64
	FileMTime   int64
	Index       int
	ResumeIndex int
}

type SendOptions struct {
	Parallelism int
	Resume      bool
}

type ReceiveOptions struct {
	Resume bool
}

type resumeState struct {
	FileName  string `json:"file_name"`
	FileSize  int64  `json:"file_size"`
	FileMTime int64  `json:"file_mtime"`
	NextIndex int    `json:"next_index"`
}

func (t *Transport) SendFile(ctx context.Context, addr, filePath string, engine *store.Engine) error {
	return t.SendFileWithOptions(ctx, addr, filePath, engine, SendOptions{Parallelism: 1, Resume: true})
}

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

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial peer %s: %w", addr, err)
	}
	defer conn.Close()

	enc := gob.NewEncoder(conn)
	dec := gob.NewDecoder(conn)
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
						results <- result{err: fmt.Errorf("persist outgoing chunk: %w", err)}
						return
					}
				}
				results <- result{
					index: j.index,
					packet: packet{
						Type:  "chunk",
						Hash:  j.chunk.Hash,
						Data:  j.chunk.Data,
						Size:  j.chunk.Size,
						Index: j.index,
					},
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	idx := 0
	for {
		c, err := chunker.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			close(jobs)
			return fmt.Errorf("chunk file: %w", err)
		}
		if idx < resumeIndex {
			idx++
			continue
		}

		select {
		case <-ctx.Done():
			close(jobs)
			return ctx.Err()
		case jobs <- job{index: idx, chunk: c}:
		}
		idx++
	}
	close(jobs)

	next := resumeIndex
	pending := make(map[int]packet)
	for r := range results {
		if r.err != nil {
			return r.err
		}
		pending[r.index] = r.packet
		for {
			p, ok := pending[next]
			if !ok {
				break
			}
			if err := enc.Encode(p); err != nil {
				return fmt.Errorf("send chunk packet: %w", err)
			}
			delete(pending, next)
			next++
		}
	}

	if err := enc.Encode(packet{Type: "end"}); err != nil {
		return fmt.Errorf("send end packet: %w", err)
	}

	return nil
}

func (t *Transport) ReceiveOnce(ctx context.Context, listenAddr, outputDir string, engine *store.Engine) error {
	return t.ReceiveOnceWithOptions(ctx, listenAddr, outputDir, engine, ReceiveOptions{Resume: true})
}

func (t *Transport) ReceiveOnceWithOptions(ctx context.Context, listenAddr, outputDir string, engine *store.Engine, opts ReceiveOptions) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listenAddr, err)
	}
	defer listener.Close()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		acceptCh <- acceptResult{conn: conn, err: err}
	}()

	var conn net.Conn
	select {
	case <-ctx.Done():
		return ctx.Err()
	case result := <-acceptCh:
		if result.err != nil {
			return fmt.Errorf("accept connection: %w", result.err)
		}
		conn = result.conn
	}
	defer conn.Close()

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	dec := gob.NewDecoder(conn)
	enc := gob.NewEncoder(conn)
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
				continue
			}
			if p.Index > nextIndex {
				return fmt.Errorf("received out-of-order chunk: got %d expected %d", p.Index, nextIndex)
			}
			if chunk.HashChunk(p.Data) != p.Hash {
				return fmt.Errorf("chunk hash mismatch for %s", p.Hash)
			}
			if _, err := outFile.Write(p.Data); err != nil {
				return fmt.Errorf("write output file: %w", err)
			}
			if engine != nil {
				if _, err := engine.WriteChunk(outFile.Name(), p.Data); err != nil {
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
			return nil

		default:
			return fmt.Errorf("unknown packet type %q", p.Type)
		}
	}

	if outFile != nil {
		if err := outFile.Close(); err != nil {
			return fmt.Errorf("close output file: %w", err)
		}
	}

	return nil
}

func NewChunkStream(r io.Reader) *chunk.BufferedChunker {
	return chunk.NewBufferedChunker(r)
}
