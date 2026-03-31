package network

import (
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

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
	Type     string
	FileName string
	Hash     string
	Data     []byte
	Size     int64
}

func (t *Transport) SendFile(ctx context.Context, addr, filePath string, engine *store.Engine) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open source file: %w", err)
	}
	defer f.Close()

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial peer %s: %w", addr, err)
	}
	defer conn.Close()

	enc := gob.NewEncoder(conn)
	if err := enc.Encode(packet{Type: "start", FileName: filepath.Base(filePath)}); err != nil {
		return fmt.Errorf("send start packet: %w", err)
	}

	chunker := NewChunkStream(f)
	for {
		c, err := chunker.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("chunk file: %w", err)
		}

		if engine != nil {
			if _, err := engine.WriteChunk(filePath, c.Data); err != nil {
				return fmt.Errorf("persist outgoing chunk: %w", err)
			}
		}

		if err := enc.Encode(packet{Type: "chunk", Hash: c.Hash, Data: c.Data, Size: c.Size}); err != nil {
			return fmt.Errorf("send chunk packet: %w", err)
		}
	}

	if err := enc.Encode(packet{Type: "end"}); err != nil {
		return fmt.Errorf("send end packet: %w", err)
	}

	return nil
}

func (t *Transport) ReceiveOnce(ctx context.Context, listenAddr, outputDir string, engine *store.Engine) error {
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
	var outFile *os.File

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
			f, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("create output file: %w", err)
			}
			outFile = f

		case "chunk":
			if outFile == nil {
				return fmt.Errorf("received chunk before start packet")
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

		case "end":
			if outFile != nil {
				if err := outFile.Close(); err != nil {
					return fmt.Errorf("close output file: %w", err)
				}
				outFile = nil
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
