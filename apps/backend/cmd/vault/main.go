package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"vault-backend/internal/network"
	"vault-backend/internal/store"

	"github.com/spf13/cobra"
)

var (
	dbPath    string
	walPath   string
	chunkPath string
)

var rootCmd = &cobra.Command{
	Use:   "vault",
	Short: "Vault P2P Node",
	Long:  "Vault P2P is a private encrypted peer-to-peer file sharing node.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Starting Vault P2P node...")
		// Initialization of Network, Storage, and API will happen here.
	},
}

var sendCmd = &cobra.Command{
	Use:   "send [file] [peer_id]",
	Short: "Send a file directly to a peer",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		engine, err := initEngine()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to initialize storage: %v\n", err)
			os.Exit(1)
		}
		defer engine.Close()

		fmt.Printf("Sending file '%s' to peer '%s'...\n", args[0], args[1])
		transport := network.NewTransport()
		if err := transport.SendFile(context.Background(), args[1], args[0], engine); err != nil {
			fmt.Fprintf(os.Stderr, "Transfer failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Transfer completed")
	},
}

var receiveCmd = &cobra.Command{
	Use:   "receive [listen_addr] [output_dir]",
	Short: "Receive one file from a peer",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		engine, err := initEngine()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to initialize storage: %v\n", err)
			os.Exit(1)
		}
		defer engine.Close()

		fmt.Printf("Waiting for incoming transfer on '%s'...\n", args[0])
		transport := network.NewTransport()
		if err := transport.ReceiveOnce(context.Background(), args[0], args[1], engine); err != nil {
			fmt.Fprintf(os.Stderr, "Receive failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("File received in '%s'\n", args[1])
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", filepath.Join("data", "vault.db"), "SQLite metadata database path")
	rootCmd.PersistentFlags().StringVar(&walPath, "wal", filepath.Join("data", "wal.db"), "BoltDB WAL path")
	rootCmd.PersistentFlags().StringVar(&chunkPath, "chunks", filepath.Join("data", "chunks"), "Chunk storage directory")
	rootCmd.AddCommand(sendCmd, receiveCmd)
}

func initEngine() (*store.Engine, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(walPath), 0o755); err != nil {
		return nil, err
	}
	engine := store.NewEngineWithChunkDir(dbPath, walPath, chunkPath)
	if err := engine.Init(); err != nil {
		return nil, err
	}
	return engine, nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
