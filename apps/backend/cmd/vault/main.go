package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"vault-backend/internal/crypto"
	"vault-backend/internal/network"
	"vault-backend/internal/relay"
	"vault-backend/internal/store"
	"vault-backend/internal/sync"

	"github.com/spf13/cobra"
)

var (
	dbPath          string
	walPath         string
	chunkPath       string
	sendParallelism int
	sendResume      bool
	receiveResume   bool
	relayAddr       string
	identityPath    string
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

// ---------------------------------------------------------------------------
// vault send
// ---------------------------------------------------------------------------

var sendCmd = &cobra.Command{
	Use:   "send [file] [peer_id]",
	Short: "Send a file directly to a peer (queues in WAL if peer offline)",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		engine, err := initEngine()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to initialize storage: %v\n", err)
			os.Exit(1)
		}
		defer engine.Close()

		filePath := args[0]
		peerAddr := args[1]

		fmt.Printf("Sending file '%s' to peer '%s'...\n", filePath, peerAddr)
		transport := network.NewTransport()
		err = transport.SendFileWithOptions(context.Background(), peerAddr, filePath, engine, network.SendOptions{
			Parallelism: sendParallelism,
			Resume:      sendResume,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Direct transfer failed: %v\n", err)
			fmt.Println("Queuing in WAL for retry when peer comes online...")

			payload, _ := json.Marshal(map[string]string{
				"file_path": filePath,
				"peer_addr": peerAddr,
			})
			entry, qErr := engine.EnqueueWAL(peerAddr, "send_file", payload)
			if qErr != nil {
				fmt.Fprintf(os.Stderr, "Failed to queue in WAL: %v\n", qErr)
				os.Exit(1)
			}
			fmt.Printf("Queued as WAL entry %s — will retry when peer is online.\n", entry.ID)
			return
		}
		fmt.Println("Transfer completed")
	},
}

// ---------------------------------------------------------------------------
// vault receive
// ---------------------------------------------------------------------------

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
		if err := transport.ReceiveOnceWithOptions(context.Background(), args[0], args[1], engine, network.ReceiveOptions{
			Resume: receiveResume,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "Receive failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("File received in '%s'\n", args[1])
	},
}

// ---------------------------------------------------------------------------
// vault share
// ---------------------------------------------------------------------------

var shareCmd = &cobra.Command{
	Use:   "share",
	Short: "Manage shared spaces and invite tokens",
}

var shareCreateCmd = &cobra.Command{
	Use:   "create [space-name]",
	Short: "Create a new shared space",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		space, err := crypto.NewSpace(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create space: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Space created\n")
		fmt.Printf("  ID:   %s\n", space.ID)
		fmt.Printf("  Name: %s\n", space.Name)
		fmt.Printf("  Key:  (stored locally — never transmitted in plaintext)\n")
		fmt.Printf("\nTo invite a peer: vault share invite %s <peer-pubkey>\n", space.ID)
	},
}

var shareInviteCmd = &cobra.Command{
	Use:   "invite [space-id] [grantee-pubkey-hex]",
	Short: "Create a signed invite token for a peer",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		issuer, err := loadOrGenerateIdentity(identityPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load identity: %v\n", err)
			os.Exit(1)
		}

		granteeKey, err := crypto.DecodePublicKey(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid grantee pubkey: %v\n", err)
			os.Exit(1)
		}

		// Placeholder space — in production, loaded from the store.
		space := &crypto.Space{
			ID:           args[0],
			Name:         "space",
			SymmetricKey: make([]byte, 32),
		}

		invite, err := crypto.CreateInvite(issuer, space, crypto.PermWrite, 24*time.Hour)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create invite: %v\n", err)
			os.Exit(1)
		}
		_ = granteeKey

		tokenBytes, err := crypto.MarshalInvite(invite)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to marshal invite: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Invite token (share this with the peer):\n%s\n", string(tokenBytes))
	},
}

// ---------------------------------------------------------------------------
// vault relay
// ---------------------------------------------------------------------------

var relayCmd = &cobra.Command{
	Use:   "relay",
	Short: "Run or interact with the relay server",
}

var relayServeCmd = &cobra.Command{
	Use:   "serve [listen-addr]",
	Short: "Start the relay server (e.g. vault relay serve :9090)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		dbPath := filepath.Join("data", "relay.db")
		srv := relay.NewServer(args[0], dbPath, 24*time.Hour)
		fmt.Printf("Starting relay server on %s (db: %s)...\n", args[0], dbPath)
		if err := srv.Run(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "Relay server error: %v\n", err)
			os.Exit(1)
		}
	},
}

var relayStatusCmd = &cobra.Command{
	Use:   "ping [relay-addr]",
	Short: "Ping a relay server to check connectivity",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		client := relay.NewClient(args[0])
		if err := client.Ping(); err != nil {
			fmt.Fprintf(os.Stderr, "Relay unreachable: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Relay at %s is reachable\n", args[0])
	},
}

// ---------------------------------------------------------------------------
// vault queue
// ---------------------------------------------------------------------------

var queueCmd = &cobra.Command{
	Use:   "queue",
	Short: "Inspect and manage the WAL offline send queue",
}

var queueListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all pending WAL entries",
	Run: func(cmd *cobra.Command, args []string) {
		engine, err := initEngine()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to initialize storage: %v\n", err)
			os.Exit(1)
		}
		defer engine.Close()

		entries, err := engine.GetAllPendingWAL()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to list queue: %v\n", err)
			os.Exit(1)
		}
		if len(entries) == 0 {
			fmt.Println("Queue is empty.")
			return
		}
		fmt.Printf("%-12s %-20s %-12s %-8s %s\n", "ID", "Peer", "Op", "Retries", "Created")
		for _, e := range entries {
			fmt.Printf("%-12s %-20s %-12s %-8d %s\n",
				e.ID, e.PeerID, e.Op, e.Retries,
				formatUnix(e.CreatedAt))
		}
	},
}

var queueRetryCmd = &cobra.Command{
	Use:   "retry [peer-addr]",
	Short: "Trigger an immediate retry for all pending entries for a peer",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		engine, err := initEngine()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to initialize storage: %v\n", err)
			os.Exit(1)
		}
		defer engine.Close()

		peerID := args[0]
		transport := network.NewTransport()

		deliverFn := func(ctx context.Context, pid string, entry *store.WALEntry) error {
			var payload map[string]string
			if err := json.Unmarshal(entry.Payload, &payload); err != nil {
				return fmt.Errorf("bad payload: %w", err)
			}
			filePath := payload["file_path"]
			peerAddr := payload["peer_addr"]
			return transport.SendFileWithOptions(ctx, peerAddr, filePath, engine, network.SendOptions{
				Parallelism: 1,
				Resume:      true,
			})
		}

		coord := sync.NewCoordinator(engine, deliverFn)
		coord.MarkOnline(context.Background(), peerID)

		fmt.Printf("Draining WAL queue for peer %s...\n", peerID)
		if err := coord.DrainPeer(context.Background(), peerID); err != nil {
			fmt.Fprintf(os.Stderr, "Drain failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Done.")
	},
}

// ---------------------------------------------------------------------------
// init + helpers
// ---------------------------------------------------------------------------

func init() {
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", filepath.Join("data", "vault.db"), "SQLite metadata database path")
	rootCmd.PersistentFlags().StringVar(&walPath, "wal", filepath.Join("data", "wal.db"), "BoltDB WAL path")
	rootCmd.PersistentFlags().StringVar(&chunkPath, "chunks", filepath.Join("data", "chunks"), "Chunk storage directory")
	rootCmd.PersistentFlags().StringVar(&relayAddr, "relay", "", "Relay server address (optional fallback)")
	rootCmd.PersistentFlags().StringVar(&identityPath, "identity", filepath.Join("data", "identity.key"), "Node identity private key path")

	sendCmd.Flags().IntVar(&sendParallelism, "parallel", 1, "Number of workers used to process outgoing chunks")
	sendCmd.Flags().BoolVar(&sendResume, "resume", true, "Enable resume handshake when sending")
	receiveCmd.Flags().BoolVar(&receiveResume, "resume", true, "Enable resume tracking when receiving")

	shareCmd.AddCommand(shareCreateCmd, shareInviteCmd)
	relayCmd.AddCommand(relayServeCmd, relayStatusCmd)
	queueCmd.AddCommand(queueListCmd, queueRetryCmd)

	rootCmd.AddCommand(sendCmd, receiveCmd, shareCmd, relayCmd, queueCmd)
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

func loadOrGenerateIdentity(path string) (*crypto.Identity, error) {
	if _, err := os.Stat(path); err == nil {
		return crypto.LoadIdentity(path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	id, err := crypto.GenerateIdentity()
	if err != nil {
		return nil, err
	}
	if err := crypto.SaveIdentity(path, id); err != nil {
		return nil, err
	}
	return id, nil
}

func formatUnix(ts int64) string {
	return time.Unix(ts, 0).Format("2006-01-02 15:04:05")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
