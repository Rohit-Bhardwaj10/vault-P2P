package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"vault-backend/internal/crypto"
	"vault-backend/internal/network"
	"vault-backend/internal/node"
	"vault-backend/internal/relay"
	"vault-backend/internal/store"
	"vault-backend/internal/sync"

	"github.com/spf13/cobra"
)

var (
	dbPath            string
	walPath           string
	chunkPath         string
	sendParallelism   int
	sendResume        bool
	receiveResume     bool
	receiveAuth       bool
	relayAddr         string
	identityPath      string
	spaceID           string
	recipientPubkey   string
	recipientID       string
	peerID            string
	apiPort           int
	mdnsPort          int
	outputDir         string
	rendezvousServer  string // rendezvous server base URL
	pingAddr          string // address to ping for vault peers ping
)

var rootCmd = &cobra.Command{
	Use:   "vault",
	Short: "Vault P2P Node",
	Long:  "Vault P2P is a private encrypted peer-to-peer file sharing node.",
}

// ---------------------------------------------------------------------------
// vault run
// ---------------------------------------------------------------------------

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start the Vault node (WAL worker, mDNS, relay poll, API)",
	Run: func(cmd *cobra.Command, args []string) {
		if peerID == "" {
			fmt.Fprintf(os.Stderr, "Error: --peer-id is required for vault run\n")
			os.Exit(1)
		}
		if outputDir == "" {
			outputDir = filepath.Join("data", "inbox")
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		n := node.New(node.Config{
			DBPath:       dbPath,
			WALPath:      walPath,
			ChunkPath:    chunkPath,
			IdentityPath: identityPath,
			OutputDir:    outputDir,
			PeerID:       peerID,
			APIPort:      apiPort,
			MDNSPort:     mdnsPort,
			RelayAddr:    relayAddr,
			SpaceID:      spaceID,
		})

		fmt.Printf("Starting Vault node (peer=%s, api=:%d)...\n", peerID, apiPort)
		if err := n.Run(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "Node error: %v\n", err)
			os.Exit(1)
		}
	},
}

// ---------------------------------------------------------------------------
// vault send
// ---------------------------------------------------------------------------

var sendCmd = &cobra.Command{
	Use:   "send [file] [peer_addr]",
	Short: "Send a file to a peer (WAL-first, encrypted when --space is set)",
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
		relay := optionalRelayClient()

		payload, authToken, spaceKey, err := buildSendPayload(engine, filePath, peerAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to prepare send: %v\n", err)
			os.Exit(1)
		}
		payloadBytes, _ := json.Marshal(payload)

		entry, err := engine.EnqueueWAL(peerAddr, "send_file", payloadBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to enqueue WAL: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Sending file '%s' to '%s' (WAL entry %s)...\n", filePath, peerAddr, entry.ID)

		recipient := recipientID
		if recipient == "" {
			recipient = peerAddr
		}

		d := &network.Deliverer{
			Transport:   network.NewTransport(),
			Relay:       relay,
			AuthToken:   authToken,
			SpaceKey:    spaceKey,
			PeerAddr:    peerAddr,
			RecipientID: recipient,
		}

		if err := d.SendFile(context.Background(), filePath, engine, network.DeliverOptions{
			Parallelism: sendParallelism,
			Resume:      sendResume,
			OnProgress: func(sent, total int64) {
				progressBar("Sending", sent, total)
			},
		}); err != nil {
			fmt.Println() // newline after progress bar
			fmt.Fprintf(os.Stderr, "Delivery failed (will retry when peer is online): %v\n", err)
			return
		}
		progressDone("Sending", fileSize(filePath))

		_ = engine.MarkWALDone(entry.ID)
		_ = engine.DeleteWALEntry(entry.ID)
		fmt.Println("Transfer completed")
	},
}

// ---------------------------------------------------------------------------
// vault receive
// ---------------------------------------------------------------------------

var receiveCmd = &cobra.Command{
	Use:   "receive [listen_addr] [output_dir]",
	Short: "Receive one encrypted file from a peer",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		engine, err := initEngine()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to initialize storage: %v\n", err)
			os.Exit(1)
		}
		defer engine.Close()

		identity, err := loadOrGenerateIdentity(identityPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load identity: %v\n", err)
			os.Exit(1)
		}

		var spaceKey []byte
		if spaceID != "" {
			space, _, err := engine.GetSpace(spaceID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to load space: %v\n", err)
				os.Exit(1)
			}
			spaceKey = space.SymmetricKey
		}

		fmt.Printf("Waiting for incoming transfer on '%s'...\n", args[0])
		transport := network.NewTransport()
		if err := transport.ReceiveOnceWithOptions(context.Background(), args[0], args[1], engine, network.ReceiveOptions{
			Resume:      receiveResume,
			RequireAuth: receiveAuth || spaceID != "",
			Identity:    identity,
			SpaceKey:    spaceKey,
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
		engine, err := initEngine()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to initialize storage: %v\n", err)
			os.Exit(1)
		}
		defer engine.Close()

		identity, err := loadOrGenerateIdentity(identityPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load identity: %v\n", err)
			os.Exit(1)
		}

		space, err := crypto.NewSpace(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create space: %v\n", err)
			os.Exit(1)
		}
		if err := engine.SaveSpace(space, hex.EncodeToString(identity.PublicKey)); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to persist space: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("✓ Space created\n")
		fmt.Printf("  ID:   %s\n", space.ID)
		fmt.Printf("  Name: %s\n", space.Name)
		fmt.Printf("\nTo invite a peer: vault share invite %s <peer-pubkey>\n", space.ID)
		fmt.Printf("To send files:     vault send <file> <peer> --space %s --recipient-pubkey <hex>\n", space.ID)
	},
}

var shareInviteCmd = &cobra.Command{
	Use:   "invite [space-id] [grantee-pubkey-hex]",
	Short: "Create a signed invite token for a peer",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		engine, err := initEngine()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to initialize storage: %v\n", err)
			os.Exit(1)
		}
		defer engine.Close()

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

		space, _, err := engine.GetSpace(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Space not found: %v\n", err)
			os.Exit(1)
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
		rdb := filepath.Join("data", "relay.db")
		srv := relay.NewServer(args[0], rdb, 24*time.Hour)
		fmt.Printf("Starting relay server on %s (db: %s)...\n", args[0], rdb)
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
	Use:   "retry [peer-id]",
	Short: "Trigger an immediate retry for all pending entries for a peer",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		engine, err := initEngine()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to initialize storage: %v\n", err)
			os.Exit(1)
		}
		defer engine.Close()

		peer := args[0]
		coord := sync.NewCoordinator(engine, makeDeliverFn(engine, optionalRelayClient()))
		coord.MarkOnline(context.Background(), peer)

		fmt.Printf("Draining WAL queue for peer %s...\n", peer)
		if err := coord.DrainPeer(context.Background(), peer); err != nil {
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
	rootCmd.PersistentFlags().StringVar(&spaceID, "space", "", "Space ID for encrypted transfers")
	rootCmd.PersistentFlags().StringVar(&recipientPubkey, "recipient-pubkey", "", "Recipient Ed25519 public key (hex)")
	rootCmd.PersistentFlags().StringVar(&recipientID, "recipient-id", "", "Recipient peer ID for relay delivery")

	sendCmd.Flags().IntVar(&sendParallelism, "parallel", 1, "Number of workers used to process outgoing chunks")
	sendCmd.Flags().BoolVar(&sendResume, "resume", true, "Enable resume handshake when sending")
	receiveCmd.Flags().BoolVar(&receiveResume, "resume", true, "Enable resume tracking when receiving")
	receiveCmd.Flags().BoolVar(&receiveAuth, "require-auth", false, "Require capability token on incoming connections")

	runCmd.Flags().StringVar(&peerID, "peer-id", "", "This node's peer ID (required)")
	runCmd.Flags().IntVar(&apiPort, "api-port", 8080, "HTTP API port")
	runCmd.Flags().IntVar(&mdnsPort, "mdns-port", 4242, "mDNS service port")
	runCmd.Flags().StringVar(&outputDir, "output-dir", filepath.Join("data", "inbox"), "Directory for relay-received files")

	shareCmd.AddCommand(shareCreateCmd, shareInviteCmd)
	relayCmd.AddCommand(relayServeCmd, relayStatusCmd)
	queueCmd.AddCommand(queueListCmd, queueRetryCmd)
	peersCmd.AddCommand(peersListCmd, peersPingCmd)
	rendezvousCmd.AddCommand(rendezvousRegisterCmd, rendezvoousLookupCmd)

	rootCmd.AddCommand(runCmd, sendCmd, receiveCmd, shareCmd, relayCmd, queueCmd, statusCmd, peersCmd, rendezvousCmd)
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

func optionalRelayClient() *relay.Client {
	if relayAddr == "" {
		return nil
	}
	return relay.NewClient(relayAddr)
}

func buildSendPayload(engine *store.Engine, filePath, peerAddr string) (map[string]string, *crypto.SignedToken, []byte, error) {
	payload := map[string]string{
		"file_path": filePath,
		"peer_addr": peerAddr,
	}
	if recipientID != "" {
		payload["recipient_id"] = recipientID
	}

	if spaceID == "" {
		return payload, nil, nil, nil
	}

	identity, err := loadOrGenerateIdentity(identityPath)
	if err != nil {
		return nil, nil, nil, err
	}
	space, _, err := engine.GetSpace(spaceID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load space: %w", err)
	}

	grantee := identity.PublicKey
	if recipientPubkey != "" {
		grantee, err = crypto.DecodePublicKey(recipientPubkey)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("recipient pubkey: %w", err)
		}
	}

	token, err := crypto.IssueToken(identity, grantee, space.ID, crypto.PermWrite, 24*time.Hour)
	if err != nil {
		return nil, nil, nil, err
	}
	tokJSON, err := crypto.MarshalToken(token)
	if err != nil {
		return nil, nil, nil, err
	}
	payload["auth_token"] = string(tokJSON)
	payload["space_id"] = space.ID

	return payload, token, space.SymmetricKey, nil
}

func makeDeliverFn(engine *store.Engine, relayClient *relay.Client) sync.DeliveryFunc {
	return func(ctx context.Context, peerID string, entry *store.WALEntry) error {
		var payload map[string]string
		if err := json.Unmarshal(entry.Payload, &payload); err != nil {
			return fmt.Errorf("bad payload: %w", err)
		}

		authToken, spaceKey, err := authFromPayload(engine, payload)
		if err != nil {
			return err
		}

		peerAddr := payload["peer_addr"]
		if peerAddr == "" {
			peerAddr = peerID
		}
		recipient := payload["recipient_id"]
		if recipient == "" {
			recipient = peerAddr
		}

		d := &network.Deliverer{
			Transport:   network.NewTransport(),
			Relay:       relayClient,
			AuthToken:   authToken,
			SpaceKey:    spaceKey,
			PeerAddr:    peerAddr,
			RecipientID: recipient,
		}
		return d.SendFile(ctx, payload["file_path"], engine, network.DeliverOptions{
			Parallelism: 1,
			Resume:      true,
		})
	}
}

func authFromPayload(engine *store.Engine, payload map[string]string) (*crypto.SignedToken, []byte, error) {
	if tokJSON := payload["auth_token"]; tokJSON != "" {
		tok, err := crypto.UnmarshalToken([]byte(tokJSON))
		if err != nil {
			return nil, nil, err
		}
		sid := payload["space_id"]
		if sid == "" {
			var ct crypto.CapabilityToken
			_ = json.Unmarshal(tok.Payload, &ct)
			sid = ct.SpaceID
		}
		space, _, err := engine.GetSpace(sid)
		if err != nil {
			return tok, nil, err
		}
		return tok, space.SymmetricKey, nil
	}
	return nil, nil, nil
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
