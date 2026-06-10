package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"

	"vault-backend/internal/rendezvous"

	"github.com/spf13/cobra"
)

// ---------------------------------------------------------------------------
// vault status
// ---------------------------------------------------------------------------

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show node status: identity, WAL queue, relay, peers",
	Run: func(cmd *cobra.Command, args []string) {
		engine, err := initEngine()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Storage error: %v\n", err)
			os.Exit(1)
		}
		defer engine.Close()

		identity, err := loadOrGenerateIdentity(identityPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Identity error: %v\n", err)
			os.Exit(1)
		}

		pending, err := engine.GetAllPendingWAL()
		if err != nil {
			fmt.Fprintf(os.Stderr, "WAL error: %v\n", err)
			os.Exit(1)
		}

		pubkeyHex := hex.EncodeToString(identity.PublicKey)
		short := pubkeyHex
		if len(short) > 16 {
			short = short[:16] + "…"
		}

		fmt.Println("╔══════════════════════════════════════╗")
		fmt.Println("║         Vault P2P Node Status        ║")
		fmt.Println("╠══════════════════════════════════════╣")
		fmt.Printf("║  Identity   %-25s║\n", short)
		fmt.Printf("║  WAL Queue  %-25s║\n", fmt.Sprintf("%d pending entries", len(pending)))

		// Relay reachability
		relayStatus := "not configured"
		if relayAddr != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, dialErr := new(net.Dialer).DialContext(ctx, "tcp", relayAddr)
			if dialErr == nil {
				conn.Close()
				relayStatus = "✓ reachable (" + relayAddr + ")"
			} else {
				relayStatus = "✗ unreachable (" + relayAddr + ")"
			}
		}
		// Truncate to fit box
		if len(relayStatus) > 25 {
			relayStatus = relayStatus[:24] + "…"
		}
		fmt.Printf("║  Relay      %-25s║\n", relayStatus)
		fmt.Printf("║  DB         %-25s║\n", truncate(dbPath, 25))
		fmt.Println("╚══════════════════════════════════════╝")

		if len(pending) > 0 {
			fmt.Printf("\n  Pending WAL entries:\n")
			fmt.Printf("  %-12s %-20s %-10s %s\n", "ID", "Peer", "Retries", "Created")
			for _, e := range pending {
				fmt.Printf("  %-12s %-20s %-10d %s\n",
					e.ID, truncate(e.PeerID, 20), e.Retries,
					time.Unix(e.CreatedAt, 0).Format("15:04:05"))
			}
		}
	},
}

// ---------------------------------------------------------------------------
// vault peers
// ---------------------------------------------------------------------------

var peersCmd = &cobra.Command{
	Use:   "peers",
	Short: "Inspect known peers",
}

var peersListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all peers this node has interacted with",
	Run: func(cmd *cobra.Command, args []string) {
		engine, err := initEngine()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Storage error: %v\n", err)
			os.Exit(1)
		}
		defer engine.Close()

		// Collect unique peer IDs from the WAL (all peers we've ever queued for).
		entries, err := engine.GetAllPendingWAL()
		if err != nil {
			fmt.Fprintf(os.Stderr, "WAL error: %v\n", err)
			os.Exit(1)
		}
		seen := map[string]bool{}
		for _, e := range entries {
			seen[e.PeerID] = true
		}

		if len(seen) == 0 {
			fmt.Println("No known peers. Send a file to register a peer.")
			return
		}

		fmt.Printf("%-36s %-30s %-12s\n", "Peer ID / Address", "Stored Address", "Latency")
		fmt.Println("─────────────────────────────────────────────────────────────────────────")
		for id := range seen {
			_, addrs, latency, lookErr := engine.GetPeer(id)
			if lookErr != nil {
				addrs = "(not stored)"
				latency = -1
			}
			lat := fmt.Sprintf("%d ms", latency)
			if latency < 0 {
				lat = "—"
			}
			fmt.Printf("%-36s %-30s %-12s\n", truncate(id, 36), truncate(addrs, 30), lat)
		}
	},
}

var peersPingCmd = &cobra.Command{
	Use:   "ping <addr>",
	Short: "Check if a peer address is reachable (TCP probe)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		addr := args[0]
		fmt.Printf("Pinging %s ...", addr)

		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := new(net.Dialer).DialContext(ctx, "udp", addr)
		if err != nil {
			// UDP "connect" always succeeds (it just sets the default dest), so
			// try TCP for a real reachability check.
			conn, err = new(net.Dialer).DialContext(ctx, "tcp", addr)
		}
		elapsed := time.Since(start)

		if err != nil {
			fmt.Printf(" ✗ unreachable (%v)\n", err)
			os.Exit(1)
		}
		conn.Close()
		fmt.Printf(" ✓ reachable  rtt=%s\n", elapsed.Round(time.Millisecond))
	},
}

// ---------------------------------------------------------------------------
// vault rendezvous
// ---------------------------------------------------------------------------

var rendezvousCmd = &cobra.Command{
	Use:   "rendezvous",
	Short: "Register this node or look up a peer via the rendezvous server",
}

var rendezvousRegisterCmd = &cobra.Command{
	Use:   "register <peer-id> <quic-addr>",
	Short: "Register this peer's public QUIC address on the rendezvous server",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		if rendezvousServer == "" {
			fmt.Fprintln(os.Stderr, "Error: --rendezvous is required")
			os.Exit(1)
		}
		id, addr := args[0], args[1]
		c := rendezvous.NewClient(rendezvousServer)
		if err := c.Register(id, addr); err != nil {
			fmt.Fprintf(os.Stderr, "Register failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Registered peer %s at %s on %s\n", id, addr, rendezvousServer)
	},
}

var rendezvoousLookupCmd = &cobra.Command{
	Use:   "lookup <peer-id>",
	Short: "Look up a peer's public QUIC address from the rendezvous server",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if rendezvousServer == "" {
			fmt.Fprintln(os.Stderr, "Error: --rendezvous is required")
			os.Exit(1)
		}
		c := rendezvous.NewClient(rendezvousServer)
		addr, err := c.Lookup(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Lookup failed: %v\n", err)
			os.Exit(1)
		}
		if addr == "" {
			fmt.Printf("Peer %s is not registered on %s\n", args[0], rendezvousServer)
			os.Exit(1)
		}
		fmt.Printf("%-20s %s\n", args[0], addr)
	},
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func init() {
	// --rendezvous flag available on all rendezvous subcommands.
	rendezvousCmd.PersistentFlags().StringVar(&rendezvousServer, "server", "", "Rendezvous server base URL (e.g. http://relay.example.com:8080)")
	// Also expose at root level so vault send / vault run can pick it up.
	rootCmd.PersistentFlags().StringVar(&rendezvousServer, "rendezvous", "", "Rendezvous server base URL")
}
