package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
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
		fmt.Printf("Sending file '%s' to peer '%s'...\n", args[0], args[1])
	},
}

var receiveCmd = &cobra.Command{
	Use:   "receive [file]",
	Short: "Receive a file from a peer",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Receiving file '%s'...\n", args[0])
	},
}

func init() {
	rootCmd.AddCommand(sendCmd, receiveCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
