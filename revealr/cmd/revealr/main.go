// cmd/revealr/main.go
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"revealr/pkg/app"    // Correct: Import the app package for Orchestrator
	"revealr/pkg/config"
	"revealr/pkg/core"
	"revealr/pkg/output"
)

// Global variables to hold CLI flag values. These are populated by Cobra.
var (
	cfgFile       string
	targets       []string
	ports         string
	scanMode      string
	concurrency   int
	timeout       string
	hostDiscovery []string
	debug         bool
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "revealr",
	Short: "Revealr: Your all-in-one security assistant",
	Long: `Revealr is a next-generation, modular, cross-platform scanning and enumeration tool.
It combines active scanning, passive reconnaissance, deep service fingerprinting,
and intelligent insights to reveal hidden vulnerabilities.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help() // If no subcommand is given, print help.
	},
}

// scanCmd represents the 'scan' subcommand, which initiates the network scan.
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Perform a network scan",
	Long:  `Initiates a comprehensive network scan against specified targets.`,
	Run: func(cmd *cobra.Command, args []string) {
		runScan() // Call the function that contains the main scan orchestration logic.
	},
}

// init function runs automatically before the main() function.
// It sets up Cobra's command-line flags and subcommands.
func init() {
	cobra.OnInitialize(initConfig) // Register initConfig to be called before command execution.

	// Define global flags that can be used with any command (e.g., `revealr --config my.yaml scan`).
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is data/configs/default_config.yaml)")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug output")

	// Define flags specific to the 'scan' command (e.g., `revealr scan --target 192.168.1.1`).
	scanCmd.Flags().StringSliceVarP(&targets, "target", "t", []string{}, "Target IP(s), CIDR(s), or hostname(s) (comma-separated)")
	scanCmd.Flags().StringVarP(&ports, "ports", "p", "top1000", "Ports to scan (e.g., '80,443', '1-1024', 'all', 'top1000')")
	// FIX: Ensure all new scan modes are listed in the help text for the 'mode' flag.
	scanCmd.Flags().StringVarP(&scanMode, "mode", "m", "connect", "Scan mode (connect, syn, fin, null, xmas, ack, window, maimon, udp)")
	scanCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 1000, "Maximum concurrent operations for port scanning")
	scanCmd.Flags().StringVar(&timeout, "timeout", "3s", "Timeout for each port scan attempt (e.g., 1s, 500ms)")
	// FIX: Ensure all new host discovery methods are listed in the help text for the 'host-discovery' flag.
	scanCmd.Flags().StringSliceVar(&hostDiscovery, "host-discovery", []string{"tcp-probe"}, "Host discovery methods (icmp, tcp-probe, arp, tcp-syn-ack-probe)") // Default changed to tcp-probe for reliability

	// Add the 'scan' subcommand as a child of the root command.
	rootCmd.AddCommand(scanCmd)
}

// initConfig reads in config file and environment variables if set.
// This function is called by Cobra before command execution.
func initConfig() {
	if cfgFile == "" {
		// Set the default path for the configuration file.
		cfgFile = "data/configs/default_config.yaml"
	}
	// Note: Actual config loading and flag overriding happens within runScan()
	// after all flags have been parsed by Cobra.
}

// runScan contains the main logic for the 'scan' command, executed by Cobra.
func runScan() {
	// 1. Load configuration from the specified file and apply any overrides from CLI flags.
	cfg, err := config.LoadConfig(cfgFile)
	if err != nil {
		output.PrintError("Configuration error: %v", err)
		os.Exit(1)
	}

	// Override configuration values with those provided via command-line flags.
	if len(targets) > 0 {
		cfg.Targets = targets
	}
	if ports != "top1000" { // Only override if user explicitly set it (not default)
		cfg.Ports = ports
	}
	if scanMode != "connect" { // Only override if user explicitly set it (not default)
		cfg.ScanMode = scanMode
	}
	if concurrency != 1000 { // Only override if user explicitly set it (not default)
		cfg.Concurrency = concurrency
	}
	if timeout != "3s" { // Only override if user explicitly set it (not default)
		parsedTimeout, parseErr := time.ParseDuration(timeout)
		if parseErr != nil {
			output.PrintError("Invalid timeout format: %v", parseErr)
			os.Exit(1)
		}
		cfg.Timeout = parsedTimeout
	}
	if len(hostDiscovery) > 0 { // Allow overriding host discovery methods
		cfg.HostDiscovery = hostDiscovery
	}
	cfg.Debug = debug // Set debug mode based on the CLI flag.

	// Set the debug mode for the output package based on loaded/overridden config.
	output.SetDebugMode(cfg.Debug)

	// Ensure targets are provided, either via config file or CLI flag.
	if len(cfg.Targets) == 0 {
		output.PrintError("No targets specified. Use --target or configure in default_config.yaml")
		os.Exit(1)
	}

	// 2. Initialize Session for local data persistence.
	// This will create or open the SQLite database to store scan results.
	session, err := core.NewSession("data/db/revealr.db")
	if err != nil {
		output.PrintError("Failed to initialize session: %v", err)
		os.Exit(1)
	}
	defer session.Close() // Ensure the database connection is closed when the scan finishes.

	// 3. Initialize the Orchestrator and start the scan process.
	// This delegates the core application logic to the 'app' package.
	orchestrator := app.NewOrchestrator(cfg, session)
	err = orchestrator.StartScan(cfg.Targets)
	if err != nil {
		output.PrintError("Scan operation failed: %v", err)
		os.Exit(1)
	}

	output.PrintSuccess("Scan completed successfully.")
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is the function called from `main()` to start the Cobra CLI application.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// main function is the entry point of the Go program.
func main() {
	Execute() // Start the Cobra CLI.
}