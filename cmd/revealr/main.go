// cmd/revealr/main.go
// it manages cli input for the program and call respective function according to cli input 
package main

import (
	"fmt"
	"os"
	"time"

	"revealr/pkg/app" // Correct: Import the app package for Orchestrator
	"revealr/pkg/config"
	"revealr/pkg/core"
	"revealr/pkg/output"
	"revealr/pkg/plugin_manager"
	
	"github.com/spf13/cobra"
)
// it is the main page it controls  the whole program 

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
	timing        string
	advancedMode  bool
)
// main command runs everytime shows how to run revelar
var rootCmd = &cobra.Command{
	Use:   "revealr [command]",
	Short: fmt.Sprintf("%sRevealr:%s Your all-in-one security assistant", output.Cyan, output.Reset),
	Long: fmt.Sprintf(`%s
Revealr is a powerful, modular, and cross-platform network scanning and enumeration tool.
It combines high-speed Go-based scanning with a Python-powered intelligence engine
to discover live hosts, identify services and their versions, and detect potential misconfigurations.%s

%sUsage:%s
  revealr [command]

%sAvailable Commands:%s
  %sscan%s        Perform a network scan
  %ssetup%s       Check and fulfill Revealr's system requirements
  %shelp%s        Help about any command
  %splugins%s	  Manage and list intelligence plugins

%sGlobal Flags:%s
  %s-c, --config string%s      Config file (default: data/configs/default_config.yaml)
  %s    --debug%s            Enable debug output (very verbose, for troubleshooting)

Use "%srevealr [command] --help%s" for more information about a specific command.

%s--- Scan Command Details ---%s

%sUsage:%s
  revealr scan [flags]

%sFlags for 'scan' command:%s
  %s-t, --target strings%s      Target IP(s), CIDR(s), or hostname(s)
                              Examples: 192.168.1.1, scanme.nmap.org, 10.0.0.0/24

  %s-p, --ports string%s        Ports to scan. Accepts:
                              - "top1000" (default: scans 87 common ports)
                              - "all" (all 65535 ports)
                              - "80,443,22" or "1-1024"

  %s-m, --mode string%s         Port scan mode. Accepts:
                              - "connect" (default)
                              - "syn", "fin", "null", "xmas","ack", "window", "maimon", "udp"

  %s-c, --concurrency int%s     Maximum concurrent port scan operations (default: 1000)

  %s-T, --timing string%s       Timing template (like Nmap's -T<0-5>)
                              Options: "paranoid", "stealthy", "polite", "normal" (default), "aggressive", "insane"

  %s    --host-discovery strings%s  Host discovery methods (comma-separated)
                              Accepts: "icmp", "tcp-probe" (default), "arp", "tcp-syn-ack-probe"

  %s    --timeout duration%s     Timeout per port probe (e.g. "1s", "500ms", "10s") (default: 3s)
%sExamples:%s
  revealr scan -t scanme.nmap.org -p 80,443 --mode connect
  revealr scan -t 192.168.1.0/24 -p all -m syn -T aggressive
  revealr setup

%sFor more detailed information:
  revealr scan --help
  revealr setup --help
%s`,
		output.Cyan, output.Reset, // For Short description
		output.Yellow, output.Reset, // For "Usage:" header
		output.Yellow, output.Reset, // For "Available Commands:" header
		output.Green, output.Reset, // For "scan" command
		output.Green, output.Reset, // For "setup" command
		output.Green, output.Reset, // For "plugin" command
		output.Green, output.Reset, // For "help" command
		output.Yellow, output.Reset, // For "Global Flags:" header
		output.Green, output.Reset, // For "-c, --config string" flag
		output.Green, output.Reset, // For "--debug" flag
		output.Cyan, output.Reset, // For "revealr [command] --help" example
		output.Yellow, output.Reset, // For "--- Scan Command Details ---" header
		output.Yellow, output.Reset, // For "Usage:" header under Scan
		output.Yellow, output.Reset, // For "Flags for 'scan' command:" header
		output.Green, output.Reset, // For "-t, --target strings" flag
		output.Green, output.Reset, // For "-p, --ports string" flag
		output.Green, output.Reset, // For "-m, --mode string" flag
		output.Green, output.Reset, // For "-c, --concurrency int" flag
		output.Green, output.Reset, // For "-T, --timing string" flag
		output.Green, output.Reset, // For "--host-discovery strings" flag
		output.Green, output.Reset, // For "--timeout duration" flag
		output.Yellow, output.Reset, // For "Examples:" header
		output.Red,output.Reset,
	),
	Run: func(cmd *cobra.Command, args []string) {
		printBanner() // Print the banner
		cmd.Help() // Show help information for the specific command
	},
}

// scanCmd represents the 'scan' subcommand, which initiates the network scan.
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Perform a network scan",
	Long:  `Initiates a comprehensive network scan against specified targets.`,
	Run: func(cmd *cobra.Command, args []string) {
		runScan() // Call the function that contains the main scan orchestration logic this exist in the same file .
	},
}
//setupCmd represents the 'setup' subcommand, which checks and fulfills Revealr's system requirements.
var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Check and fulfill Revealr's system requirements",
	Long:  `Checks for Go, Git, Protoc, Python, and required Python libraries. Attempts to guide installation or perform setup tasks.`,
	Run: func(cmd *cobra.Command, args []string) {
		app.RunSetup() // Call the setup function in pkg/app
	},
}

var pluginsCmd = &cobra.Command{
	Use:   "plugins",
	Short: "Manage intelligence plugins",
	Long:  `Manage the plugins used by the Revealr Intelligence Engine.`,
}

var initPluginCmd = &cobra.Command{
	Use:   "init [plugin_name]",
	Short: "Initialize a new local plugin",
	Long: `Creates a new plugin structure in the plugins/local directory.
Example: revealr plugins init my_custom_check`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		plugin_manager.CreatePlugin(args[0])
	},
}

var listPluginsCmd = &cobra.Command{
	Use:   "list",
	Short: "List all installed plugins",
	Long:  `Scans the plugins directory and displays all available intelligence plugins.`,
	Run: func(cmd *cobra.Command, args []string) {
		plugin_manager.ListPlugins()
	},
}

var installPluginCmd = &cobra.Command{
	Use:   "install [url]",
	Short: "Download and install a plugin",
	Aliases: []string{"get", "download"},
	Long:  `Downloads a plugin from a git repository URL into the plugins/local directory.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		plugin_manager.InstallPlugin(args[0])
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
	// Ensure all new scan modes are listed in the help text for the 'mode' flag.
	scanCmd.Flags().StringVarP(&scanMode, "mode", "m", "connect", "Scan mode (connect, syn, fin, null, xmas, ack, window, maimon, udp)")
	scanCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 1000, "Maximum concurrent operations for port scanning")
	scanCmd.Flags().StringVar(&timeout, "timeout", "3s", "Timeout for each port scan attempt (e.g., 1s, 500ms)")
	// Ensure all new host discovery methods are listed in the help text for the 'host-discovery' flag.
	scanCmd.Flags().StringSliceVar(&hostDiscovery, "host-discovery", []string{"tcp-probe"}, "Host discovery methods (icmp, tcp-probe, arp, tcp-syn-ack-probe)") 
	scanCmd.Flags().StringVarP(&timing, "timing", "T", "normal", "Timing template: paranoid, stealthy, polite, normal, aggressive, insane")
	scanCmd.Flags().BoolVar(&advancedMode, "advanced", false, "Enable advanced audit mode (deeper inspection, slower)")

	// Add the 'scan' subcommand as a child of the root command.
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(pluginsCmd)
	pluginsCmd.AddCommand(initPluginCmd)
	pluginsCmd.AddCommand(listPluginsCmd)
	pluginsCmd.AddCommand(installPluginCmd)
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

	// Apply timing templates (overrides default config, but can be overridden by specific flags)
	if timing != "normal" {
		switch timing {
		case "paranoid":
			cfg.Concurrency = 1
			cfg.Timeout = 300 * time.Second
		case "stealthy":
			cfg.Concurrency = 1
			cfg.Timeout = 15 * time.Second
		case "polite":
			cfg.Concurrency = 1
			cfg.Timeout = 400 * time.Millisecond
		case "aggressive":
			cfg.Concurrency = 2000
			cfg.Timeout = 1000 * time.Millisecond
		case "insane":
			cfg.Concurrency = 5000
			cfg.Timeout = 250 * time.Millisecond
		}
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
	cfg.AdvancedMode = advancedMode // Set advanced mode from CLI flag

	// Set the debug mode for the output package based on loaded/overridden config from output file.
	output.SetDebugMode(cfg.Debug)

	// Ensure targets are provided, either via config file or CLI flag.
	if len(cfg.Targets) == 0 {
		output.PrintError("No targets specified. Use --target")
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
	Controller := app.NewController(cfg, session)
	err = Controller.StartScan(cfg.Targets)
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

func printBanner() {
	fmt.Printf("%s", output.Green)
	fmt.Println(`
██████   ███████  ██    ██  ███████   █████   ██       ██████  
██   ██  ██       ██    ██  ██       ██   ██  ██       ██   ██ 
██████   █████    ██    ██  █████    ███████  ██       ██████  
██   ██  ██       ██    ██  ██       ██   ██  ██       ██   ██ 
██   ██  ███████   ██████   ███████  ██   ██  ███████  ██   ██ 
                                                  `)
	fmt.Printf("%sRevealr:%s A High-Speed Adaptive Network Scanner with Intelligence Engine\n", output.Cyan, output.Reset)
	fmt.Printf("%sVersion:%s  0.1.0-alpha\n", output.White, output.Reset)
	fmt.Printf("%sAuthor:%s   Rounak Neema\n", output.White, output.Reset)
	fmt.Printf("%sGitHub:%s   https://github.com/Rounakneema/Advance-Network-Scanner\n", output.White, output.Reset)
	fmt.Println()
}

// main function is the entry point of the Go program.
func main() {
	Execute() // Start the Cobra CLI.
}
