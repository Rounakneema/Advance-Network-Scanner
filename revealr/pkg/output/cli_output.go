// pkg/output/cli_output.go
package output

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// ANSI escape codes for colors
const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	White  = "\033[97m"
)

var (
	// stdoutMux prevents interleaved prints from concurrent goroutines
	stdoutMux sync.Mutex
)

// PrintInfo prints informational messages in Cyan.
func PrintInfo(format string, a ...interface{}) {
	printMessage(Cyan, "INFO", format, a...)
}

// PrintSuccess prints success messages in Green.
func PrintSuccess(format string, a ...interface{}) {
	printMessage(Green, "SUCCESS", format, a...)
}

// PrintWarning prints warning messages in Yellow.
func PrintWarning(format string, a ...interface{}) {
	printMessage(Yellow, "WARN", format, a...)
}

// PrintError prints error messages in Red.
func PrintError(format string, a ...interface{}) {
	printMessage(Red, "ERROR", format, a...)
}

// PrintDebug prints debug messages in Blue (only if debug mode is enabled).
// For now, it always prints. Later, add a config check based on `cfg.Debug`.
func PrintDebug(format string, a ...interface{}) {
	// TODO: Integrate with a global debug flag from config
	printMessage(Blue, "DEBUG", format, a...)
}

// printMessage is a helper to format and print messages safely.
func printMessage(color, prefix, format string, a ...interface{}) {
	stdoutMux.Lock()
	defer stdoutMux.Unlock()
	timestamp := time.Now().Format("15:04:05") // Format: HH:MM:SS
	fmt.Fprintf(os.Stdout, "%s[%s] [%s] %s%s\n", color, timestamp, prefix, fmt.Sprintf(format, a...), Reset)
}

// PrintHostScanProgress displays live progress for host discovery.
func PrintHostScanProgress(current, total int, target string) {
	stdoutMux.Lock()
	defer stdoutMux.Unlock()
	// Use \r to return cursor to start of line for in-place updates, creating a dynamic progress line.
	fmt.Printf("\r%s[INFO] [%s] Discovering hosts: %d/%d - %s...%s", Cyan, time.Now().Format("15:04:05"), current, total, target, Reset)
	if current == total {
		fmt.Println() // Add a newline after completion to ensure next output is on a new line.
	}
}

// PrintPortScanProgress displays live progress for port scanning a specific host.
func PrintPortScanProgress(host string, current, total int) {
	stdoutMux.Lock()
	defer stdoutMux.Unlock()
	fmt.Printf("\r%s[%s] [%s] Scanning ports for %s: %d/%d...%s", Green, time.Now().Format("15:04:05"), "SCAN", host, current, total, Reset)
	if current == total {
		fmt.Println() // Add a newline after completion.
	}
}

// PrintOpenPort displays an open port in a highlighted format.
func PrintOpenPort(host, protocol string, port int, service string) {
	stdoutMux.Lock()
	defer stdoutMux.Unlock()
	fmt.Fprintf(os.Stdout, "%s[%s] [OPEN] %s:%d/%s - %s%s\n", Yellow, time.Now().Format("15:04:05"), host, port, protocol, service, Reset)
}
