// pkg/scanner/ports.go
package scanner

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"revealr/pkg/core"   // Update import path
	"revealr/pkg/output" // Update import path
)

// PortScanner manages port scanning operations.
type PortScanner struct {
	config *PortScannerConfig
}

// PortScannerConfig holds specific configurations for port scanning.
type PortScannerConfig struct {
	ScanMode    string        // "connect"
	Timeout     time.Duration // Timeout per port
	Concurrency int           // Max concurrent operations
}

// NewPortScanner creates a new PortScanner instance.
func NewPortScanner(cfg *PortScannerConfig) *PortScanner {
	return &PortScanner{
		config: cfg,
	}
}

// ScanPorts performs port scanning on a given host for a list of ports.
func (ps *PortScanner) ScanPorts(ctx context.Context, host *core.Host, ports []int) {
	output.PrintInfo("Starting %s scan for %s on %d ports...", ps.config.ScanMode, host.IPAddress.String(), len(ports))

	var wg sync.WaitGroup
	portQueue := make(chan int, ps.config.Concurrency*2) // Buffered channel for ports to scan (allows more tasks than workers)
	resultsChan := make(chan *core.Port, len(ports))     // Channel to collect results from workers

	// Start a goroutine to collect and process results as they come in.
	go func() {
		processedCount := 0
		totalPorts := len(ports)
		for p := range resultsChan {
			host.AddPort(p) // Add the scanned port to the host object
			processedCount++
			if p.IsOpen {
				output.PrintOpenPort(host.IPAddress.String(), p.Protocol, p.PortNumber, p.Service.Name)
			}
			output.PrintPortScanProgress(host.ID, processedCount, totalPorts) // Update live progress
		}
		// Ensure a final newline if the progress line was the last output, to clean up the terminal.
		if processedCount > 0 {
			output.PrintPortScanProgress(host.ID, processedCount, totalPorts) // Force final print to ensure newline
		}
	}()

	// Start worker goroutines. These workers will pull ports from `portQueue`.
	for i := 0; i < ps.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for portNum := range portQueue { // Loop until portQueue is closed
				select {
				case <-ctx.Done():
					return // If context is cancelled, stop this worker.
				default:
					isPortOpen := false
					var serviceName string
					protocolUsed := "tcp" // For TCP Connect scan

					// Perform the TCP Connect scan
					isPortOpen, serviceName = ps.tcpConnectScan(host.IPAddress, portNum)

					// Create a new Port object with the scan result
					port := core.NewPort(portNum, protocolUsed)
					port.IsOpen = isPortOpen
					port.Service.Name = serviceName
					resultsChan <- port // Send the result to the collector goroutine
				}
			}
		}()
	}

	// Feed ports into the `portQueue` for workers to pick up.
	for _, p := range ports {
		portQueue <- p
	}
	close(portQueue) // Close the queue to signal workers that no more ports will be sent.

	wg.Wait()          // Wait for all worker goroutines to finish their tasks.
	close(resultsChan) // Close the results channel after all workers are done.

	output.PrintSuccess("Port scan for %s completed.", host.IPAddress.String())
}

// tcpConnectScan performs a full TCP connect scan using standard library `net.DialTimeout`.
// This method attempts to establish a full TCP handshake.
func (ps *PortScanner) tcpConnectScan(ip net.IP, port int) (bool, string) {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	conn, err := net.DialTimeout("tcp", addr, ps.config.Timeout)
	if err != nil {
		return false, "" // If an error occurs (e.g., connection refused, timeout), the port is considered closed or filtered.
	}
	defer conn.Close() // Ensure the connection is closed when the function exits.

	// Attempt a simple banner grabbing by reading a small buffer from the connection.
	// This helps identify the service running on the port.
	conn.SetReadDeadline(time.Now().Add(time.Millisecond * 500)) // Set a short deadline for reading the banner.
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err == nil {
		banner := string(bytes.TrimSpace(buffer[:n])) // Clean up whitespace from the banner.
		return true, inferServiceFromBanner(banner)   // Port is open, return inferred service from banner.
	}
	return true, inferServiceFromPort(port) // Port is open, but no banner or read error, so infer service from port number.
}

// inferServiceFromPort provides a basic service name lookup based on common port numbers.
func inferServiceFromPort(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 135:
		return "msrpc"
	case 139:
		return "netbios-ssn"
	case 143:
		return "imap"
	case 443:
		return "https"
	case 445:
		return "microsoft-ds"
	case 3306:
		return "mysql"
	case 3389:
		return "ms-wbt-server"
	case 5900:
		return "vnc"
	case 8080:
		return "http-proxy"
	default:
		return "unknown" // If port is not in the list, service is unknown.
	}
}

// inferServiceFromBanner attempts to guess service from a captured banner string.
func inferServiceFromBanner(banner string) string {
	if len(banner) > 0 {
		cleanBanner := bytes.TrimSpace([]byte(banner))
		if len(cleanBanner) > 30 { // Trim banner for display to avoid overly long output.
			cleanBanner = cleanBanner[:30]
		}
		return "banner: " + string(cleanBanner)
	}
	return "unknown" // No banner found.
}
