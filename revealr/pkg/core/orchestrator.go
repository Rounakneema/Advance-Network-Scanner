// pkg/core/orchestrator.go
package core

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"revealr/pkg/config"
	"revealr/pkg/discovery"
	"revealr/pkg/output"
	"revealr/pkg/scanner"
)

// Orchestrator manages the overall scan process. It coordinates host discovery,
// port scanning, and future phases like enumeration and analysis.
type Orchestrator struct {
	config   *config.ScanConfig
	session  *Session // Manages scan state and persistence to database
	hostDisc *discovery.HostDiscoverer
	portScan *scanner.PortScanner
	ctx      context.Context    // Context for cancellation
	cancel   context.CancelFunc // Function to cancel the context
}

// NewOrchestrator creates a new Orchestrator instance, setting up
// host discovery and port scanning components.
func NewOrchestrator(cfg *config.ScanConfig, sess *Session) *Orchestrator {
	ctx, cancel := context.WithCancel(context.Background())

	// Set up a signal handler to gracefully shut down on Ctrl+C (SIGINT or SIGTERM).
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan // Blocks until a signal is received
		output.PrintWarning("Ctrl+C detected. Attempting graceful shutdown...")
		cancel() // Cancel the context, signaling all goroutines to stop.
	}()

	// Initialize the HostDiscoverer and PortScanner with the provided configuration.
	hd := discovery.NewHostDiscoverer()
	ps := scanner.NewPortScanner(&scanner.PortScannerConfig{
		ScanMode:    cfg.ScanMode,
		Timeout:     cfg.Timeout,
		Concurrency: cfg.Concurrency,
	})

	return &Orchestrator{
		config:   cfg,
		session:  sess,
		hostDisc: hd,
		portScan: ps,
		ctx:      ctx,
		cancel:   cancel,
	}
}

// StartScan initiates the complete scanning process.
func (o *Orchestrator) StartScan(targets []string) error {
	defer o.cancel() // Ensure the context is cancelled when StartScan exits, releasing resources.

	output.PrintInfo("Revealr scan started at %s", time.Now().Format(time.RFC1123))

	// 1. Resolve targets (IPs, CIDRs, hostnames) into a list of unique IP addresses.
	resolvedIPs, err := o.resolveTargets(targets)
	if err != nil {
		return fmt.Errorf("failed to resolve targets: %w", err)
	}
	if len(resolvedIPs) == 0 {
		return fmt.Errorf("no valid IP addresses or hostnames found in targets after resolution")
	}
	output.PrintInfo("Resolved %d unique IP addresses for scanning.", len(resolvedIPs))

	// 2. Perform Host Discovery using configured methods.
	var liveHosts []*Host
	for _, method := range o.config.HostDiscovery {
		select {
		case <-o.ctx.Done(): // Check if scan was cancelled during host discovery.
			output.PrintWarning("Host discovery cancelled.")
			return o.ctx.Err()
		default:
			output.PrintInfo("Performing host discovery using method: %s", method)
			switch method {
			case "icmp":
				hosts, err := o.hostDisc.PingHosts(o.ctx, resolvedIPs, o.config.Timeout)
				if err != nil {
					output.PrintError("ICMP host discovery failed: %v", err)
					// Continue to next method or fail based on policy.
				}
				liveHosts = append(liveHosts, hosts...)
			case "tcp-probe":
				// TODO: Implement TCP probe host discovery (connect to common ports).
				output.PrintWarning("TCP probe host discovery not yet implemented. Skipping.")
			default:
				output.PrintWarning("Unknown host discovery method: %s. Skipping.", method)
			}
		}
	}

	// Deduplicate live hosts if multiple discovery methods were used, ensuring each host is processed once.
	uniqueLiveHosts := make(map[string]*Host)
	for _, host := range liveHosts {
		if _, exists := uniqueLiveHosts[host.ID]; !exists {
			uniqueLiveHosts[host.ID] = host
		}
	}
	finalLiveHosts := make([]*Host, 0, len(uniqueLiveHosts))
	for _, host := range uniqueLiveHosts {
		finalLiveHosts = append(finalLiveHosts, host)
	}

	if len(finalLiveHosts) == 0 {
		output.PrintWarning("No live hosts found to scan after discovery.")
		return nil
	}
	output.PrintSuccess("Found %d live hosts for port scanning.", len(finalLiveHosts))

	// 3. Parse Ports to scan from configuration.
	portsToScan, err := o.config.ParsePorts()
	if err != nil {
		return fmt.Errorf("failed to parse ports: %w", err)
	}
	if len(portsToScan) == 0 {
		return fmt.Errorf("no ports specified for scanning")
	}
	output.PrintInfo("Prepared to scan %d ports.", len(portsToScan))

	// 4. Perform Port Scanning for each live host concurrently.
	var scanWG sync.WaitGroup
	for _, host := range finalLiveHosts {
		select {
		case <-o.ctx.Done(): // Check for cancellation before starting new host scan.
			output.PrintWarning("Port scanning cancelled for remaining hosts.")
			scanWG.Wait() // Wait for any ongoing scans to finish.
			return o.ctx.Err()
		default:
			scanWG.Add(1)
			go func(h *Host) {
				defer scanWG.Done()
				o.portScan.ScanPorts(o.ctx, h, portsToScan)
				// Save host and its discovered ports to session after its scan is complete.
				if o.session != nil {
					if err := o.session.SaveHost(h); err != nil {
						output.PrintError("Failed to save host %s to session: %v", h.ID, err)
					} else {
						output.PrintDebug("Host %s saved to session.", h.ID)
					}
				}
			}(host)
		}
	}
	scanWG.Wait() // Wait for all host scans to complete.

	output.PrintInfo("Scan finished at %s", time.Now().Format(time.RFC1123))

	// TODO: Future phases will involve:
	// - Sending scan results to Python for deeper enumeration, analysis, etc.
	// - Generating comprehensive reports based on all collected data.

	return nil
}

// resolveTargets resolves target strings (IPs, CIDRs, hostnames) into a slice of unique net.IP addresses.
func (o *Orchestrator) resolveTargets(targets []string) ([]net.IP, error) {
	var ips []net.IP
	for _, target := range targets {
		if ip := net.ParseIP(target); ip != nil {
			// It's a direct IP address.
			ips = append(ips, ip)
		} else if _, ipNet, err := net.ParseCIDR(target); err == nil {
			// It's a CIDR range (e.g., "192.168.1.0/24"). Iterate through all IPs in the range.
			for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
				ips = append(ips, net.ParseIP(ip.String())) // Append a copy of the IP to avoid modification issues.
			}
		} else {
			// Assume it's a hostname, perform DNS lookup.
			addrs, err := net.LookupIP(target)
			if err != nil {
				output.PrintWarning("Could not resolve target '%s': %v. Skipping.", target, err)
				continue
			}
			for _, addr := range addrs {
				if ip4 := addr.To4(); ip4 != nil { // Prefer IPv4 addresses.
					ips = append(ips, ip4)
				}
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no valid IP addresses or hostnames found in targets")
	}

	// Deduplicate IPs using a map to ensure each IP is scanned only once.
	uniqueIPs := make(map[string]struct{})
	var finalIPs []net.IP
	for _, ip := range ips {
		if _, exists := uniqueIPs[ip.String()]; !exists {
			finalIPs = append(finalIPs, ip)
			uniqueIPs[ip.String()] = struct{}{}
		}
	}

	return finalIPs, nil
}

// inc increments an IP address (used for iterating through CIDR ranges).
func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}
