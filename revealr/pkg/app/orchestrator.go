// pkg/app/orchestrator.go
package app

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"revealr/pkg/config"
	"revealr/pkg/core"
	"revealr/pkg/discovery"
	"revealr/pkg/output"
	"revealr/pkg/scanner"
)

// Orchestrator manages the overall scan process. It coordinates host discovery,
// port scanning, and future phases like enumeration and analysis.
type Orchestrator struct {
	config    *config.ScanConfig
	session   *core.Session
	hostDisc  *discovery.HostDiscoverer
	portScan  *scanner.PortScanner // Now holds the scanner with raw capabilities
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewOrchestrator creates a new Orchestrator instance, setting up
// host discovery and port scanning components.
func NewOrchestrator(cfg *config.ScanConfig, sess *core.Session) *Orchestrator {
	ctx, cancel := context.WithCancel(context.Background())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		output.PrintWarning("Ctrl+C detected. Attempting graceful shutdown...")
		cancel()
	}()

	hd := discovery.NewHostDiscoverer()
	// FIX: Assign both return values of scanner.NewPortScanner (ps and err)
	ps, err := scanner.NewPortScanner(&scanner.PortScannerConfig{
		ScanMode:    cfg.ScanMode,
		Timeout:     cfg.Timeout,
		Concurrency: cfg.Concurrency,
	})
	if err != nil {
		// Log the error and set ps to nil if initialization fails.
		// The StartScan method will check if ps is nil before calling ScanPorts.
		output.PrintError("Failed to initialize Port Scanner: %v. Raw scan modes (syn, fin, xmas, null, ack, window, maimon, udp) require root/admin privileges for optimal performance.", err)
		ps = nil // Set to nil so StartScan can gracefully handle it.
	}

	return &Orchestrator{
		config:    cfg,
		session:   sess,
		hostDisc:  hd,
		portScan:  ps, // ps might be nil if initialization failed.
		ctx:       ctx,
		cancel:    cancel,
	}
}

// StartScan initiates the complete scanning process.
func (o *Orchestrator) StartScan(targets []string) error {
	defer o.cancel()
	// FIX: Ensure PortScanner's pcap handle is closed only if ps is not nil
	if o.portScan != nil {
		defer o.portScan.Close()
	}

	output.PrintInfo("Revealr scan started at %s", time.Now().Format(time.RFC1123))

	resolvedIPs, err := o.resolveTargets(targets)
	if err != nil {
		return fmt.Errorf("failed to resolve targets: %w", err)
	}
	if len(resolvedIPs) == 0 {
		return fmt.Errorf("no valid IP addresses or hostnames found in targets after resolution")
	}
	output.PrintInfo("Resolved %d unique IP addresses for scanning.", len(resolvedIPs))

	var liveHosts []*core.Host
	if len(o.config.HostDiscovery) == 0 {
		output.PrintWarning("No host discovery methods specified. Assuming all resolved targets are live.")
		for _, ip := range resolvedIPs {
			host := core.NewHost(ip)
			host.IsUp = true
			liveHosts = append(liveHosts, host)
		}
	} else {
		discoveredHostsMap := make(map[string]*core.Host)
		
		for _, method := range o.config.HostDiscovery {
			select {
			case <-o.ctx.Done():
				output.PrintWarning("Host discovery cancelled.")
				return o.ctx.Err()
			default:
				var hosts [] *core.Host
				var discErr error
				output.PrintInfo("Performing host discovery using method: %s", method)
				switch method {
				case "icmp":
					hosts, discErr = o.hostDisc.PingHosts(o.ctx, resolvedIPs, o.config.Timeout)
				case "tcp-probe": // Existing TCP Connect probe
					hosts, discErr = o.hostDisc.TCPProbeHosts(o.ctx, resolvedIPs, o.config.Timeout)
				case "arp": // ARP scan
					// ARP scan needs a CIDR target for local subnet.
					// Check if resolvedIPs is a single CIDR.
					if len(resolvedIPs) == 1 && strings.Contains(targets[0], "/") {
						_, ipNet, parseErr := net.ParseCIDR(targets[0])
						if parseErr == nil {
							hosts, discErr = o.hostDisc.ARPScan(o.ctx, ipNet, o.config.Timeout)
						} else {
							discErr = fmt.Errorf("ARP scan requires a single CIDR target, got %s", targets[0])
						}
					} else {
						discErr = fmt.Errorf("ARP scan requires a single CIDR target for local subnet discovery. Skipping.")
					}
				case "tcp-syn-ack-probe": // TCP SYN/ACK ping host discovery
					hosts, discErr = o.hostDisc.TCPHostProbePing(o.ctx, resolvedIPs, o.config.Timeout)
				default:
					output.PrintWarning("Unknown host discovery method: %s. Skipping.", method)
					continue
				}

				if discErr != nil {
					output.PrintError("Host discovery method '%s' failed: %v", method, discErr)
				} else {
					for _, h := range hosts {
						discoveredHostsMap[h.ID] = h
					}
				}
			}
		}

		for _, h := range discoveredHostsMap {
			liveHosts = append(liveHosts, h)
		}
	}


	if len(liveHosts) == 0 {
		output.PrintWarning("No live hosts found to scan after discovery.")
		return nil
	}
	output.PrintSuccess("Found %d live hosts for port scanning.", len(liveHosts))

	portsToScan, err := o.config.ParsePorts()
	if err != nil {
		return fmt.Errorf("failed to parse ports: %w", err)
	}
	if len(portsToScan) == 0 {
		return fmt.Errorf("no ports specified for scanning")
	}
	output.PrintInfo("Prepared to scan %d ports.", len(portsToScan))

	if o.portScan == nil {
		output.PrintError("Port scanner not initialized (likely due to insufficient permissions for raw modes, or other initialization error). Skipping port scan.")
		return fmt.Errorf("port scanner not initialized")
	}

	var scanWG sync.WaitGroup
	for _, host := range liveHosts {
		select {
		case <-o.ctx.Done():
			output.PrintWarning("Port scanning cancelled for remaining hosts.")
			scanWG.Wait()
			return o.ctx.Err()
		default:
			scanWG.Add(1)
			go func(h *core.Host) {
				defer scanWG.Done()
				o.portScan.ScanPorts(o.ctx, h, portsToScan)
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
	scanWG.Wait()

	output.PrintInfo("Scan finished at %s", time.Now().Format(time.RFC1123))

	return nil
}

// resolveTargets (same as before)
func (o *Orchestrator) resolveTargets(targets []string) ([]net.IP, error) {
	var ips []net.IP
	for _, target := range targets {
		if ip := net.ParseIP(target); ip != nil {
			ips = append(ips, ip)
		} else if _, ipNet, err := net.ParseCIDR(target); err == nil {
			for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
				ips = append(ips, net.ParseIP(ip.String()))
			}
		} else {
			addrs, err := net.LookupIP(target)
			if err != nil {
				output.PrintWarning("Could not resolve target '%s': %v. Skipping.", target, err)
				continue
			}
			for _, addr := range addrs {
				if ip4 := addr.To4(); ip4 != nil {
					ips = append(ips, ip4)
				}
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no valid IP addresses or hostnames found in targets")
	}

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

// inc (same as before)
func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// contains (helper, same as before)
func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}