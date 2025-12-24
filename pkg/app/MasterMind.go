// pkg/app/MasterMind.go it contanines the main logic of the program 

package app

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	rp "revealr/internal/proto"
	"revealr/pkg/config"
	"revealr/pkg/core"
	"revealr/pkg/discovery"
	"revealr/pkg/models"
	"revealr/pkg/output"
	"revealr/pkg/scanner"

	"google.golang.org/protobuf/proto"
)

// Orchestrator struct 
type Controller struct {
	config   *config.ScanConfig //it has all the configration of scan
	session  *core.Session // it containes all  the information about the db session
	hostDisc *discovery.HostDiscoverer
	portScan *scanner.PortScanner //has all information for scanning ports
	ctx       context.Context //context for clean exit by cli intruption crl+c
	cancel    context.CancelFunc //function that is called when ctrl+c is executed attached with context
	hasPython  bool //checks wheter the system path has python or not
	pythonPath string //stores the python path
}

// NewController takes configration of scan and session  and output the Controller sruct filled with all the information
func NewController(cfg *config.ScanConfig, sess *core.Session) *Controller {
	ctx, cancel := context.WithCancel(context.Background())

	// Load well-known ports from CSV at startup
	err := models.LoadWellKnownPortsDB("data/service-names-port-numbers.csv")
	if err != nil {
		output.PrintError("Failed to load well-known ports database: %v. Using hardcoded defaults only.", err)
	}

	sigChan := make(chan os.Signal, 1) // a buffered channel to handle graceful shutdown
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)//notify the channel of os signals
	go func() { // go routine that run indefentlly and sleeps until a signal is received	
		<-sigChan
		output.PrintWarning("Ctrl+C detected. Attempting graceful shutdown")
		cancel() //cancel the context
	}()

	hd := discovery.NewHostDiscoverer() //mutex for host discovery
	ps, err := scanner.NewPortScanner(&scanner.PortScannerConfig{ // it scans ports and return portscanner
		ScanMode:    cfg.ScanMode,
		Timeout:     cfg.Timeout,
		Concurrency: cfg.Concurrency,
	})
	if err != nil {
		if cfg.ScanMode != "connect" { //automated downgrading if previoues scan fails due to privilage issue or any issue for syn,ack,xmas etc
			output.PrintWarning("Failed to initialize raw port scanner (requires root/admin): %v. Automatically downgrading to TCP Connect scan (non-privileged).", err)
			ps, err = scanner.NewPortScanner(&scanner.PortScannerConfig{ // again do scan but now with connect mode
				ScanMode:    "connect",
				Timeout:     cfg.Timeout,
				Concurrency: cfg.Concurrency,
			})
			if err != nil {
				output.PrintError("Failed to initialize fallback TCP Connect scanner: %v", err)
				ps = nil
			} else {
				// Update config to reflect usage of connect mode
				cfg.ScanMode = "connect"
			}
		} else {
			output.PrintError("Failed to initialize Port Scanner: %v", err)
			ps = nil
		}
	}

	pythonPath, hasPy := checkPythonAvailability()
	if !hasPy {
		output.PrintWarning("Python environment not found (bundled or system). Advanced intelligence features (service detection, OSINT) will be disabled.")
	} else {
		if strings.Contains(pythonPath, string(os.PathSeparator)+"python") {
			output.PrintSuccess("Using bundled Python runtime: %s", pythonPath)
		} else {
			output.PrintSuccess("Using system Python: %s", pythonPath)
		}
	}

	return &Controller{
		config:   cfg,
		session:  sess,
		hostDisc: hd,
		portScan: ps,
		ctx:       ctx,
		cancel:    cancel,
		hasPython:  hasPy,
		pythonPath: pythonPath,
	}
}

// StartScan starts the scan process
func (o *Controller) StartScan(targets []string) error { //starts the scan to identify live host	
	defer o.cancel()
	if o.portScan != nil {
		defer o.portScan.Close()
	}
	scanStartTime := time.Now() // Record scan start time
	output.PrintInfo("Revealr scan started at %s", scanStartTime.Format(time.RFC1123))

	resolvedIPs, err := o.resolveTargets(targets) // gives converted ipaddress as target can be domain name, range ,direct ip address 
	if err != nil {
		return fmt.Errorf("failed to resolve targets: %w", err)
	}
	if len(resolvedIPs) == 0 {
		return fmt.Errorf("no valid IP addresses or hostnames found in targets after resolution")
	}
	output.PrintInfo("Resolved %d unique IP addresses for scanning.", len(resolvedIPs))

	var liveHosts []*models.Host //dynamic slice which store host structer 
	if len(o.config.HostDiscovery) == 0 {
		output.PrintWarning("No host discovery methods specified. Assuming all resolved targets are live.")
		for _, ip := range resolvedIPs {
			host := models.NewHost(ip) // creates new host with the resolved ip address
			host.IsUp = true // mark it live so can scan it in future
			liveHosts = append(liveHosts, host) //add this host to map
		}
	} else {
		discoveredHostsMap := make(map[string]*models.Host)

		for _, method := range o.config.HostDiscovery {
			select {
			case <-o.ctx.Done():
				output.PrintWarning("Host discovery cancelled.")
				return o.ctx.Err()
			default:
				var hosts []*models.Host
				var discErr error

				// FIX: For Raw Scans (SYN, FIN, etc.), default to ICMP to avoid polluting TCP ports
				if (o.config.ScanMode == "syn" || o.config.ScanMode == "fin" || o.config.ScanMode == "null" || o.config.ScanMode == "xmas") && method == "tcp-probe" {
					output.PrintInfo("Switching host discovery method from 'tcp-probe' to 'icmp' to avoid interference with raw %s scan.", o.config.ScanMode)
					method = "icmp"
				}

				output.PrintInfo("Performing host discovery using method: %s", method)
				switch method {
				case "icmp":
					hosts, discErr = o.hostDisc.PingHosts(o.ctx, resolvedIPs, o.config.Timeout)
				case "tcp-probe":
					hosts, discErr = o.hostDisc.TCPProbeHosts(o.ctx, resolvedIPs, o.config.Timeout)
				case "arp":
					if len(resolvedIPs) == 1 && strings.Contains(targets[0], "/") {
						_, ipNet, parseErr := net.ParseCIDR(targets[0])
						if parseErr == nil {
							hosts, discErr = o.hostDisc.ARPScan(o.ctx, ipNet, o.config.Timeout)
						} else {
							discErr = fmt.Errorf("ARP scan requires a single CIDR target, got %s", targets[0])
						}
					} else {
						discErr = fmt.Errorf("ARP scan requires a single CIDR target for local subnet discovery. Skipping")
					}
				case "tcp-syn-ack-probe":
					hosts, discErr = o.hostDisc.TCPHostProbePing(o.ctx, resolvedIPs, o.config.Timeout)
				default:
					output.PrintWarning("Unknown host discovery method: %s. Skipping.", method)
					continue
				}

				if discErr != nil {
					output.PrintError("host discovery method '%s' failed: %v", method, discErr)
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
			go func(h *models.Host) {
				defer scanWG.Done()
				o.portScan.ScanPorts(o.ctx, h, portsToScan) //scans port 

				var hostToSave *models.Host = h // Start with the Go-scanned host
				// Only run Python enrichment for "connect" scans. 
				// Raw scans (syn/fin/etc) should be fast and stealthy, avoiding HTTP handshakes.
				shouldEnrich := o.config.ScanMode == "connect" 
				if o.config.EnableOSINT && o.hasPython && shouldEnrich {
					enrichedHost, pyErr := o.callPythonIntelligence(o.ctx, h)
					if pyErr != nil {
						output.PrintError("Error during Python intelligence for host %s: %v", h.ID, pyErr)
					} else if enrichedHost != nil {
						output.PrintDebug("Host %s successfully enriched by Python intelligence. Using enriched data.", enrichedHost.ID)
						hostToSave = enrichedHost // Use the enriched host for saving
					}
				}

				if o.session != nil {
					if err := o.session.SaveHost(hostToSave); err != nil {
						output.PrintError("failed to save host %s to session: %v", hostToSave.ID, err)
					} else {
						output.PrintDebug("Host %s (final) saved/updated to session.", hostToSave.ID)
					}
				}
			}(host)
		}
	}
	scanWG.Wait()
	scanEndTime := time.Now() //Record scan end time

	scanDuration := scanEndTime.Sub(scanStartTime) //Calculate duration

	output.PrintInfo("Scan finished at %s", scanEndTime.Format(time.RFC1123))

	finalScanHosts, err := o.session.GetHostsByScanID(o.session.GetCurrentScanID())
	if err != nil {
		output.PrintError("failed to retrieve final scan results for summary: %v", err)
	} else {
		o.PrintScanSummary(finalScanHosts, scanDuration)
	}

	return nil
}

// callPythonIntelligence function (Method of Orchestrator)
func (o *Controller) callPythonIntelligence(ctx context.Context, host *models.Host) (*models.Host, error) {
	// Optimization: Filter out 'filtered' ports (timeouts) before sending to Python
	// Python plugins likely cannot probe filtered ports anyway, and sending hundreds creates overhead.
	activePorts := make([]*models.Port, 0)
	for _, p := range host.Ports {
		if p.State == models.PortOpen {
			activePorts = append(activePorts, p)
		}
	}
	// Create a shallow copy of host for protobuf conversion, pointing to activePorts
	hostForProto := &models.Host{
		ID:        host.ID,
		IPAddress: host.IPAddress,
		IsUp:      host.IsUp,
		Ports:     activePorts,
		Details:   host.Details,
	}

	protoHost := convertCoreHostToProto(hostForProto)

	// Construct the ScanResultRequest message with ScanConfig
	scanID := o.session.GetCurrentScanID()
	// Workaround for missing protoc: Encode AdvancedMode into ScanTiming string
	scanTiming := o.config.ScanTiming
	if o.config.AdvancedMode {
		scanTiming += "|advanced"
	}

	protoScanConfig := &rp.ScanConfig{ // Create protobuf ScanConfig message
		ScanTiming:   scanTiming,
		Debug:        o.config.Debug,
	}

	scanRequestProto := &rp.ScanResultRequest{
		ScanId:     scanID,
		Host:       protoHost,
		ScanConfig: protoScanConfig, // Pass the new ScanConfig
	}

	serializedRequest, err := proto.Marshal(scanRequestProto)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal protobuf message: %w", err)
	}

	length := uint32(len(serializedRequest))
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, length)

	cmdPath := o.pythonPath
	if cmdPath == "" {
		cmdPath = "python" // Fallback (shouldn't be reached if hasPython is true, but safe)
	}
	scriptPath := "plugins/intelligence.py"

	cmd := exec.CommandContext(ctx, cmdPath, scriptPath)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdin pipe for Python script: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdout pipe for Python script: %w", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start Python script (ensure 'python' is in PATH and 'plugins/intelligence.py' exists): %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stdin.Close()

		if _, err := stdin.Write(lengthBytes); err != nil {
			output.PrintError("failed to write length prefix to Python script stdin: %v", err)
			return
		}
		output.PrintDebug("Go: Wrote length prefix (%d bytes) to Python stdin.", length)

		if _, err := stdin.Write(serializedRequest); err != nil {
			output.PrintError("failed to write protobuf message to Python script stdin: %v", err)
		}
		output.PrintDebug("Go: Wrote protobuf message to Python stdin.")
	}()
	wg.Wait()

	outputBytes, err := io.ReadAll(stdout)
	if err != nil {
		return nil, fmt.Errorf("failed to read from Python script stdout: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("python script failed with exit code: %w (Output: %s)", err, string(outputBytes))
	}

	// 5. Parse the JSON output from Python
	type PythonPortUpdate struct {
		HostID         string                 `json:"host_id"`
		PortNumber     int                    `json:"port_number"`
		Protocol       string                 `json:"protocol"`
		ServiceName    string                 `json:"service_name"`
		ServiceVersion string                 `json:"service_version"`
		Details        map[string]interface{} `json:"details"` // Keep as interface{} for unmarshaling
	}
	var enrichedPortsData []PythonPortUpdate
	if len(outputBytes) > 0 {
		if err := json.Unmarshal(outputBytes, &enrichedPortsData); err != nil {
			output.PrintError("failed to unmarshal JSON from Python script: %v (Raw: %s)", err, string(outputBytes))
			return host, fmt.Errorf("Python script returned invalid JSON: %w", err)
		}
	} else {
		output.PrintDebug("Python script returned empty stdout for host %s. No enrichment.", host.ID)
		return host, nil
	}

	// 6. Apply enriched data back to the original Go Host object
	for _, p := range host.Ports {
		for _, enrichedP := range enrichedPortsData {
			if p.PortNumber == enrichedP.PortNumber && p.Protocol == enrichedP.Protocol {
				// FIX: Update Service Name and Version (Python's guess takes precedence)
				if enrichedP.ServiceName != "" && enrichedP.ServiceName != "unknown" {
					p.Service.Name = enrichedP.ServiceName
				}
				if enrichedP.ServiceVersion != "" {
					p.Service.Version = enrichedP.ServiceVersion
				}

				// FIX: Update Host's top-level OS detail if Python inferred it
				if osVal, ok := enrichedP.Details["os"].(string); ok && osVal != "unknown" {
					if host.Details == nil {
						host.Details = make(map[string]string)
					}
					host.Details["os"] = osVal // Update host-level OS detail
				}

				// FIX: Merge additional details into p.Details (Port-level)
				if enrichedP.Details != nil {
					if p.Details == nil {
						p.Details = make(map[string]string)
					}
					for k, v := range enrichedP.Details {
						// Ensure conversion to string for map[string]string
						p.Details[k] = fmt.Sprintf("%v", v)
					}
				}
				break // Found and updated, move to next original port
			}
		}
	}
	// NEW DEBUG LOG: Print host and port details BEFORE saving
	output.PrintDebug("Go: Host %s details before saving: %v", host.ID, host.Details)
	for _, p := range host.Ports {
		output.PrintDebug("Go: Port %d/%s details before saving: %v, Service: %s v%s",
			p.PortNumber, p.Protocol, p.Details, p.Service.Name, p.Service.Version)
	}

	return host, nil // Return the (potentially) enriched host object
}

// PrintScanSummary method, now part of Orchestrator
func (o *Controller) PrintScanSummary(hosts []*models.Host, scanDuration time.Duration) {
	output.PrintInfo("Generating scan summary...")
	fmt.Printf("\n%s==================================================%s\n", output.Green, output.Reset)
	fmt.Printf("%s               Revealr Scan Summary               %s\n", output.Green, output.Reset)
	fmt.Printf("%s==================================================%s\n", output.Green, output.Reset)

	if len(hosts) == 0 {
		fmt.Printf("%sNo live hosts found with open ports in this scan.%s\n", output.Yellow, output.Reset)
		return
	}

	for _, host := range hosts {
		fmt.Printf("\n%sHost: %s (%s)%s\n", output.Cyan, host.ID, host.IPAddress.String(), output.Reset)
		fmt.Printf("%s  Status: %s%s\n", output.Cyan, func() string {
			if host.IsUp {
				return "Up"
			} else {
				return "Down"
			}
		}(), output.Reset)

		if osVal, ok := host.Details["os"]; ok && osVal != "unknown" {
			fmt.Printf("%s  OS: %s%s\n", output.Cyan, osVal, output.Reset)
		} else {
			fmt.Printf("%s  OS: unknown%s\n", output.Yellow, output.Reset)
		}

		if len(host.Ports) == 0 {
			fmt.Printf("%s  No open ports found.%s\n", output.Yellow, output.Reset)
			continue
		}



		// Categorize ports for summary
		var openPorts []*models.Port
		var filteredPortsCount int
		var openFilteredPortsCount int
		var closedPortsCount int

		for _, port := range host.Ports {
			switch port.State {
			case models.PortOpen:
				openPorts = append(openPorts, port)
			case models.PortFiltered:
				filteredPortsCount++
			case models.PortOpenFiltered:
				openFilteredPortsCount++
			case models.PortClosed:
				closedPortsCount++
			}
		}

		// Print Port State Summary Table
		fmt.Printf("%s  Port State Summary:%s\n", output.Cyan, output.Reset)
		fmt.Printf("    Open:          %d\n", len(openPorts))
		if closedPortsCount > 0 {
			fmt.Printf("    Closed:        %d\n", closedPortsCount)
		}
		if filteredPortsCount > 0 {
			fmt.Printf("    Filtered:      %d\n", filteredPortsCount)
		}
		if openFilteredPortsCount > 0 {
			fmt.Printf("    Open|Filtered: %d\n", openFilteredPortsCount)
		}

		// Detailed Listing for OPEN ports only
		if len(openPorts) > 0 {
			// Group open ports by service
			servicesMap := make(map[string][]*models.Port)
			for _, port := range openPorts {
				serviceKey := port.Service.Name
				if serviceKey == "" || serviceKey == "unknown" {
					serviceKey = "unknown"
				}
				servicesMap[serviceKey] = append(servicesMap[serviceKey], port)
			}

			// Sort service names
			sortedServiceNames := make([]string, 0, len(servicesMap))
			for serviceName := range servicesMap {
				sortedServiceNames = append(sortedServiceNames, serviceName)
			}
			sort.Strings(sortedServiceNames)

			fmt.Printf("\n%s  Open Ports Details:%s\n", output.Cyan, output.Reset)
			for _, serviceName := range sortedServiceNames {
				portsForService := servicesMap[serviceName]
				
				// Representative port logic (same as before)
				var representativePort *models.Port
				if len(portsForService) > 0 {
					representativePort = portsForService[0]
					for _, p := range portsForService {
						if p.Service.Version != "" {
							representativePort = p
							break
						} else if len(p.Details) > len(representativePort.Details) {
							representativePort = p
						}
					}
				}

				// Format service header
				serviceHeader := fmt.Sprintf("%s    Service: %s", output.Cyan, serviceName)
				if representativePort != nil && representativePort.Service.Version != "" {
					serviceHeader += fmt.Sprintf(" v%s", representativePort.Service.Version)
				}
				fmt.Printf("%s%s\n", serviceHeader, output.Reset)

				// List individual ports
				for _, port := range portsForService {
					// Only green for open
					color := output.Green
					stateLabel := " (open)" // Explicitly state open

					portLine := fmt.Sprintf("%s      - %d/%s%s", color, port.PortNumber, port.Protocol, stateLabel)

					extraDetails := []string{}
					for k, v := range port.Details {
						if k != "banner" && k != "os" { 
							extraDetails = append(extraDetails, fmt.Sprintf("%s: %s", k, v))
						}
					}
					if len(extraDetails) > 0 {
						portLine += fmt.Sprintf(" %s(%s)", output.Reset, strings.Join(extraDetails, ", "))
					}
					fmt.Printf("%s%s\n", portLine, output.Reset)
				}
			}
		} else {
			fmt.Printf("\n%s  No open ports to display details for.%s\n", output.Yellow, output.Reset)
		}
	}
	fmt.Printf("\n%s==================================================%s\n", output.Green, output.Reset)
	fmt.Printf("%sScan Duration: %s%s\n", output.Cyan, scanDuration.Round(time.Millisecond), output.Reset)
	fmt.Printf("%s                 Scan Completed                 %s\n", output.Green, output.Reset)
	fmt.Printf("%s==================================================%s\n", output.Green, output.Reset)
}

// convertCoreHostToProto (same as before)
// sanitizeString ensures the string is valid UTF-8 by replacing invalid bytes.
func sanitizeString(s string) string {
	return strings.ToValidUTF8(s, "")
}

func convertCoreHostToProto(cHost *models.Host) *rp.Host {
	sanitizedHostDetails := make(map[string]string)
	for k, v := range cHost.Details {
		sanitizedHostDetails[sanitizeString(k)] = sanitizeString(v)
	}
	
	// Add TTL for OS fingerprinting if available
	if cHost.TTL > 0 {
		sanitizedHostDetails["ttl"] = fmt.Sprintf("%d", cHost.TTL)
	}

	pHost := &rp.Host{
		Id:        cHost.ID,
		IpAddress: cHost.IPAddress.String(),
		IsUp:      cHost.IsUp,
		Details:   sanitizedHostDetails,
	}
	for _, cPort := range cHost.Ports {
		pPort := &rp.Port{
			PortNumber: int32(cPort.PortNumber),
			Protocol:   cPort.Protocol,
			IsOpen:     (cPort.State == models.PortOpen || cPort.State == models.PortOpenFiltered),
			Details:    func() map[string]string {
				m := make(map[string]string)
				for k, v := range cPort.Details {
					m[sanitizeString(k)] = sanitizeString(v)
				}
				// Inject core fields into details for Python context
				m["state"] = sanitizeString(string(cPort.State))
				m["reason"] = sanitizeString(cPort.Reason)
				return m
			}(),
			Service: &rp.Service{
				Name:    sanitizeString(cPort.Service.Name),
				Version: sanitizeString(cPort.Service.Version),
				Details: func() map[string]string {
					m := make(map[string]string)
					for k, v := range cPort.Service.Details {
						m[sanitizeString(k)] = sanitizeString(v)
					}
					return m
				}(),
			},
		}
		pHost.Ports = append(pHost.Ports, pPort)
	}
	return pHost
}

// resolveTargets resolves target strings (IPs, CIDRs, hostnames) into a slice of unique net.IP addresses.
func (o *Controller) resolveTargets(targets []string) ([]net.IP, error) {
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

// inc increments an IP address (used for iterating through CIDR ranges).
func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}
// checkPythonAvailability checks for bundled python first, then system python
func checkPythonAvailability() (string, bool) {
	// 1. Check for Bundled Python ("./python/python.exe" or "./python/bin/python3")
	// Use relative path from CWD (where revealr.exe is running)
	
	// Windows Bundle Check
	bundledWin := "python" + string(os.PathSeparator) + "python.exe"
	if _, err := os.Stat(bundledWin); err == nil {
		// Run a quick version check to be sure
		cmd := exec.Command(bundledWin, "--version")
		if err := cmd.Run(); err == nil {
			return bundledWin, true
		}
	}

	// Linux/Mac Bundle Check (standard python structure often has bin/)
	bundledNix := "python" + string(os.PathSeparator) + "bin" + string(os.PathSeparator) + "python3"
	if _, err := os.Stat(bundledNix); err == nil {
		cmd := exec.Command(bundledNix, "--version")
		if err := cmd.Run(); err == nil {
			return bundledNix, true
		}
	}
	
	// Linux/Mac Bundle Check (root folder variant)
	bundledNixSimple := "python" + string(os.PathSeparator) + "python3"
	if _, err := os.Stat(bundledNixSimple); err == nil {
		cmd := exec.Command(bundledNixSimple, "--version")
		if err := cmd.Run(); err == nil {
			return bundledNixSimple, true
		}
	}

	// 2. Fallback to System Python
	cmd := exec.Command("python", "--version")
	if err := cmd.Run(); err == nil {
		return "python", true
	}

	// 3. Fallback to python3 (common on Linux)
	cmd3 := exec.Command("python3", "--version")
	if err := cmd3.Run(); err == nil {
		return "python3", true
	}

	return "", false
}
