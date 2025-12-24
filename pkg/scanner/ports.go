// pkg/scanner/ports.go
package scanner

import (
	"bytes"
	"context"
	"encoding/binary" // For binary.BigEndian
	"fmt"
	"net"     // For os.Getpid()
	"strings" // For string manipulation in service detection
	"sync"
	"time"

	"revealr/internal/utils" // For GetRandomEphemeralPort, GetLocalIPv4, FindActiveDevice
	"revealr/pkg/models" // Import models
	"revealr/pkg/output"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers" // Explicitly import layers for types and constants
	"github.com/google/gopacket/pcap"   // For icmp.Message types
	"golang.org/x/net/ipv4"             // For ipv4.ICMPTypeDestinationUnreachable, ipv4.ParseHeader
)

// Define IPv4FixedHeaderLen as a constant (20 bytes for standard IPv4 header).
const IPv4FixedHeaderLen = 20

// Custom TCPFlags type (uint8) and associated constants.
type CustomTCPFlags uint8

const (
	CustomTCPFlagFIN CustomTCPFlags = 0x01 // FIN flag
	CustomTCPFlagSYN CustomTCPFlags = 0x02 // SYN flag
	CustomTCPFlagRST CustomTCPFlags = 0x04 // RST flag
	CustomTCPFlagPSH CustomTCPFlags = 0x08 // PSH flag
	CustomTCPFlagACK CustomTCPFlags = 0x10 // ACK flag
	CustomTCPFlagURG CustomTCPFlags = 0x20 // URG flag
	CustomTCPFlagECE CustomTCPFlags = 0x40 // ECE flag
	CustomTCPFlagCWR CustomTCPFlags = 0x80 // CWR flag
	// CustomTCPFlagNS is removed as it overflows uint8 and is typically handled as a separate boolean field in layers.TCP.
	CustomTCPFlagXmas CustomTCPFlags = CustomTCPFlagFIN | CustomTCPFlagPSH | CustomTCPFlagURG // Common Xmas scan flags
)

// Define custom ICMP Code constant (Port Unreachable)
const ICMPv4CodePortUnreachable = 3 // Code for Port Unreachable in ICMP Destination Unreachable (uint8)

// PortScanner manages port scanning operations.
type PortScanner struct {
	config  *PortScannerConfig
	localIP net.IP
	srcMAC  net.HardwareAddr
	dstMAC  net.HardwareAddr // Default Gateway MAC or specific target MAC
	linkType layers.LinkType

	handle         *pcap.Handle
	packetSource   *gopacket.PacketSource
	packetChan     chan gopacket.Packet
	mu             sync.Mutex
	listenerCtx    context.Context
	listenerCancel context.CancelFunc
	listenerWG     sync.WaitGroup

	correlationMap sync.Map

	// NEW: Semaphore to limit active network connections
	workerSemaphore chan struct{}
}

// PortScannerConfig holds specific configurations for port scanning.
type PortScannerConfig struct {
	ScanMode    string        // "connect", "syn", "fin", "xmas", "null", "ack", "window", "maimon", "udp"
	Timeout     time.Duration // Timeout per port
	Concurrency int           // Max concurrent operations
}

// NewPortScanner creates a new PortScanner instance.
// It initializes a PCAP handle if any raw mode is selected.
// Requires root/administrator privileges for raw socket modes.
func NewPortScanner(cfg *PortScannerConfig) (*PortScanner, error) {
	ps := &PortScanner{
		config: cfg,
		// Initialize the semaphore. Its buffer size limits concurrent network ops.
		// Using cfg.Concurrency as the limit.
		workerSemaphore: make(chan struct{}, cfg.Concurrency),
	}

	if cfg.ScanMode != "connect" {
		// Use FindActiveDevice to get the interface AND its bound IP.
		// This guarantees we listen on the same interface we claim to send from.
		deviceName, deviceIP, deviceMAC, err := utils.FindActiveDevice()
		if err != nil {
			return nil, fmt.Errorf("failed to find active network device for raw scanning: %w", err)
		}
		ps.localIP = deviceIP
		ps.srcMAC = deviceMAC

		// Get Gateway MAC for Ethernet framing (Critical for Windows/Npcap)
		gatewayIP, err := utils.GetGatewayIP()
		if err == nil {
			// Trigger ARP
			func() {
				conn, _ := net.DialTimeout("udp", fmt.Sprintf("%s:53", gatewayIP.String()), 200*time.Millisecond)
				if conn != nil {
					conn.Close()
				}
			}()
			
			gwMAC, err := utils.GetMacAddress(gatewayIP)
			if err == nil {
				ps.dstMAC = gwMAC
				output.PrintDebug("Resolved Gateway %s MAC: %s", gatewayIP, gwMAC)
			} else {
				output.PrintDebug("Could not resolve Gateway MAC: %v", err)
			}
		} else {
			output.PrintDebug("Could not determine Gateway IP: %v", err)
		}

		// Open PCAP handle on the selected device. Promiscuous mode enabled.
		handle, err := pcap.OpenLive(deviceName, 65535, true, pcap.BlockForever)
		if err != nil {
			output.PrintError("Failed to open pcap handle on device '%s': %v. (Requires root/admin privileges for raw scan modes)", deviceName, err)
			return nil, fmt.Errorf("failed to open pcap handle: %w", err)
		}
		ps.handle = handle
		ps.linkType = handle.LinkType()

		// Set BPF Filter to reduce noise (only TCP for now, since we key on TCP)
		// if err := handle.SetBPFFilter("tcp"); err != nil {
		// 	output.PrintDebug("Failed to set BPF filter: %v", err)
		// }

		ps.listenerCtx, ps.listenerCancel = context.WithCancel(context.Background())
		ps.packetChan = make(chan gopacket.Packet, 10000)
		ps.packetSource = gopacket.NewPacketSource(ps.handle, ps.handle.LinkType())

		ps.startPacketListener()

		output.PrintInfo("Using device: %s (%s) for raw port scanning (%s mode). LinkType: %v", deviceName, ps.localIP.String(), ps.config.ScanMode, ps.linkType)
	}

	return ps, nil
}


// Close cleans up raw socket listener and pcap handle.
func (ps *PortScanner) Close() {
	if ps.listenerCancel != nil {
		ps.listenerCancel()
		ps.listenerWG.Wait()
	}
	if ps.handle != nil {
		ps.handle.Close()
	}
}

// startPacketListener starts a goroutine to read packets from the pcap handle.
func (ps *PortScanner) startPacketListener() {
	ps.listenerWG.Add(1)
	go func() {
		defer ps.listenerWG.Done()
		defer close(ps.packetChan)

		output.PrintDebug("Packet listener started on interface.")

		for {
			select {
			case <-ps.listenerCtx.Done():
				return
			case packet, ok := <-ps.packetSource.Packets():
				if !ok {
					output.PrintDebug("Packet source closed.")
					return
				}
				// DEBUG: Log that we physically captured bytes
				// output.PrintDebug("PCAP CAPTURE: Packet len=%d", len(packet.Data()))
				
				ps.dispatchPacket(packet)

				select {
				case ps.packetChan <- packet:
				case <-ps.listenerCtx.Done():
					return
				default:
					// Drop if channel is full, or implement a blocking send if all packets must be processed.
					// For scanning, dropping is usually acceptable for performance if overwhelmed.
				}
			}
		}
	}()
}

// dispatchPacket routes incoming packets to the correct waiting goroutine based on correlation.
func (ps *PortScanner) dispatchPacket(packet gopacket.Packet) {
	// TCP Packet Dispatch
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip4 := ipLayer.(*layers.IPv4)
			
			// Key format: TCP:RemoteIP:RemotePort:LocalPort
			// Normalize IP same as sender
			srcIPStr := ip4.SrcIP.String()
			if srcIP4 := ip4.SrcIP.To4(); srcIP4 != nil {
				srcIPStr = srcIP4.String()
			}
			key := fmt.Sprintf("TCP:%s:%d:%d", srcIPStr, uint16(tcp.SrcPort), uint16(tcp.DstPort))
			
			// DEBUG: Print only INCOMING packets destined for us
			if ip4.DstIP.Equal(ps.localIP) {
				// Only log SYN-ACK (0x12) or RST (0x04) or RST-ACK (0x14)
				// This filters out PSH, ACK, FIN background noise
				if tcp.SYN && tcp.ACK || tcp.RST {
					output.PrintDebug("Packet RX: %s:%d -> %s:%d [%s] | Key: %s", ip4.SrcIP, tcp.SrcPort, ip4.DstIP, tcp.DstPort, getTCPFlagsString(tcp), key)
				}
			}

			if ch, loaded := ps.correlationMap.Load(key); loaded {
				output.PrintDebug("  MATCH! Key found. Dispatching to channel.")
				select {
				case ch.(chan gopacket.Packet) <- packet:
				default:
					output.PrintDebug("  Channel full, dropping packet.")
				}
			} else {
				// Only print "No match" if it was strictly destined for us and relevant, to avoid spam
				if ip4.DstIP.Equal(ps.localIP) && (tcp.SYN && tcp.ACK || tcp.RST) {
					output.PrintDebug("  No match for key: '%s'", key)
				}
			}
		}
	}

	// ICMP Packet Dispatch (for UDP scan responses: Port Unreachable)
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp4 := icmpLayer.(*layers.ICMPv4)
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip4 := ipLayer.(*layers.IPv4)

			// Correct way to compare ICMP Type and Code
			if icmp4.TypeCode.Type() == layers.ICMPv4TypeDestinationUnreachable && icmp4.TypeCode.Code() == ICMPv4CodePortUnreachable {
				if len(icmp4.Payload) >= IPv4FixedHeaderLen+8 {
					originalIPHeader := icmp4.Payload[:IPv4FixedHeaderLen]
					originalUDPHeader := icmp4.Payload[IPv4FixedHeaderLen : IPv4FixedHeaderLen+8]

					origIPHdr, err := ipv4.ParseHeader(originalIPHeader)
					if err != nil {
						output.PrintDebug("Failed to parse original IP header in ICMP payload: %v", err)
						return
					}

					if origIPHdr.Dst.Equal(ps.localIP) && origIPHdr.Src.Equal(ip4.SrcIP) &&
						origIPHdr.Protocol == int(layers.IPProtocolUDP) {

						originalDstPort := binary.BigEndian.Uint16(originalUDPHeader[2:4])
						originalSrcPort := binary.BigEndian.Uint16(originalUDPHeader[0:2])

						key := fmt.Sprintf("UDP_ICMP:%s:%d:%d", origIPHdr.Src.String(), originalDstPort, originalSrcPort)
						if ch, loaded := ps.correlationMap.Load(key); loaded {
							select {
							case ch.(chan gopacket.Packet) <- packet:
							default:
								// Channel full, drop packet
							}
						}
					}
				}
			}
		}
	}
}

// ScanPorts performs port scanning on a given host for a list of ports.
func (ps *PortScanner) ScanPorts(ctx context.Context, host *models.Host, ports []int) {
	output.PrintInfo("Starting %s scan for %s on %d ports...", ps.config.ScanMode, host.IPAddress.String(), len(ports))

	var wg sync.WaitGroup
	portQueue := make(chan int, ps.config.Concurrency*2) // Buffered channel for ports to scan (allows more tasks than workers)
	resultsChan := make(chan *models.Port, len(ports))     // Channel to collect results from workers

	// Start a goroutine to collect and process results as they come in.
	go func() {
		processedCount := 0
		totalPorts := len(ports)
		for p := range resultsChan {
			processedCount++
			
			// Nmap Logic: Only "Interesting" ports (Open, Open|Filtered) are stored and reported.
			// Closed and Filtered are aggregated.
			if p.State == models.PortFiltered {
				// host.FilteredCount++ (Need to add this field to Host model if we want to track it)
				// For now, just don't add to Host.Ports
			} else if p.State == models.PortClosed {
				// host.ClosedCount++
			} else {
				// Open or Open|Filtered
				if host.AddPort(p) { 
					if p.State == models.PortOpen {
						output.PrintOpenPort(host.IPAddress.String(), p.Protocol, p.PortNumber, p.Service.Name)
					}
				}
			}
			output.PrintPortScanProgress(host.ID, processedCount, totalPorts) // Update live progress
		}
		if processedCount > 0 {
			output.PrintPortScanProgress(host.ID, processedCount, totalPorts) // Force final print to ensure newline
		}
	}()

	// Start worker goroutines. These workers will pull ports from `portQueue`.
	// The number of these goroutines is fixed by `ps.config.Concurrency`, but
	// the *actual network operations* will be further limited by the semaphore.
	for i := 0; i < ps.config.Concurrency; i++ { // These are dispatchers
		wg.Add(1)
		go func() {
			defer wg.Done()
			for portNum := range portQueue { // Loop until portQueue is closed
				select {
				case <-ctx.Done():
					return // If context is cancelled, stop this worker.
				default:
						isPortOpen := models.PortClosed
						var serviceName string
					var protocolUsed string
					var rawBanner string
					var reason string // NEW: explicitly track reason

					// Acquire a token from the semaphore before performing network I/O
					ps.workerSemaphore <- struct{}{} // Block until a slot is available

					// Perform scan based on mode
					switch ps.config.ScanMode {
					case "connect":
						protocolUsed = "tcp"
						isPortOpen, serviceName, rawBanner = ps.tcpConnectScan(host.IPAddress, portNum)
						reason = "syn-ack"
					case "syn":
						protocolUsed = "tcp"
						isPortOpen, serviceName = ps.synScan(host.IPAddress, portNum)
						rawBanner = ""
						if isPortOpen == models.PortOpen {
							reason = "syn-ack"
						} else if isPortOpen == models.PortFiltered {
							reason = "no-response"
						} else {
							reason = "rst"
						}
					case "fin":
						protocolUsed = "tcp"
						isPortOpen, reason = ps.tcpFlagScan(host.IPAddress, portNum, CustomTCPFlagFIN)
						rawBanner = ""
					case "null":
						protocolUsed = "tcp"
						isPortOpen, reason = ps.tcpFlagScan(host.IPAddress, portNum, 0)
						rawBanner = ""
					case "xmas":
						protocolUsed = "tcp"
						isPortOpen, reason = ps.tcpFlagScan(host.IPAddress, portNum, CustomTCPFlagXmas)
						rawBanner = ""
					case "ack":
						protocolUsed = "tcp"
						isPortOpen, reason = ps.tcpAckScan(host.IPAddress, portNum)
						rawBanner = ""
					case "window":
						protocolUsed = "tcp"
						isPortOpen, reason = ps.tcpWindowScan(host.IPAddress, portNum)
						rawBanner = ""
					case "maimon":
						protocolUsed = "tcp"
						isPortOpen, reason = ps.tcpMaimonScan(host.IPAddress, portNum)
						rawBanner = ""
					case "udp":
						protocolUsed = "udp"
						isPortOpen, serviceName = ps.udpScan(host.IPAddress, portNum)
						rawBanner = ""
						reason = "udp-response"
					default:
						output.PrintError("Unknown scan mode: %s", ps.config.ScanMode)
						// Release token on unknown mode path
						<-ps.workerSemaphore
						return
					}

					// Release the token back to the semaphore after network I/O is done
					<-ps.workerSemaphore

					// Create a new Port object with the scan result
					// Only save if Open or Open|Filtered (ambiguous).
					// Purely Filtered/Closed ports are dropped to save memory/processing, unless verbose (not impl yet).
					if isPortOpen == models.PortOpen || isPortOpen == models.PortOpenFiltered {
						port := models.NewPort(portNum, protocolUsed)
						port.State = isPortOpen
						port.Reason = reason // NEW: Save reason
						if serviceName != "" {
							port.Service.Name = serviceName
						} else if isPortOpen == models.PortOpen {
							// Only infer service name from port number if the port is explicitly OPEN.
							port.Service.Name = inferServiceFromPort(portNum, protocolUsed)
						}
						
						if rawBanner != "" {
							port.Details["banner"] = rawBanner
						}
						resultsChan <- port
					} else if isPortOpen == models.PortFiltered {
						// Just track the count, don't generate a Port object
						// Ideally we'd atomic increment a counter on Host, but we are in a worker.
						// We can send a special "nil" or "stat-only" update to resultsChan?
						// Or just let the caller handle the missing ports as filtered?
						// Nmap style: Total - Open - Closed = Filtered.
						// We will just NOT send it. The Orchestrator can calculate Filtered = TotalScanned - Open - Closed.
						// Wait, if we return nothing, how does progress bar update?
						// We need to signal "done".
						// Let's send a dummy port with state "Ignored" or just re-use Filtered but filter it out in the *receiver* goroutine?
						// Better: Send it to resultsChan, but the RECEIVER goroutine inside ScanPorts decides whether to add it to Host.
						
						// Sending stripped down port for counting
						port := models.NewPort(portNum, protocolUsed)
						port.State = models.PortFiltered
						port.Reason = reason
						resultsChan <- port
					} else {
						// Closed ports
						port := models.NewPort(portNum, protocolUsed)
						port.State = models.PortClosed
						port.Reason = reason
						resultsChan <- port
					}
				}
			}
		}()
	}

	// Feed ports into the `portQueue` for workers to pick up.
	for _, p := range ports {
		portQueue <- p
	}
	close(portQueue)

	wg.Wait()
	close(resultsChan)

	output.PrintSuccess("Port scan for %s completed.", host.IPAddress.String())
}

// tcpConnectScan (no change in signature, but now implicitly bounded by semaphore in ScanPorts)
// The function remains the same, but its calls are now controlled by the semaphore.
// tcpConnectScan performs a full TCP connect scan using standard library `net.DialTimeout`.
// Now returns rawBanner string
func (ps *PortScanner) tcpConnectScan(ip net.IP, port int) (models.PortState, string, string) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	// Retry logic for timeouts (Step 2: 2 retries with jitter)
	var conn net.Conn
	var err error
	maxRetries := 2

	for i := 0; i <= maxRetries; i++ {
		// Add small backoff/jitter for retries
		if i > 0 {
			time.Sleep(time.Duration(50*i) * time.Millisecond)
		}

		conn, err = net.DialTimeout("tcp", addr, ps.config.Timeout)
		if err == nil {
			break // Connection successful
		}

		// Check for RST (Step 1: "connection refused" = CLOSED)
		if strings.Contains(err.Error(), "connection refused") {
			return models.PortClosed, "", ""
		}

		// Check for Timeout
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if i == maxRetries {
				// Final timeout after retries -> Open|Filtered (ambiguous)
				return models.PortOpenFiltered, "", ""
			}
			continue // Retry
		}

		// Other errors (e.g. no route to host) -> Closed (or Filtered, but usually treated as Closed for connect scan)
		return models.PortClosed, "", ""
	}
	defer conn.Close()

	// Attempt a larger banner grab.
	conn.SetReadDeadline(time.Now().Add(time.Millisecond * 500)) // Set a short deadline for reading the banner.
	buffer := make([]byte, 4096)                                 // Increased buffer size for banner grabbing
	n, err := conn.Read(buffer)
	var rawBanner string
	if err == nil {
		rawBanner = string(bytes.TrimSpace(buffer[:n]))
		// Implement basic HTTP probing here if port is common web port and banner is not clear
		if (port == 80 || port == 8080 || port == 443 || port == 8000 || port == 8081) && !strings.Contains(strings.ToLower(rawBanner), "http/") {
			// Try sending an HTTP OPTIONS request for a quick, non-disruptive probe
			httpReq := "OPTIONS / HTTP/1.0\r\nHost: " + ip.String() + "\r\nUser-Agent: Revealr/1.0\r\n\r\n"
			conn.SetWriteDeadline(time.Now().Add(ps.config.Timeout))
			_, writeErr := conn.Write([]byte(httpReq))
			if writeErr == nil {
				conn.SetReadDeadline(time.Now().Add(ps.config.Timeout))
				httpRespBuffer := make([]byte, 4096)
				m, readErr := conn.Read(httpRespBuffer)
				if readErr == nil {
					httpResponse := string(bytes.TrimSpace(httpRespBuffer[:m]))
					if strings.HasPrefix(strings.ToLower(httpResponse), "http/") || strings.Contains(strings.ToLower(httpResponse), "server:") {
						return models.PortOpen, inferServiceFromBanner(port, httpResponse, "tcp"), httpResponse // Use HTTP response as banner
					}
				}
			}
		}
		return models.PortOpen, inferServiceFromBanner(port, rawBanner, "tcp"), rawBanner
	}
	return models.PortOpen, inferServiceFromPort(port, "tcp"), "" // Port is open, but no banner or read error
}

// Helper to send a raw TCP packet and wait for a response.
// Returns the received packet or nil if timeout/error.
// tcpFlags: a bitmask using CustomTCPFlags constants (e.g., CustomTCPFlagSYN | CustomTCPFlagACK)
func (ps *PortScanner) sendRawTCPAndListen(dstIP net.IP, dstPort int, tcpFlags CustomTCPFlags, payload []byte) gopacket.Packet {
	if ps.handle == nil {
		output.PrintError("PCAP handle not initialized for raw scan. Cannot send raw TCP packet.")
		return nil
	}

	// Bind a dummy listener to 'reserve' the port and ensure local Firewall allows the response
	// The OS will see this port as 'active' and should allow the incoming SYN-ACK.
	dummyListener, err := net.Listen("tcp", fmt.Sprintf("%s:0", ps.localIP.String()))
	if err != nil {
		// Fallback to "0.0.0.0" if localIP bind fails
		dummyListener, err = net.Listen("tcp", ":0")
	}
	
	var srcPort int
	if err != nil {
		output.PrintDebug("Failed to bind dummy listener: %v. Using random port (might be blocked by firewall).", err)
		srcPort = int(utils.GetRandomEphemeralPort())
	} else {
		defer dummyListener.Close()
		addr := dummyListener.Addr().(*net.TCPAddr)
		srcPort = addr.Port
		// output.PrintDebug("Bound dummy listener on port %d to permit inbound traffic.", srcPort)
	}

	// srcPort := utils.GetRandomEphemeralPort() // Replaced by above logic
	seq := utils.GetRandomEphemeralPort()

	ipLayer := &layers.IPv4{
		SrcIP:    ps.localIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
		TTL:      64,
		Id:       utils.GetRandomEphemeralPort(),
		Flags:    layers.IPv4DontFragment,
	}

	// Use the struct literal directly and assign boolean flags based on tcpFlags bitmask
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     uint32(seq),
		Window:  14600,
		DataOffset: 5, // CRITICAL: Min TCP header length (5 * 4 = 20 bytes)
		// Assign individual boolean flags based on the tcpFlags bitmask
		FIN: (tcpFlags & CustomTCPFlagFIN) != 0,
		SYN: (tcpFlags & CustomTCPFlagSYN) != 0,
		RST: (tcpFlags & CustomTCPFlagRST) != 0,
		PSH: (tcpFlags & CustomTCPFlagPSH) != 0,
		ACK: (tcpFlags & CustomTCPFlagACK) != 0,
		URG: (tcpFlags & CustomTCPFlagURG) != 0,
		ECE: (tcpFlags & CustomTCPFlagECE) != 0,
		CWR: (tcpFlags & CustomTCPFlagCWR) != 0,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Determine Layers for Serialization
	var layersToSerialize []gopacket.SerializableLayer

	if ps.linkType == layers.LinkTypeEthernet {
		if ps.srcMAC == nil || ps.dstMAC == nil {
			output.PrintDebug("Cannot construct Ethernet frame: Missing SrcMAC or DstMAC (Gateway). LinkType is Ethernet.")
			return nil
		}
		ethLayer := &layers.Ethernet{
			SrcMAC:       ps.srcMAC,
			DstMAC:       ps.dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}
		layersToSerialize = append(layersToSerialize, ethLayer)
	}

	layersToSerialize = append(layersToSerialize, ipLayer, tcpLayer, gopacket.Payload(payload))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(buf, opts, layersToSerialize...)
	if err != nil {
		output.PrintDebug("Failed to serialize layers: %v", err)
		return nil
	}
	outgoingPacket := buf.Bytes()

	// Use a buffered channel to prevent blocking if multiple packets arrive (e.g. retransmissions)
	responseChan := make(chan gopacket.Packet, 5)

	// Normalize IP for key generation to avoid IPv4 vs IPv6-mapped mismatches
	ipStr := dstIP.String()
	if ip4 := dstIP.To4(); ip4 != nil {
		ipStr = ip4.String()
	}
	
	// FIX: Use Source Port in correlation key to handle concurrent scans and retries cleanly.
	// We rely on the Dummy Listener (which we bound) to keep the OS port consistent.
	key := fmt.Sprintf("TCP:%s:%d:%d", ipStr, dstPort, srcPort)
	
	// Safety check: Don't overwrite an existing probe for this exact tuple.
	if _, loaded := ps.correlationMap.Load(key); loaded {
		// Output debug? 
		// output.PrintDebug("  Key collision %s, skipping duplicate probe.", key)
		return nil 
	}
	
	ps.correlationMap.Store(key, responseChan)
	defer ps.correlationMap.Delete(key)

	// DEBUG: Log Outgoing Packet Details and Key
	output.PrintDebug("Packet TX: %s:%d -> %s:%d (Flags: %v) | Seq: %d", ps.localIP, srcPort, dstIP, dstPort, tcpFlags, seq)
	output.PrintDebug("  -> Stored Key: '%s'", key)
	
	ps.mu.Lock()
	err = ps.handle.WritePacketData(outgoingPacket)
	ps.mu.Unlock()

	if err != nil {
		output.PrintDebug("Failed to send raw TCP packet to %s:%d (flags %v): %v", dstIP.String(), dstPort, tcpFlags, err)
		return nil
	}

	// TIMEOUT INCREASED FOR DEBUGGING
	ctxTimeout, cancelTimeout := context.WithTimeout(context.Background(), 2*time.Second) 
	defer cancelTimeout()

	for {
		select {
		case packet := <-responseChan:
			// We trust the correlation logic (IP:Port) to route packets correctly.
			// Strict ACK checking is prone to failure with SYN cookies / middleboxes.
			return packet
		case <-ctxTimeout.Done():
			return nil
		}
	}
}

// synScan performs a TCP SYN scan using gopacket.
func (ps *PortScanner) synScan(dstIP net.IP, dstPort int) (models.PortState, string) {
	// Send SYN once. No retries to avoid source port cycling/correlation mismatches.
	// If packet loss is a concern, we should implement stable source-port reuse, but for now 1-shot is cleaner.
	packet := ps.sendRawTCPAndListen(dstIP, dstPort, CustomTCPFlagSYN, nil)
	
	if packet == nil {
		return models.PortFiltered, "" // No response = filtered
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return models.PortFiltered, "" // Cannot parse TCP = likely filtered/garbage
	}
	tcp := tcpLayer.(*layers.TCP)

	if tcp.SYN && tcp.ACK { // SYN-ACK: Port is open
		// Send RST to close the connection immediately (stealthy / polite)
		// We don't wait for a response to the RST, so we ignore the return.
		go ps.sendRawTCPAndListen(dstIP, dstPort, CustomTCPFlagRST, nil)
		return models.PortOpen, "" // Do not infer service from banner in SYN scan
	} else if tcp.RST { // RST: Port is closed
		return models.PortClosed, ""
	}
	return models.PortFiltered, "" // No conclusive response
}

// tcpFlagScan sends a TCP packet with specific flags (FIN, NULL, Xmas)
// Open: No response
// Closed: RST response
// tcpFlagScan sends a TCP packet with specific flags (FIN, NULL, Xmas)
// Open|Filtered: No response
// Closed: RST response
func (ps *PortScanner) tcpFlagScan(dstIP net.IP, dstPort int, flags CustomTCPFlags) (models.PortState, string) {
	packet := ps.sendRawTCPAndListen(dstIP, dstPort, flags, nil)
	if packet == nil {
		// No response means Open or Filtered (firewall dropped it or port is open and ignored it)
		// This is the correct semantics for FIN/NULL/Xmas scans.
		return models.PortOpenFiltered, inferServiceFromPort(dstPort, "tcp")
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return models.PortFiltered, ""
	}
	tcp := tcpLayer.(*layers.TCP)

	if tcp.RST { // RST: Port is CLOSED
		return models.PortClosed, ""
	}
	return models.PortFiltered, "" // Unexpected response
}

// tcpAckScan sends a TCP ACK packet. Primarily for firewall rule mapping.
// Unfiltered: RST (if port closed) or ACK (if port open, or if firewall responds)
// Filtered: No response
// tcpAckScan sends a TCP ACK packet. Prioritizes firewall rule mapping.
// Returns Unfiltered, Filtered, or Closed based on RST vs No Response.
func (ps *PortScanner) tcpAckScan(dstIP net.IP, dstPort int) (models.PortState, string) {
	packet := ps.sendRawTCPAndListen(dstIP, dstPort, CustomTCPFlagACK, nil)
	if packet == nil {
		return models.PortFiltered, "filtered (no-response)"
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return models.PortFiltered, ""
	}
	tcp := tcpLayer.(*layers.TCP)

	if tcp.RST {
		// RST means the port is reachable (unfiltered), but closed or open.
		// ACK scan doesn't determine open/closed, just filtered/unfiltered.
		// We map "unfiltered" to "closed" for simplicity in this context, or better, introduce PortUnfiltered.
		// For now, sticking to PortClosed as "reachable but not open-confirmed".
		return models.PortClosed, "unfiltered (rst)"
	}
	return models.PortFiltered, "filtered (other)"
}

// tcpWindowScan sends a TCP ACK packet and examines the Window field in the reply.
// Open: Non-zero window size
// Closed: Zero window size (RST)
// Filtered: No response
// tcpWindowScan sends a TCP ACK packet and examines the Window field.
func (ps *PortScanner) tcpWindowScan(dstIP net.IP, dstPort int) (models.PortState, string) {
	packet := ps.sendRawTCPAndListen(dstIP, dstPort, CustomTCPFlagACK, nil)
	if packet == nil {
		return models.PortFiltered, "filtered (no-response)"
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return models.PortFiltered, ""
	}
	tcp := tcpLayer.(*layers.TCP)

	if tcp.RST {
		if tcp.Window > 0 {
			return models.PortOpen, inferServiceFromBanner(dstPort, "", "tcp") 
		} else {
			return models.PortClosed, "closed (rst-win0)"
		}
	}
	return models.PortFiltered, "filtered (other)"
}

// tcpMaimonScan sends FIN/ACK packet.
// Open/Filtered: No response
// Closed: RST
// tcpMaimonScan sends FIN/ACK packet.
func (ps *PortScanner) tcpMaimonScan(dstIP net.IP, dstPort int) (models.PortState, string) {
	packet := ps.sendRawTCPAndListen(dstIP, dstPort, CustomTCPFlagFIN|CustomTCPFlagACK, nil)
	if packet == nil {
		return models.PortOpenFiltered, inferServiceFromPort(dstPort, "tcp")
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return models.PortFiltered, ""
	}
	tcp := tcpLayer.(*layers.TCP)

	if tcp.RST {
		return models.PortClosed, "closed (rst)"
	}
	return models.PortFiltered, "filtered"
}

// udpScan performs a UDP scan.
// It sends a UDP packet and listens for an ICMP Port Unreachable message to detect closed ports.
// Requires root privileges for pcap handle.
// udpScan performs a UDP scan.
// It sends a UDP packet and listens for an ICMP Port Unreachable message to detect closed ports.
// Requires root privileges for pcap handle.
// udpScan performs a UDP scan.
// It sends a UDP packet and listens for an ICMP Port Unreachable message to detect closed ports.
// Requires root privileges for pcap handle.
func (ps *PortScanner) udpScan(ip net.IP, port int) (models.PortState, string) {
	if ps.handle == nil {
		output.PrintError("PCAP handle not initialized for UDP scan. UDP closed detection may be unreliable. (Requires root/admin)")
		conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: port})
		if err != nil {
			return models.PortClosed, ""
		}
		defer conn.Close()
		conn.SetWriteDeadline(time.Now().Add(ps.config.Timeout))
		_, err = conn.Write([]byte("."))
		if err != nil {
			return models.PortClosed, ""
		}
		// FIX: Pass "udp" as the protocol
		return models.PortOpen, inferServiceFromPort(port, "udp")
	}

	srcPort := utils.GetRandomEphemeralPort()

	ipLayer := &layers.IPv4{
		SrcIP:    ps.localIP,
		DstIP:    ip,
		Protocol: layers.IPProtocolUDP,
		TTL:      64,
		Id:       utils.GetRandomEphemeralPort(),
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(port),
		Length:  8 + 1, // UDP header (8 bytes) + 1 byte payload
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, ipLayer, udpLayer, gopacket.Payload([]byte("U")))
	outgoingPacket := buf.Bytes()

	responseChan := make(chan gopacket.Packet, 1)
	key := fmt.Sprintf("UDP_ICMP:%s:%d:%d", ip.String(), port, srcPort)
	ps.correlationMap.Store(key, responseChan)
	defer ps.correlationMap.Delete(key)

	ps.mu.Lock()
	err := ps.handle.WritePacketData(outgoingPacket)
	ps.mu.Unlock()

	if err != nil {
		output.PrintError("Failed to send UDP packet to %s:%d: %v.", ip.String(), port, err)
		return models.PortClosed, ""
	}

	ctxTimeout, cancel := context.WithTimeout(context.Background(), ps.config.Timeout)
	defer cancel()

	select {
	case packet := <-responseChan:
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
		if icmpLayer != nil {
			icmp4 := icmpLayer.(*layers.ICMPv4)
			// Correct way to compare ICMP TypeCode with specific Type and Code
			if icmp4.TypeCode.Type() == layers.ICMPv4TypeDestinationUnreachable && icmp4.TypeCode.Code() == ICMPv4CodePortUnreachable {
				if len(icmp4.Payload) >= IPv4FixedHeaderLen+8 {
					originalIPHeader := icmp4.Payload[:IPv4FixedHeaderLen]
					originalUDPHeader := icmp4.Payload[IPv4FixedHeaderLen : IPv4FixedHeaderLen+8]

					origIPHdr, err := ipv4.ParseHeader(originalIPHeader)
					if err != nil {
						output.PrintDebug("Failed to parse original IP header in ICMP payload: %v", err)
						return models.PortClosed, ""
					}

					if origIPHdr.Dst.Equal(ps.localIP) && origIPHdr.Src.Equal(ip) &&
						origIPHdr.Protocol == int(layers.IPProtocolUDP) {

						originalDstPort := binary.BigEndian.Uint16(originalUDPHeader[2:4])
						originalSrcPort := binary.BigEndian.Uint16(originalUDPHeader[0:2])

						key := fmt.Sprintf("UDP_ICMP:%s:%d:%d", origIPHdr.Src.String(), originalDstPort, originalSrcPort)
						if ch, loaded := ps.correlationMap.Load(key); loaded {
							select {
							case ch.(chan gopacket.Packet) <- packet:
							default:
								// Channel full, drop packet
							}
						}
					}
				}
			}
		}
	case <-ctxTimeout.Done():
		// Timeout (no ICMP unreachable) means open or filtered.
	}
	// FIX: Pass "udp" as the protocol
	return models.PortOpenFiltered, inferServiceFromPort(port, "udp")
}

// inferServiceFromPort provides a basic service name lookup based on common port numbers.
func inferServiceFromPort(port int, protocol string) string {
	return models.GetLikelyServiceName(port, protocol)
}

// inferServiceFromBanner attempts to guess service from a captured banner string.
// NEW: Enhanced to perform intelligent banner parsing and basic probes.
// inferServiceFromBanner (no change, but the fallback to inferServiceFromPort will be better)
func inferServiceFromBanner(port int, banner string, protocol string) string { // FIX: Added protocol parameter
	cleanBanner := strings.TrimSpace(banner)
	lowerBanner := strings.ToLower(cleanBanner)

	// High-confidence banner matches for Go's initial pass.
	// Everything else is left as "unknown" for Python to figure out.
	if strings.HasPrefix(lowerBanner, "ssh-") {
		return "ssh"
	} else if strings.HasPrefix(lowerBanner, "http/") || strings.Contains(lowerBanner, "server:") || strings.Contains(lowerBanner, "<html>") {
		return "http" // Generic HTTP
	}

	// We intentionally do NOT try to guess other protocols here (FTP, SMTP, etc.) using weak string matching.
	// That is the job of the Intelligence Engine (Python) which has robust probe logic.
	// Returning "unknown" here forces the system to rely on Python, which is safer.
	return "unknown"
}
