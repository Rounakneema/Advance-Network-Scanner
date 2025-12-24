// pkg/scanner/ports.go
package scanner

import (
	"bytes"
	"context"
	"encoding/binary" // For binary.BigEndian
	"fmt"
	"net" // For os.Getpid()
	"sync"
	"time"

	"revealr/internal/utils" // For GetRandomEphemeralPort, GetLocalIPv4, FindActiveDevice
	"revealr/pkg/output"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers" // FIX: Explicitly import layers for all types and constants
	"github.com/google/gopacket/pcap"   // For icmp.Message types
	"golang.org/x/net/ipv4"             // For ipv4.ICMPTypeDestinationUnreachable, ipv4.ParseHeader
)

// Define IPv4FixedHeaderLen as a constant, as layers.IPv4HeaderLen might be version-dependent or causing issues.
// This is the standard IPv4 header length without options.
const IPv4FixedHeaderLen = 20

// PortScanner manages port scanning operations.
type PortScanner struct {
	config  *PortScannerConfig
	localIP net.IP // Local IP for raw packets (auto-detected)

	// PCAP handle for raw packet injection/capture (shared across raw scan types)
	handle         *pcap.Handle
	packetSource   *gopacket.PacketSource // Source to read packets from handle
	packetChan     chan gopacket.Packet   // FIX: Channel type is gopacket.Packet (interface)
	mu             sync.Mutex             // Mutex for pcap handle writes
	listenerCtx    context.Context
	listenerCancel context.CancelFunc
	listenerWG     sync.WaitGroup

	// Map to correlate sent packets with replies (key: uniqueID, value: chan gopacket.Packet)
	correlationMap sync.Map // FIX: Map value is chan gopacket.Packet
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
	}

	if cfg.ScanMode != "connect" {
		localIP, err := utils.GetLocalIPv4() // Uses helper from internal/utils
		if err != nil {
			return nil, fmt.Errorf("failed to get local IPv4 for raw scanning: %w", err)
		}
		ps.localIP = localIP

		deviceName, _, _, err := utils.FindActiveDevice() // Uses helper from internal/utils
		if err != nil {
			return nil, fmt.Errorf("failed to find active network device for raw scanning: %w", err)
		}

		handle, err := pcap.OpenLive(deviceName, 65535, false, pcap.BlockForever)
		if err != nil {
			output.PrintError("Failed to open pcap handle on device '%s': %v. (Requires root/admin privileges for raw scan modes)", deviceName, err)
			return nil, fmt.Errorf("failed to open pcap handle: %w", err)
		}
		ps.handle = handle

		ps.listenerCtx, ps.listenerCancel = context.WithCancel(context.Background())
		ps.packetChan = make(chan gopacket.Packet, 10000) // FIX: Channel type is gopacket.Packet
		ps.packetSource = gopacket.NewPacketSource(ps.handle, ps.handle.LinkType())

		ps.startPacketListener() // Start a goroutine to read from pcap handle

		output.PrintInfo("Using device: %s (%s) for raw port scanning (%s mode).", deviceName, ps.localIP.String(), ps.config.ScanMode)
	}

	return ps, nil
}

// Close cleans up raw socket listener and pcap handle.
func (ps *PortScanner) Close() {
	if ps.listenerCancel != nil {
		ps.listenerCancel()  // Signal listener to stop
		ps.listenerWG.Wait() // Wait for listener goroutine to finish
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
		defer close(ps.packetChan) // Close channel when listener stops

		for {
			select {
			case <-ps.listenerCtx.Done():
				return // Context cancelled, stop reading
			case packet, ok := <-ps.packetSource.Packets(): // packet is gopacket.Packet
				if !ok {
					return // Packet source closed
				}
				ps.dispatchPacket(packet) // Pass the interface directly

				select {
				case ps.packetChan <- packet: // Send interface to channel
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
func (ps *PortScanner) dispatchPacket(packet gopacket.Packet) { // Accepts gopacket.Packet interface
	// TCP Packet Dispatch
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip4 := ipLayer.(*layers.IPv4)

			// The correlation key must match how it's stored in the scan functions (e.g., synScan)
			// Using SrcIP (target), DstPort (our ephemeral port), SrcPort (target's port for reply)
			key := fmt.Sprintf("TCP:%s:%d:%d", ip4.SrcIP.String(), tcp.DstPort, tcp.SrcPort)
			if ch, loaded := ps.correlationMap.Load(key); loaded {
				select {
				case ch.(chan gopacket.Packet) <- packet: // Send gopacket.Packet interface
				default:
					// Channel full, drop packet
				}
			}
		}
	}

	// ICMP Packet Dispatch (for UDP scan responses: Port Unreachable)
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp4 := icmpLayer.(*layers.ICMPv4)
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip4 := ipLayer.(*layers.IPv4)

			// FIX: Correct way to compare ICMP TypeCode with specific Type and Code
			// Compare the actual TypeCode struct value.
			if icmp4.TypeCode == layers.ICMPv4TypeDestinationUnreachable.WithCode(layers.ICMPv4CodePortUnreachable) { // Corrected: Using WithCode with its proper constant.
				// The ICMP payload contains the original IP header + 8 bytes of original packet.
				if len(icmp4.Payload) >= IPv4FixedHeaderLen+8 { // FIX: Using IPv4FixedHeaderLen
					originalIPHeader := icmp4.Payload[:IPv4FixedHeaderLen]
					originalUDPHeader := icmp4.Payload[IPv4FixedHeaderLen : IPv4FixedHeaderLen+8]

					// FIX: Use ipv4.ParseHeader from golang.org/x/net/ipv4 for parsing raw IP header bytes
					origIPHdr, err := ipv4.ParseHeader(originalIPHeader)
					if err != nil {
						output.PrintDebug("Failed to parse original IP header in ICMP payload: %v", err)
						return // Failed to parse original IP header
					}

					// Correlate with our sent UDP packet:
					// Original destination IP (from ICMP payload) should be our local IP.
					// Original source IP (from ICMP payload) should be the target IP.
					// Original protocol should be UDP.
					// Original destination port should match our sent port.
					// Original source port should match our sent ephemeral port.
					if origIPHdr.Dst.Equal(ps.localIP) && origIPHdr.Src.Equal(ip4.SrcIP) && // Corrected: ip4.SrcIP is the actual source of the ICMP (the target)
						origIPHdr.Protocol == layers.IPProtocolUDP { // FIX: Compare int with layers.IPProtocol by casting layers.IPProtocolUDP to int

						originalDstPort := binary.BigEndian.Uint16(originalUDPHeader[2:4])
						originalSrcPort := binary.BigEndian.Uint16(originalUDPHeader[0:2])

						key := fmt.Sprintf("UDP_ICMP:%s:%d:%d", origIPHdr.Src.String(), originalDstPort, originalSrcPort)
						if ch, loaded := ps.correlationMap.Load(key); loaded {
							select {
							case ch.(chan gopacket.Packet) <- packet: // Send gopacket.Packet interface
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

// tcpConnectScan performs a full TCP connect scan using standard library `net.DialTimeout`.
func (ps *PortScanner) tcpConnectScan(ip net.IP, port int) (bool, string) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, ps.config.Timeout)
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(time.Millisecond * 500))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err == nil {
		banner := string(bytes.TrimSpace(buffer[:n]))
		return true, inferServiceFromBanner(banner)
	}
	return true, inferServiceFromPort(port)
}

// Helper to send a raw TCP packet and wait for a response.
// Returns the received packet or nil if timeout/error.
func (ps *PortScanner) sendRawTCPAndListen(dstIP net.IP, dstPort int, tcpFlags layers.TCPFlags, payload []byte) gopacket.Packet { // FIX: Return gopacket.Packet interface
	if ps.handle == nil {
		output.PrintError("PCAP handle not initialized for raw scan. Cannot send raw TCP packet.")
		return nil
	}

	srcPort := utils.GetRandomEphemeralPort()
	seq := utils.GetRandomEphemeralPort()

	ipLayer := &layers.IPv4{
		SrcIP:    ps.localIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
		TTL:      64,
		Id:       utils.GetRandomEphemeralPort(),
		Flags:    layers.IPv4DontFragment,
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     uint32(seq),
		Window:  14600,
	}
	tcpLayer.Flags = tcpFlags // FIX: Set flags directly on the Flags field
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer, gopacket.Payload(payload))
	outgoingPacket := buf.Bytes()

	responseChan := make(chan gopacket.Packet, 1) // FIX: Channel type is gopacket.Packet
	// Correlation key: target IP + target port + our ephemeral source port
	key := fmt.Sprintf("TCP:%s:%d:%d", dstIP.String(), dstPort, srcPort)
	ps.correlationMap.Store(key, responseChan)
	defer ps.correlationMap.Delete(key)

	ps.mu.Lock() // Protect handle writes
	err := ps.handle.WritePacketData(outgoingPacket)
	ps.mu.Unlock()

	if err != nil {
		output.PrintDebug("Failed to send raw TCP packet to %s:%d (flags %v): %v", dstIP.String(), dstPort, tcpFlags, err)
		return nil
	}

	ctxTimeout, cancelTimeout := context.WithTimeout(context.Background(), ps.config.Timeout)
	defer cancelTimeout()

	select {
	case packet := <-responseChan: // Receive gopacket.Packet interface
		return packet // Return the received interface
	case <-ctxTimeout.Done():
		return nil // Timeout
	}
}

// synScan performs a TCP SYN scan using gopacket.
func (ps *PortScanner) synScan(dstIP net.IP, dstPort int) (bool, string) {
	packet := ps.sendRawTCPAndListen(dstIP, dstPort, layers.TCPFlagSyn, nil) // FIX: Use layers.TCPFlagSyn
	if packet == nil {
		return false, ""
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP) // Call Layer method on interface
	if tcpLayer == nil {
		return false, ""
	}
	tcp := tcpLayer.(*layers.TCP)

	if tcp.SYN && tcp.ACK { // SYN-ACK: Port is open
		return true, inferServiceFromPort(dstPort)
	} else if tcp.RST { // RST: Port is closed/filtered
		return false, ""
	}
	return false, "" // No conclusive response
}

// tcpFlagScan sends a TCP packet with specific flags (FIN, NULL, Xmas)
// Open: No response
// Closed: RST response
func (ps *PortScanner) tcpFlagScan(dstIP net.IP, dstPort int, flags layers.TCPFlags) (bool, string) { // FIX: Use layers.TCPFlags
	packet := ps.sendRawTCPAndListen(dstIP, dstPort, flags, nil)
	if packet == nil {
		// Timeout / No response: Port is OPEN or filtered
		return true, inferServiceFromPort(dstPort)
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false, ""
	}
	tcp := tcpLayer.(*layers.TCP)

	if tcp.RST { // RST: Port is CLOSED
		return false, ""
	}
	return false, "" // Unexpected response or no conclusive flags
}

// tcpAckScan sends a TCP ACK packet. Primarily for firewall rule mapping.
// Unfiltered: RST (if port closed) or ACK (if port open, or if firewall responds)
// Filtered: No response
func (ps *PortScanner) tcpAckScan(dstIP net.IP, dstPort int) (bool, string) {
	packet := ps.sendRawTCPAndListen(dstIP, dstPort, layers.TCPFlagAck, nil) // FIX: Use layers.TCPFlagAck
	if packet == nil {
		return false, "filtered (ack)"
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false, ""
	}
	tcp := tcpLayer.(*layers.TCP)

	if tcp.RST {
		return false, "unfiltered (ack-rst)"
	}
	return false, "unfiltered (ack-other)"
}

// tcpWindowScan sends a TCP ACK packet and examines the Window field in the reply.
// Open: Non-zero window size
// Closed: Zero window size (RST)
// Filtered: No response
func (ps *PortScanner) tcpWindowScan(dstIP net.IP, dstPort int) (bool, string) {
	packet := ps.sendRawTCPAndListen(dstIP, dstPort, layers.TCPFlagAck, nil) // FIX: Use layers.TCPFlagAck
	if packet == nil {
		return false, "filtered (window)"
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false, ""
	}
	tcp := tcpLayer.(*layers.TCP)

	if tcp.RST {
		if tcp.Window > 0 {
			return true, inferServiceFromPort(dstPort)
		} else {
			return false, "closed (window-rst0)"
		}
	}
	return false, "unfiltered (window-other)"
}

// tcpMaimonScan sends FIN/ACK packet.
// Open/Filtered: No response
// Closed: RST
func (ps *PortScanner) tcpMaimonScan(dstIP net.IP, dstPort int) (bool, string) {
	packet := ps.sendRawTCPAndListen(dstIP, dstPort, layers.TCPFlagFin|layers.TCPFlagAck, nil) // FIX: Use layers.TCPFlagFin | layers.TCPFlagAck
	if packet == nil {
		return true, inferServiceFromPort(dstPort)
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false, ""
	}
	tcp := tcpLayer.(*layers.TCP)

	if tcp.RST {
		return false, "closed (maimon-rst)"
	}
	return false, ""
}

// udpScan performs a UDP scan.
// It sends a UDP packet and listens for an ICMP Port Unreachable message to detect closed ports.
// Requires root privileges for pcap handle.
func (ps *PortScanner) udpScan(ip net.IP, port int) (bool, string) {
	if ps.handle == nil {
		output.PrintError("PCAP handle not initialized for UDP scan. UDP closed detection may be unreliable. (Requires root/admin)")
		conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: port})
		if err != nil {
			return false, ""
		}
		defer conn.Close()
		conn.SetWriteDeadline(time.Now().Add(ps.config.Timeout))
		_, err = conn.Write([]byte("."))
		if err != nil {
			return false, ""
		}
		return true, inferServiceFromPort(port)
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

	responseChan := make(chan gopacket.Packet, 1) // FIX: Channel is gopacket.Packet
	key := fmt.Sprintf("UDP_ICMP:%s:%d:%d", ip.String(), port, srcPort)
	ps.correlationMap.Store(key, responseChan)
	defer ps.correlationMap.Delete(key)

	ps.mu.Lock() // Protect handle writes
	err := ps.handle.WritePacketData(outgoingPacket)
	ps.mu.Unlock()

	if err != nil {
		output.PrintError("Failed to send UDP packet to %s:%d: %v.", ip.String(), port, err)
		return false, ""
	}

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), ps.config.Timeout)
	defer cancel()

	select {
	case packet := <-responseChan: // Receive gopacket.Packet
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
		if icmpLayer != nil {
			icmp4 := icmpLayer.(*layers.ICMPv4)
			// FIX: Correct way to compare ICMP TypeCode with specific Type and Code
			if icmp4.TypeCode == layers.ICMPv4TypeDestinationUnreachable.WithCode(layers.ICMPv4CodePortUnreachable) { // FIX: Use WithCode(3) for Port Unreachable
				// The ICMP payload contains the original IP header + 8 bytes of original packet.
				if len(icmp4.Payload) >= IPv4FixedHeaderLen+8 { // FIX: Use IPv4FixedHeaderLen
					originalIPHeader := icmp4.Payload[:IPv4FixedHeaderLen]
					originalUDPHeader := icmp4.Payload[IPv4FixedHeaderLen : IPv4FixedHeaderLen+8]

					// FIX: Use ipv4.ParseHeader from golang.org/x/net/ipv4
					origIPHdr, err := ipv4.ParseHeader(originalIPHeader)
					if err != nil {
						output.PrintDebug("Failed to parse original IP header in ICMP payload: %v", err)
						return false, "" // Failed to parse original IP header
					}

					if origIPHdr.Dst.Equal(ps.localIP) && origIPHdr.Src.Equal(ip) && // Corrected origIPHdr.Src.Equal(ip)
						origIPHdr.Protocol == layers.IPProtocolUDP { // FIX: Compare int with layers.IPProtocol by casting layers.IPProtocolUDP to int

						originalDstPort := binary.BigEndian.Uint16(originalUDPHeader[2:4])
						originalSrcPort := binary.BigEndian.Uint16(originalUDPHeader[0:2])

						key := fmt.Sprintf("UDP_ICMP:%s:%d:%d", origIPHdr.Src.String(), originalDstPort, originalSrcPort)
						if ch, loaded := ps.correlationMap.Load(key); loaded {
							select {
							case ch.(chan gopacket.Packet) <- packet: // Send gopacket.Packet interface
							default:
								// Channel full, drop packet
							}
						}
					}
				}
			}
		}
	case <-ctx.Done():
		// Timeout (no ICMP unreachable) means open or filtered.
	}
	return true, inferServiceFromPort(port) // Default to open/filtered
}

// inferServiceFromPort (same as before)
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
		return "unknown"
	}
}

// inferServiceFromBanner (same as before)
func inferServiceFromBanner(banner string) string {
	if len(banner) > 0 {
		cleanBanner := bytes.TrimSpace([]byte(banner))
		if len(cleanBanner) > 30 {
			cleanBanner = cleanBanner[:30]
		}
		return "banner: " + string(cleanBanner)
	}
	return "unknown"
}
