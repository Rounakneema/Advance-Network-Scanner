// pkg/discovery/hostdiscovery.go
package discovery

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"revealr/internal/utils" // FIX: Correctly import internal/utils for helper functions
	"revealr/pkg/core"
	"revealr/pkg/output"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers" // FIX: Add layers import
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4" // Provides ICMPTypeEcho, etc.
)

// HostDiscoverer manages host discovery operations.
type HostDiscoverer struct {
	mu sync.Mutex // FIX: Add mutex for concurrent access to pcap handle in TCPHostProbePing / ARPScan (if used concurrently)
}

// NewHostDiscoverer creates a new HostDiscoverer.
func NewHostDiscoverer() *HostDiscoverer {
	return &HostDiscoverer{}
}

// PingHosts performs ICMP echo requests to determine if hosts are up.
// It returns a slice of *core.Host objects that are found to be online.
// Note: On Linux, this typically requires CAP_NET_RAW or root privileges.
// On Windows, it usually works without admin if firewall allows.
func (hd *HostDiscoverer) PingHosts(ctx context.Context, targets []net.IP, timeout time.Duration) ([]*core.Host, error) {
	output.PrintInfo("Starting ICMP host discovery (may require root/admin on some OSes)...")

	var liveHosts []*core.Host
	var wg sync.WaitGroup
	hostChan := make(chan *core.Host, len(targets))

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		output.PrintError("Failed to open ICMP listener: %v. Host discovery may be unreliable. (Try running with `sudo` on Linux/macOS)", err)
		return nil, fmt.Errorf("ICMP listener setup failed: %w", err)
	}
	defer conn.Close()

	sentICMPs := sync.Map{}

	go func() {
		buffer := make([]byte, 1500)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
				n, peer, err := conn.ReadFrom(buffer)
				if err != nil {
					if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
						continue
					}
					if !os.IsTimeout(err) && err != context.Canceled && err.Error() != "use of closed network connection" {
						output.PrintDebug("ICMP read error: %v", err)
					}
					continue
				}

				msg, err := icmp.ParseMessage(1, buffer[:n])
				if err != nil {
					output.PrintDebug("Failed to parse ICMP message: %v", err)
					continue
				}

				if msg.Type == ipv4.ICMPTypeEchoReply {
					if echoReply, ok := msg.Body.(*icmp.Echo); ok {
						key := fmt.Sprintf("%d:%d", echoReply.ID, echoReply.Seq)
						if targetIP, loaded := sentICMPs.LoadAndDelete(key); loaded {
							if targetIP.(net.IP).Equal(peer.(*net.IPAddr).IP) {
								host := core.NewHost(peer.(*net.IPAddr).IP)
								host.IsUp = true
								hostChan <- host
							}
						}
					}
				}
			}
		}
	}()

	sem := make(chan struct{}, 100)

	for i, ip := range targets {
		select {
		case <-ctx.Done():
			output.PrintWarning("Host discovery cancelled.")
			close(hostChan)
			wg.Wait()
			return liveHosts, ctx.Err()
		case sem <- struct{}{}:
			wg.Add(1)
			go func(ip net.IP, idx int) {
				defer func() {
					<-sem
					wg.Done()
				}()

				output.PrintHostScanProgress(idx+1, len(targets), ip.String())

				body := &icmp.Echo{
					ID:   os.Getpid() & 0xffff,
					Seq:  idx,
					Data: []byte("REVEALR_PING"),
				}

				msg := icmp.Message{
					Type: ipv4.ICMPTypeEcho,
					Code: 0,
					Body: body,
				}

				wb, err := msg.Marshal(nil) // Correctly calls Marshal with nil pseudo-header for IPv4
				if err != nil {
					output.PrintError("Failed to marshal ICMP message for %s: %v", ip.String(), err)
					return
				}

				key := fmt.Sprintf("%d:%d", body.ID, body.Seq)
				sentICMPs.Store(key, ip)

				_, err = conn.WriteTo(wb, &net.IPAddr{IP: ip})
				if err != nil {
					output.PrintDebug("Failed to send ICMP ping to %s: %v", ip.String(), err)
					sentICMPs.Delete(key)
				}
			}(ip, i)
		}
	}

	wg.Wait()
	time.Sleep(timeout / 2)
	close(hostChan)

	for host := range hostChan {
		liveHosts = append(liveHosts, host)
	}

	output.PrintSuccess("ICMP host discovery finished. Found %d live hosts.", len(liveHosts))
	return liveHosts, nil
}

// TCPProbeHosts performs host discovery by attempting to establish TCP connections
// to a common port (like 80 or 443). If a connection is established or refused,
// the host is considered live.
func (hd *HostDiscoverer) TCPProbeHosts(ctx context.Context, targets []net.IP, timeout time.Duration) ([]*core.Host, error) {
	output.PrintInfo("Starting TCP probe host discovery...")

	var liveHosts []*core.Host
	var wg sync.WaitGroup
	hostChan := make(chan *core.Host, len(targets))
	sem := make(chan struct{}, 200)

	probePorts := []int{80, 443, 22, 23, 25, 53, 110, 445}

	for i, ip := range targets {
		select {
		case <-ctx.Done():
			output.PrintWarning("Host discovery cancelled.")
			close(hostChan)
			wg.Wait()
			return liveHosts, ctx.Err()
		case sem <- struct{}{}:
			wg.Add(1)
			go func(ip net.IP, idx int) {
				defer func() {
					<-sem
					wg.Done()
				}()

				output.PrintHostScanProgress(idx+1, len(targets), ip.String())

				isLive := false
				for _, port := range probePorts {
					addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
					conn, err := net.DialTimeout("tcp", addr, timeout)
					if err == nil {
						conn.Close()
						isLive = true
						break
					}
					if opErr, ok := err.(*net.OpError); ok && opErr.Op == "dial" {
						if sysErr, ok := opErr.Unwrap().(*os.SyscallError); ok {
							if sysErr.Err == syscall.ECONNREFUSED || sysErr.Err.Error() == "wsarefused" { // Add "wsarefused" for Windows
								isLive = true
								break
							}
						}
					}
				}

				if isLive {
					host := core.NewHost(ip)
					host.IsUp = true
					hostChan <- host
				}
			}(ip, i)
		}
	}

	wg.Wait()
	close(hostChan)

	for host := range hostChan {
		liveHosts = append(liveHosts, host)
	}

	output.PrintSuccess("TCP probe host discovery finished. Found %d live hosts.", len(liveHosts))
	return liveHosts, nil
}

// ARPScan performs ARP requests on the local subnet to discover hosts.
// Requires root/admin privileges for pcap handle.
func (hd *HostDiscoverer) ARPScan(ctx context.Context, targetCIDR *net.IPNet, timeout time.Duration) ([]*core.Host, error) {
	output.PrintInfo("Starting ARP host discovery for %s (requires root/admin)...", targetCIDR.String())

	var liveHosts []*core.Host
	var wg sync.WaitGroup
	hostChan := make(chan *core.Host, 100)

	// FIX: Use utils.FindActiveDevice
	device, localIP, localMAC, err := utils.FindActiveDevice()
	if err != nil {
		return nil, fmt.Errorf("failed to find active device for ARP scan: %w", err)
	}
	output.PrintInfo("Using device '%s' (%s) for ARP scan.", device, localIP.String())

	handle, err := pcap.OpenLive(device, 65535, true, pcap.BlockForever) // Promiscuous: true for sniffing all ARP
	if err != nil {
		output.PrintError("Failed to open pcap handle for ARP scan (%s): %v. (Requires root/admin)", device, err)
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(fmt.Sprintf("arp and ether dst host %s", localMAC.String()))
	if err != nil {
		output.PrintWarning("Failed to set BPF filter for ARP replies: %v. ARP scan may be less efficient.", err)
	}

	sentARPs := sync.Map{}

	go func() {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			select {
			case <-ctx.Done():
				return
			case packet, ok := <-packetSource.Packets():
				if !ok {
					return
				}
				arpLayer := packet.Layer(layers.LayerTypeARP)
				if arpLayer != nil {
					arp := arpLayer.(*layers.ARP)
					if arp.Operation == layers.ARPReply && len(arp.SourceProtAddress) == 4 {
						replyIP := net.IP(arp.SourceProtAddress).To4()
						if targetCIDR.Contains(replyIP) {
							if _, loaded := sentARPs.LoadAndDelete(replyIP.String()); loaded {
								host := core.NewHost(replyIP)
								host.IsUp = true
								hostChan <- host
							}
						}
					}
				}
			}
		}
	}()

	ipsToScan := make([]net.IP, 0)
	for ip := targetCIDR.IP.Mask(targetCIDR.Mask); targetCIDR.Contains(ip); inc(ip) {
		ipsToScan = append(ipsToScan, net.ParseIP(ip.String()))
	}
	ipsToScan = removeNetworkAndBroadcast(ipsToScan, targetCIDR)

	sem := make(chan struct{}, 50)

	for i, ip := range ipsToScan {
		select {
		case <-ctx.Done():
			output.PrintWarning("ARP scan cancelled.")
			close(hostChan)
			wg.Wait()
			return liveHosts, ctx.Err()
		case sem <- struct{}{}:
			wg.Add(1)
			go func(ip net.IP, idx int) {
				defer func() {
					<-sem
					wg.Done()
				}()

				output.PrintHostScanProgress(idx+1, len(ipsToScan), ip.String())

				arpLayer := &layers.ARP{
					AddrType:          layers.LinkTypeEthernet,
					Protocol:          layers.EthernetTypeIPv4,
					HwAddressSize:     6,
					ProtAddressSize:   4,
					Operation:         layers.ARPRequest,
					SourceHwAddress:   localMAC,      // This will be localMAC from utils.FindActiveDevice
					SourceProtAddress: localIP.To4(), // This will be localIP from utils.FindActiveDevice
					DstHwAddress:      net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
					DstProtAddress:    ip.To4(),
				}
				etherLayer := &layers.Ethernet{
					SrcMAC:       localMAC,
					DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
					EthernetType: layers.EthernetTypeARP,
				}
				buf := gopacket.NewSerializeBuffer()
				gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, etherLayer, arpLayer)

				sentARPs.Store(ip.String(), true)

				hd.mu.Lock() // Protect handle writes
				err := handle.WritePacketData(buf.Bytes())
				hd.mu.Unlock()
				if err != nil {
					output.PrintDebug("Failed to send ARP request to %s: %v", ip.String(), err)
					sentARPs.Delete(ip.String())
				}
			}(ip, i)
		}
	}
	wg.Wait()
	time.Sleep(timeout / 2)
	close(hostChan)

	for host := range hostChan {
		liveHosts = append(liveHosts, host)
	}

	output.PrintSuccess("ARP host discovery finished. Found %d live hosts.", len(liveHosts))
	return liveHosts, nil
}

// TCPHostProbePing performs host discovery by sending a SYN packet to a common port (e.g., 80)
// and looks for a SYN-ACK or RST.
// Requires root/admin privileges for pcap handle.
func (hd *HostDiscoverer) TCPHostProbePing(ctx context.Context, targets []net.IP, timeout time.Duration) ([]*core.Host, error) {
	output.PrintInfo("Starting TCP SYN/ACK probe host discovery (requires root/admin)...")

	var liveHosts []*core.Host
	var wg sync.WaitGroup
	hostChan := make(chan *core.Host, len(targets))
	sem := make(chan struct{}, 200)

	device, localIP, _, err := utils.FindActiveDevice()
	if err != nil {
		return nil, fmt.Errorf("failed to find active device for TCP probe: %w", err)
	}
	output.PrintInfo("Using device '%s' (%s) for TCP probe scan.", device, localIP.String())

	handle, err := pcap.OpenLive(device, 65535, false, pcap.BlockForever)
	if err != nil {
		output.PrintError("Failed to open pcap handle for TCP probe (%s): %v. (Requires root/admin)", device, err)
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}
	defer handle.Close()

	filter := fmt.Sprintf("tcp and (tcp[tcpflags] & (0x10|0x04) != 0) and dst host %s", localIP.String())
	if err := handle.SetBPFFilter(filter); err != nil {
		output.PrintWarning("Failed to set BPF filter for TCP probe: %v. Raw TCP probe may capture more traffic than necessary.", err)
	}

	synCorrelation := sync.Map{}

	go func() {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			select {
			case <-ctx.Done():
				return
			case packet, ok := <-packetSource.Packets():
				if !ok {
					return
				}
				if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					tcp := tcpLayer.(*layers.TCP)
					if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
						ip4 := ipLayer.(*layers.IPv4)

						key := fmt.Sprintf("%s:%d", ip4.SrcIP.String(), tcp.DstPort)
						if ch, loaded := synCorrelation.Load(key); loaded {
							isLive := (tcp.SYN && tcp.ACK) || tcp.RST
							ch.(chan bool) <- isLive
							synCorrelation.Delete(key)
						}
					}
				}
			}
		}
	}()

	probePort := 80

	for i, ip := range targets {
		select {
		case <-ctx.Done():
			output.PrintWarning("TCP probe scan cancelled.")
			close(hostChan)
			wg.Wait()
			return liveHosts, ctx.Err()
		case sem <- struct{}{}:
			wg.Add(1)
			go func(ip net.IP, idx int) {
				defer func() {
					<-sem
					wg.Done()
				}()

				output.PrintHostScanProgress(idx+1, len(targets), ip.String())

				srcPort := utils.GetRandomEphemeralPort()
				seq := utils.GetRandomEphemeralPort()

				ipLayer := &layers.IPv4{
					SrcIP:    localIP.To4(),
					DstIP:    ip.To4(),
					Protocol: layers.IPProtocolTCP,
					TTL:      64,
					Id:       uint16(idx),
				}
				tcpLayer := &layers.TCP{
					SrcPort: layers.TCPPort(srcPort),
					DstPort: layers.TCPPort(probePort),
					SYN:     true,
					Window:  14600,
					Seq:     uint32(seq),
				}
				tcpLayer.SetNetworkLayerForChecksum(ipLayer)

				buf := gopacket.NewSerializeBuffer()
				gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ipLayer, tcpLayer)
				outgoingPacket := buf.Bytes()

				responseChan := make(chan bool, 1)
				key := fmt.Sprintf("%s:%d", ip.String(), srcPort)
				synCorrelation.Store(key, responseChan)

				hd.mu.Lock() // Protect handle writes
				err := handle.WritePacketData(outgoingPacket)
				hd.mu.Unlock()
				if err != nil {
					output.PrintDebug("Failed to send TCP probe to %s:%d: %v", ip.String(), probePort, err)
					synCorrelation.Delete(key)
					return
				}

				ctxTimeout, cancelTimeout := context.WithTimeout(context.Background(), timeout)
				defer cancelTimeout()

				select {
				case isLive := <-responseChan:
					if isLive {
						host := core.NewHost(ip)
						host.IsUp = true
						hostChan <- host
					}
				case <-ctxTimeout.Done():
				}
			}(ip, i)
		}
	}
	wg.Wait()
	time.Sleep(timeout / 2)
	close(hostChan)

	for host := range hostChan {
		liveHosts = append(liveHosts, host)
	}
	output.PrintSuccess("TCP SYN/ACK probe host discovery finished. Found %d live hosts.", len(liveHosts))
	return liveHosts, nil
}

// removeNetworkAndBroadcast is a helper to clean up IPs from a CIDR range.
func removeNetworkAndBroadcast(ips []net.IP, ipNet *net.IPNet) []net.IP {
	var filtered []net.IP
	networkAddr := ipNet.IP.Mask(ipNet.Mask)
	broadcastAddr := make(net.IP, len(networkAddr))
	copy(broadcastAddr, networkAddr)
	for i := range broadcastAddr {
		broadcastAddr[i] |= ^ipNet.Mask[i]
	}

	for _, ip := range ips {
		if !ip.Equal(networkAddr) && !ip.Equal(broadcastAddr) {
			filtered = append(filtered, ip)
		}
	}
	return filtered
}

// inc increments an IP address (used for CIDR iteration).
func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}
