// pkg/discovery/hostdiscovery.go
package discovery

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"revealr/pkg/core"   // Corrected import path
	"revealr/pkg/output" // Corrected import path

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// HostDiscoverer manages host discovery operations.
type HostDiscoverer struct{}

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

				msg, err := icmp.ParseMessage(1, buffer[:n]) // Corrected protocol to 1 (int)
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

				msg := icmp.Message{
					Type: ipv4.ICMPTypeEcho,
					Code: 0,
					Body: &icmp.Echo{
						ID:   os.Getpid() & 0xffff,
						Seq:  idx,
						Data: []byte("REVEALR_PING"),
					},
				}
				wb, err := msg.Marshal(1) // Corrected protocol to 1 (int)
				if err != nil {
					output.PrintError("Failed to marshal ICMP message for %s: %v", ip.String(), err)
					return
				}

				key := fmt.Sprintf("%d:%d", msg.Body.(*icmp.Echo).ID, msg.Body.(*icmp.Echo).Seq)
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
