// internal/utils/network.go
package utils

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket/pcap"
	"os/exec"
)

// GetLocalIPv4 retrieves a suitable local IPv4 address for outgoing connections.
// This is used as the source IP for packets.
func GetLocalIPv4() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53") // Connect to a public DNS server
	if err != nil {
		return nil, fmt.Errorf("could not connect to determine local IP: %w", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	if localAddr.IP.To4() == nil {
		return nil, fmt.Errorf("could not determine a valid IPv4 address for local interface")
	}
	return localAddr.IP.To4(), nil
}

// GetRandomEphemeralPort generates a random port number in the ephemeral range (>1023).
func GetRandomEphemeralPort() uint16 {
	var n uint16
	binary.Read(rand.Reader, binary.BigEndian, &n)
	return n% (65535 - 1024) + 1024 // Ports from 1024 to 65535
}

// FindActiveDevice finds a suitable active network device and its IPv4 address/MAC address.
// It uses pcap.FindAllDevs to ensure the returned device name is compatible with pcap.OpenLive (especially on Windows).
func FindActiveDevice() (string, net.IP, net.HardwareAddr, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to find pcap devices: %w", err)
	}

	// Candidate struct to score interfaces
	type Candidate struct {
		Device       pcap.Interface
		IP           net.IP
		HardwareAddr net.HardwareAddr
		Score        int
	}
	var candidates []Candidate

	for _, device := range devices {
		// Basic filter: Scan addresses to see if it has a valid IPv4
		var ipv4 net.IP
		for _, address := range device.Addresses {
			if ip := address.IP.To4(); ip != nil && !ip.IsLoopback() {
				ipv4 = ip
				break
			}
		}

		if ipv4 == nil {
			continue // No valid IPv4 on this device
		}

		// Cross-reference with net.Interfaces
		interfaces, err := net.Interfaces()
		if err == nil {
			for _, iface := range interfaces {
				addrs, _ := iface.Addrs()
				for _, addr := range addrs {
					if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.Equal(ipv4) {
						// Found the matching Go interface!
						// Check flags
						if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
							// Valid candidate. Calculate Score.
							score := 10 // Base score

							// Deprioritize known virtual/WSL adapters based on Description or Name
							descLower := device.Description
							// Note: device.Description might be empty on some platforms, check iface.Name too?
							// Actually, pcap.Interface (device) often has the FriendlyName in Description on Windows.
							
							if containsAny(descLower, "wsl", "hyper-v", "virtual", "pseudo", "vmware", "virtualbox") {
								score -= 50
							}

							candidates = append(candidates, Candidate{
								Device:       device,
								IP:           ipv4,
								HardwareAddr: iface.HardwareAddr,
								Score:        score,
							})
						}
					}
				}
			}
		}
	}

	if len(candidates) == 0 {
		return "", nil, nil, fmt.Errorf("no suitable active pcap device found")
	}

	// Select the candidate with the highest score
	best := candidates[0]
	for _, c := range candidates {
		if c.Score > best.Score {
			best = c
		}
	}

	return best.Device.Name, best.IP, best.HardwareAddr, nil
}

// Helper to check if string contains any of the substrings (case-insensitive done by caller logic preferably, but doing it here)
func containsAny(s string, subs ...string) bool {
	sLower := strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(sLower, sub) {
			return true
		}
	}
	return false
}

// GetGatewayIP attempts to determine the default gateway IPv4 address.
// Windows implementation using 'route print'.
func GetGatewayIP() (net.IP, error) {
	cmd := exec.Command("route", "print", "0.0.0.0")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	// Output format example (Windows):
	// Network Destination        Netmask          Gateway       Interface  Metric
	//           0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			gateway := net.ParseIP(fields[2])
			if gateway != nil {
				return gateway, nil
			}
		}
	}
	return nil, fmt.Errorf("gateway not found in route table")
}

// GetMacAddress attempts to resolve the MAC address for a given IP.
// It uses the system ARP cache ('arp -a').
// Important: The ARP entry must exist. The caller should ensure traffic has been sent to the IP recently.
func GetMacAddress(ip net.IP) (net.HardwareAddr, error) {
	cmd := exec.Command("arp", "-a", ip.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	// Output format example:
	// Interface: 192.168.1.100 --- 0x10
	//   Internet Address      Physical Address      Type
	//   192.168.1.1           00-11-22-33-44-55     dynamic
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			// Check if the first field matches the IP (sometimes arp -a output varies)
			// But 'arp -a <IP>' usually filters it.
			// Windows: "  192.168.1.1           00-11-22-33-44-55     dynamic"
			if fields[0] == ip.String() {
				macStr := strings.ReplaceAll(fields[1], "-", ":")
				mac, err := net.ParseMAC(macStr)
				if err == nil {
					return mac, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("MAC address for %s not found in ARP cache", ip)
}