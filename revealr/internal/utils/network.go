// internal/utils/network.go
package utils

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
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
// This is used internally by host discovery and scanner for raw operations.
func FindActiveDevice() (string, net.IP, net.HardwareAddr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		// Skip loopback, down interfaces, or those without hardware addresses
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 && iface.HardwareAddr != nil {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
					// Found an active, non-loopback IPv4 interface with a MAC address
					return iface.Name, ipNet.IP.To4(), iface.HardwareAddr, nil
				}
			}
		}
	}
	return "", nil, nil, fmt.Errorf("no suitable active IPv4 network interface with a MAC address found")
}