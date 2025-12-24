// pkg/core/types.go
package core

import (
	"fmt"
	"net"
	"sync"
)

// Host represents a target host that was discovered.
type Host struct {
	ID        string            // Unique ID for the host (e.g., IP address string)
	IPAddress net.IP            // IP address of the host
	IsUp      bool              // True if host is determined to be up
	Ports     []*Port           // Slice of ports found on the host
	Details   map[string]string // General details (e.g., OS, hostname, initial banner)
	mu        sync.Mutex        // Mutex for concurrent access to Host fields
	// Add a map to track added ports for quick deduplication within the Host object
	addedPorts map[string]struct{} // Key: "portNum/protocol"
}

// NewHost creates a new Host instance.
func NewHost(ip net.IP) *Host {
	return &Host{
		ID:         ip.String(),
		IPAddress:  ip,
		Ports:      make([]*Port, 0),
		Details:    make(map[string]string),
		addedPorts: make(map[string]struct{}), // Initialize the deduplication map
	}
}

// AddPort adds a port to the host's list of ports safely, ensuring no duplicates.
func (h *Host) AddPort(p *Port) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Create a unique key for the port (e.g., "80/tcp")
	portKey := fmt.Sprintf("%d/%s", p.PortNumber, p.Protocol)

	// Check if this port has already been added to this host
	if _, exists := h.addedPorts[portKey]; exists {
		// output.PrintDebug("Skipping duplicate add for port %s on host %s", portKey, h.ID) // Uncomment for debug
		return // Port already exists, do not add again
	}

	h.Ports = append(h.Ports, p)
	h.addedPorts[portKey] = struct{}{} // Mark as added
}

// ... rest of the file (Port and Service structs, NewPort, NewService) remains the same ...
// Port represents a discovered port on a host.
type Port struct {
	PortNumber int               // Port number (e.g., 80, 443)
	Protocol   string            // Protocol (e.g., "tcp", "udp")
	IsOpen     bool              // True if the port is open
	Service    *Service          // Details of the service running on the port
	Details    map[string]string // Raw banner, specific flags etc.
}

// NewPort creates a new Port instance.
func NewPort(portNum int, proto string) *Port {
	return &Port{
		PortNumber: portNum,
		Protocol:   proto,
		IsOpen:     false, // Default to closed
		Service:    NewService(),
		Details:    make(map[string]string),
	}
}

// Service represents details about a service running on a port.
type Service struct {
	Name    string            // e.g., "http", "ftp", "ssh"
	Version string            // e.g., "Apache 2.4.54", "OpenSSH 8.9"
	Details map[string]string // Additional key-value pairs of service info
}

// NewService creates a new Service instance.
func NewService() *Service {
	return &Service{
		Name:    "", // Default empty
		Version: "", // Default empty
		Details: make(map[string]string),
	}
}
