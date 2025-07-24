// pkg/core/types.go
package core

import (
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
}

// NewHost creates a new Host instance.
func NewHost(ip net.IP) *Host {
	return &Host{
		ID:        ip.String(),
		IPAddress: ip,
		Ports:     make([]*Port, 0),
		Details:   make(map[string]string),
	}
}

// AddPort adds a port to the host's list of ports safely.
func (h *Host) AddPort(p *Port) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Ports = append(h.Ports, p)
}

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
