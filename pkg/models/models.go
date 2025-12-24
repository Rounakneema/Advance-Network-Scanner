package models

import (
	"fmt"
	"net"
	"sync"
	"revealr/pkg/output"
)

// Host represents a target host that was discovered.
type Host struct {
	ID         string
	IPAddress  net.IP
	IsUp       bool
	TTL        uint8 // TTL from response packet for OS fingerprinting
	Ports      []*Port
	Details    map[string]string
	mu         sync.Mutex
	addedPorts map[string]struct{} // For deduplication within the host
}

// NewHost creates a new Host instance.
func NewHost(ip net.IP) *Host {
	return &Host{
		ID:         ip.String(),
		IPAddress:  ip,
		Ports:      make([]*Port, 0),
		Details:    make(map[string]string),
		addedPorts: make(map[string]struct{}),
	}
}

// AddPort adds a port if not already added (deduplicates within host object).
func (h *Host) AddPort(p *Port) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	portKey := fmt.Sprintf("%d/%s", p.PortNumber, p.Protocol)

	if _, exists := h.addedPorts[portKey]; exists {
		// Avoid debug noise for known duplicates
		// output.PrintDebug("Host.AddPort: Skipping duplicate port %s for host %s.", portKey, h.ID)
		return false
	}

	h.Ports = append(h.Ports, p)
	h.addedPorts[portKey] = struct{}{}
	output.PrintDebug("Host.AddPort: Added port %s to host %s.", portKey, h.ID)
	return true
}

// PortState represents the state of a port (open, closed, filtered, etc.)
type PortState string

const (
	PortOpen         PortState = "open"
	PortClosed       PortState = "closed"
	PortFiltered     PortState = "filtered"
	PortOpenFiltered PortState = "open|filtered" // For UDP/FIN scans where we can't distinguish
)

// Port represents a discovered port on a host.
type Port struct {
	PortNumber int
	Protocol   string
	State      PortState
	Reason     string // Reason for the state (e.g., "syn-ack", "timeout")
	Service    *Service
	Details    map[string]string
}

// NewPort creates a new Port instance.
func NewPort(portNum int, proto string) *Port {
	return &Port{
		PortNumber: portNum,
		Protocol:   proto,
		State:      PortClosed, // Default to closed until proven otherwise
		Service:    NewService(),
		Details:    make(map[string]string),
	}
}

// Service represents details about a service running on a port.
type Service struct {
	Name    string
	Version string
	Details map[string]string
}

// NewService creates a new Service instance.
func NewService() *Service {
	return &Service{
		Name:    "",
		Version: "",
		Details: make(map[string]string),
	}
}
