package models

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// WellKnownPort represents a well-known service associated with a port and protocol.
type WellKnownPort struct {
	PortNumber  int
	Protocol    string
	ServiceName string
}

// Private Encapsulated DB
var wellKnownPortsDB = make(map[string]WellKnownPort)

// GetLikelyServiceName returns the well-known service name for a given port and protocol.
// This is a heuristic based on IANA assignments and is NOT authoritative.
// Returns "unknown" if not found.
func GetLikelyServiceName(port int, protocol string) string {
	// Normalize protocol to ensure consistent lookup
	protocol = strings.ToLower(protocol)
	key := fmt.Sprintf("%d/%s", port, protocol)
	
	if entry, ok := wellKnownPortsDB[key]; ok {
		return entry.ServiceName
	}
	return "unknown"
}

// LoadWellKnownPortsDB loads service data from the CSV file.
// This should be called once at application startup.
func LoadWellKnownPortsDB(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("failed to open well-known ports DB: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to parse well-known ports CSV: %w", err)
	}

	// Reset DB (thread-unsafe, assume startup only)
	wellKnownPortsDB = make(map[string]WellKnownPort)

	for i, record := range records {
		if i == 0 { // Skip header row
			continue
		}
		if len(record) < 3 {
			continue // Skip malformed rows
		}

		serviceName := record[0]
		portStr := record[1]
		protocol := strings.TrimSpace(record[2])

		portNum, err := strconv.Atoi(portStr)
		if err != nil {
			continue // Skip non-numeric ports
		}

		// Sanity check for valid port range
		if portNum < 1 || portNum > 65535 {
			continue
		}

		key := fmt.Sprintf("%d/%s", portNum, strings.ToLower(protocol))
		wellKnownPortsDB[key] = WellKnownPort{
			PortNumber:  portNum,
			Protocol:    strings.ToLower(protocol),
			ServiceName: serviceName,
		}
	}
	
	return nil
}
