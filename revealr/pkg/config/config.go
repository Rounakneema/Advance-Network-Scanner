// pkg/config/config.go
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"revealr/pkg/output"
	"gopkg.in/yaml.v3"
)

// ScanConfig holds all configuration parameters for a scan.
type ScanConfig struct {
	// General
	Targets       []string `yaml:"targets"`
	Ports         string   `yaml:"ports"`
	ScanMode      string   `yaml:"scan_mode"`      // NEW: Expanded list of scan modes
	HostDiscovery []string `yaml:"host_discovery"` // NEW: Expanded list of host discovery methods
	ExcludeHosts  []string `yaml:"exclude_hosts"`
	Debug         bool     `yaml:"debug"`

	// Scanner Specific
	Timeout     time.Duration `yaml:"timeout"`
	Retries     int           `yaml:"retries"`
	Concurrency int           `yaml:"concurrency"`

	// Future Phases (placeholders)
	EnableOSINT      bool   `yaml:"enable_osint"`
	OSINTSources     []string `yaml:"osint_sources"`
	PythonPluginPort string `yaml:"python_plugin_port"`
}

// NewDefaultConfig creates and returns a default ScanConfig.
func NewDefaultConfig() *ScanConfig {
	return &ScanConfig{
		Targets:          []string{},
		Ports:            "top1000",
		ScanMode:         "connect", // Default remains connect
		HostDiscovery:    []string{"tcp-probe"}, // FIX: Changed default to tcp-probe for public targets
		ExcludeHosts:     []string{},
		Debug:            false,
		Timeout:          time.Second * 3,
		Retries:          1,
		Concurrency:      1000,
		EnableOSINT:      false,
		OSINTSources:     []string{},
		PythonPluginPort: "50051",
	}
}


// LoadConfig loads configuration from a YAML file.
// If the file doesn't exist or is empty, it returns a default config.
func LoadConfig(filePath string) (*ScanConfig, error) {
	cfg := NewDefaultConfig()

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			output.PrintWarning("Config file '%s' not found. Using default configuration.", filePath)
			return cfg, nil // If file doesn't exist, it's not an error; use defaults.
		}
		return nil, fmt.Errorf("failed to read config file '%s': %w", filePath, err)
	}

	if len(data) == 0 {
		output.PrintWarning("Config file '%s' is empty. Using default configuration.", filePath)
		return cfg, nil // If file is empty, use defaults.
	}

	err = yaml.Unmarshal(data, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file '%s': %w", filePath, err)
	}

	output.PrintInfo("Configuration loaded from '%s'.", filePath)
	return cfg, nil
}

// ParsePorts parses the ports string into a slice of integers.
// Supports "all", "top1000", comma-separated lists (e.g., "80,443"), and ranges (e.g., "1-100").
func (c *ScanConfig) ParsePorts() ([]int, error) {
	switch c.Ports {
	case "all":
		// Generates all 65535 ports. Be cautious, this is very slow for full scans.
		allPorts := make([]int, 65535)
		for i := 0; i < 65535; i++ {
			allPorts[i] = i + 1
		}
		return allPorts, nil
	case "top1000":
		// A simplified list of commonly scanned ports. In a real tool, this list would be much longer
		// and potentially loaded from a data file.
		return []int{
			21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
			20, 24, 67, 68, 69, 79, 88, 109, 111, 113, 119, 156, 161, 162, 179, 199, 389, 465, 500, 512,
			513, 514, 520, 546, 547, 587, 631, 636, 666, 902, 990, 1080, 1433, 1521, 2049, 2082, 2083,
			2086, 2087, 2095, 2096, 2483, 2484, 2967, 3000, 3128, 3306, 4000, 5000, 5060, 5432, 5800, 5901,
			6000, 6001, 7001, 8000, 8008, 8081, 8443, 8888, 9000, 9090, 10000, 27017, 27018, 27019, 28017,
			// ... (add more top ports if you want a more comprehensive "top1000" list)
		}, nil
	default:
		// Parse comma-separated list or ranges (e.g., "80,443,100-200")
		var ports []int
		portStrs := strings.Split(c.Ports, ",")
		for _, ps := range portStrs {
			ps = strings.TrimSpace(ps) // Remove leading/trailing whitespace
			if ps == "" {
				continue // Skip empty parts
			}
			// Handle port ranges (e.g., "1-100")
			if rangeParts := strings.Split(ps, "-"); len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err1 == nil && err2 == nil && start <= end && start >= 1 && end <= 65535 {
					for i := start; i <= end; i++ {
						ports = append(ports, i)
					}
					continue
				}
			}
			// Handle single ports
			p, err := strconv.Atoi(ps)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port format '%s'. Ports must be between 1 and 65535", ps)
			}
			ports = append(ports, p)
		}
		return ports, nil
	}
}
