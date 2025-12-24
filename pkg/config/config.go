// pkg/config/config.go
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"revealr/pkg/output"
	"revealr/pkg/models"

	"gopkg.in/yaml.v3"
)

// ScanConfig holds all configuration parameters for a scan.
type ScanConfig struct {
	Targets          []string      `yaml:"targets"`
	Ports            string        `yaml:"ports"`
	ScanMode         string        `yaml:"scan_mode"`
	HostDiscovery    []string      `yaml:"host_discovery"`
	ExcludeHosts     []string      `yaml:"exclude_hosts"`
	Debug            bool          `yaml:"debug"`
	Timeout          time.Duration `yaml:"timeout"`
	Retries          int           `yaml:"retries"`
	Concurrency      int           `yaml:"concurrency"`
	EnableOSINT      bool          `yaml:"enable_osint"`
	OSINTSources     []string      `yaml:"osint_sources"`
	PythonPluginPort string        `yaml:"python_plugin_port"`
	ScanTiming       string        `yaml:"scan_timing"`
	AdvancedMode     bool          `yaml:"advanced_mode"`
}

// NewDefaultConfig creates and returns a default ScanConfig.
func NewDefaultConfig() *ScanConfig {
	return &ScanConfig{
		Targets:          []string{},
		Ports:            "top1000",
		ScanMode:         "connect",
		HostDiscovery:    []string{"tcp-probe"}, 
		ExcludeHosts:     []string{},
		Debug:            false,
		Timeout:          time.Second * 3,
		Retries:          1,
		Concurrency:      1000,
		EnableOSINT:      false,
		OSINTSources:     []string{},
		PythonPluginPort: "50051",
		ScanTiming:       "normal",
		AdvancedMode:     false,
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
	case "top100":
		return models.GetTopPorts(100, "data/ports/nmap-top-ports.txt")
	case "top500":
		return models.GetTopPorts(500, "data/ports/nmap-top-ports.txt")
	case "top1000":
		return models.GetTopPorts(1000, "data/ports/nmap-top-ports.txt")
	case "top10000":
		return models.GetTopPorts(10000, "data/ports/nmap-top-ports.txt")
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
