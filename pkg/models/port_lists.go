package models

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
)

// LoadPortList reads a file containing a list of ports (one per line) 
// and returns them as a slice of integers.
func LoadPortList(path string) ([]int, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ports []int
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}
		
		p, err := strconv.Atoi(line)
		if err != nil {
			continue // Skip malformed lines
		}
		ports = append(ports, p)
	}

	return ports, scanner.Err()
}

// Global cache for the master frequency list.
var (
	masterPortList     []int
	masterListLoadOnce sync.Once
	masterListLoadError error
)

// GetTopPorts returns the top N ports from the master frequency list.
// If n is larger than the list, it returns the entire list.
func GetTopPorts(n int, path string) ([]int, error) {
	masterListLoadOnce.Do(func() {
		masterPortList, masterListLoadError = LoadPortList(path)
	})

	if masterListLoadError != nil {
		return nil, masterListLoadError
	}

	if n > len(masterPortList) {
		return masterPortList, nil
	}
	return masterPortList[:n], nil
}
