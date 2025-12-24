package plugin_manager

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"revealr/pkg/output"
)

// ListPlugins walks the plugins directory and lists found plugins.
func ListPlugins() {
	pluginRoot := "plugins"
	output.PrintInfo("Listing installed plugins...")

	if _, err := os.Stat(pluginRoot); os.IsNotExist(err) {
		output.PrintWarning("Plugins directory not found: %s", pluginRoot)
		return
	}

	foundCount := 0
	err := filepath.Walk(pluginRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Look for plugin.py or plugin.json
		if !info.IsDir() && (info.Name() == "plugin.py" || info.Name() == "plugin.json") {
			// Found a plugin definition
			pluginDir := filepath.Dir(path)
			// Derive a pretty name: e.g. plugins/core/scan -> core/scan
			relPath, _ := filepath.Rel(pluginRoot, pluginDir)
			// Print it
			category := filepath.Dir(relPath)
			name := filepath.Base(relPath)
			
			if name == "." {
				// skip root
				return nil
			}
			
			// Simple deduplication if both py and json exist
			// We can just print the dir once.
			// Ideally we check if we already printed this dir?
			// But for now, let's just print.
			// Actually, let's look ONLY for plugin.json as metadata, fallback to plugin.py
			if info.Name() == "plugin.json" {
				fmt.Printf(" - %s/%s\n", category, name)
				foundCount++
			} else if info.Name() == "plugin.py" {
				// Check if json exists, if so skip (captured above)
				if _, err := os.Stat(filepath.Join(pluginDir, "plugin.json")); os.IsNotExist(err) {
					fmt.Printf(" - %s/%s (Logic only)\n", category, name)
					foundCount++
				}
			}
		}
		return nil
	})

	if err != nil {
		output.PrintError("Error walking plugins: %v", err)
	} else {
		output.PrintSuccess("Found %d plugins.", foundCount)
	}
}

// InstallPlugin downloads a plugin from a URL.
func InstallPlugin(url string) {
	// Basic implementation: git clone to plugins/local
	localPluginsDir := filepath.Join("plugins", "local")
	
	// Create local dir if not exists
	if _, err := os.Stat(localPluginsDir); os.IsNotExist(err) {
		os.MkdirAll(localPluginsDir, 0755)
	}

	// Derive directory name from URL
	parts := strings.Split(url, "/")
	repoName := parts[len(parts)-1]
	repoName = strings.TrimSuffix(repoName, ".git")
	
	destPath := filepath.Join(localPluginsDir, repoName)
	
	if _, err := os.Stat(destPath); !os.IsNotExist(err) {
		output.PrintError("Plugin already exists at: %s", destPath)
		return
	}

	output.PrintInfo("Cloning plugin from %s...", url)
	cmd := exec.Command("git", "clone", url, destPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	err := cmd.Run()
	if err != nil {
		output.PrintError("Failed to install plugin: %v", err)
	} else {
		output.PrintSuccess("Plugin installed to: %s", destPath)
	}
}
