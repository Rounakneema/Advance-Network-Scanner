package plugin_manager

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"revealr/pkg/output"
)

// CreatePlugin generates a new plugin structure in the plugins/local directory.
func CreatePlugin(rawName string) error {
	// Sanitize plugin name
	pluginName := strings.ReplaceAll(rawName, " ", "_")
	pluginName = strings.ReplaceAll(pluginName, "-", "_")
	pluginName = strings.ToLower(pluginName)

	baseDir := "plugins/local"
	pluginDir := filepath.Join(baseDir, pluginName)

	if _, err := os.Stat(pluginDir); !os.IsNotExist(err) {
		output.PrintError("Plugin directory already exists: %s", pluginDir)
		return fmt.Errorf("plugin directory already exists")
	}

	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		output.PrintError("Failed to create plugin directory: %v", err)
		return err
	}

	// Template: plugin.json
	jsonContent := fmt.Sprintf(`{
    "name": "%s",
    "version": "0.1.0",
    "type": "service",
    "entry": "plugin.py",
    "description": "Auto-generated plugin %s",
    "author": "Local User",
    "inputs": [
        "service:http" 
    ]
}`, pluginName, pluginName)

	// Template: plugin.py
	pyContent := `def run(context):
    """
    Main entry point for the plugin.
    
    Args:
        context (dict): Contains 'target', 'port', 'service', 'banner', 'details'.
    
    Returns:
        dict: A dictionary of findings or details to merge into the host info.
              Return None or empty dict if nothing found.
    """
    target = context['target']
    port = context['port']
    service = context.get('service', 'unknown')
    
    # ------------------------------------------------------------------
    # Blueprint: Use the debug helper for consistent logging
    # ------------------------------------------------------------------
    debug = context.get('debug', lambda x: None)
    debug(f"Starting check on {target}:{port}...")
    
    # checking logic here
    # ...

    return {
        "manual_check": f"Executed on {target}:{port} ({service})"
    }
`

	// Write Files
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin.json"), []byte(jsonContent), 0644); err != nil {
		output.PrintError("Failed to write plugin.json: %v", err)
		return err
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin.py"), []byte(pyContent), 0644); err != nil {
		output.PrintError("Failed to write plugin.py: %v", err)
		return err
	}

	output.PrintSuccess("Created new plugin: %s", pluginName)
	output.PrintInfo("Location: %s", pluginDir)
	output.PrintInfo("Edit plugin.py to add your logic!")
	return nil
}
