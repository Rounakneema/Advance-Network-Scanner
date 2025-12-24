import os
import sys
import json
import importlib.util
import logging

class PluginManager:
    """
    Manages loading and execution of Revealr Intelligence Plugins.
    
    Architecture:
    - Scans 'core', 'community', and 'local' directories.
    - Each plugin MUST be a folder with a 'plugin.json' metadata file.
    - The entry point is defined in 'plugin.json' (default: plugin.py).
    """
    def __init__(self, base_dir="plugins"):
        self.base_dir = os.path.abspath(base_dir)
        # Order matters: Local overrides Community overrides Core (if we implemented overriding, but for now just load all)
        self.plugin_categories = ['core', 'community', 'local']
        self.plugins = []
        self.load_plugins()

    def load_plugins(self):
        """Scans all category directories for valid plugins."""
        self.plugins = [] # Reset
        logging.info(f"[PluginManager] Scanning for plugins in {self.base_dir}...")

        for category in self.plugin_categories:
            cat_path = os.path.join(self.base_dir, category)
            if not os.path.exists(cat_path):
                continue
            
            # Recursively walk to find plugin.json files
            for root, dirs, files in os.walk(cat_path):
                if "plugin.json" in files:
                    self.load_single_plugin(root, category)
        
        # Sort plugins by execution priority
        PRIORITY = {
            "network": 10,
            "service": 20,
            "web": 30,
            "auth": 40,
            "vuln": 50,
            "intelligence": 60
        }
        self.plugins.sort(key=lambda p: PRIORITY.get(p["metadata"].get("type", "other"), 99))
        
        logging.info(f"[PluginManager] Loaded {len(self.plugins)} plugins.")

    def load_single_plugin(self, plugin_dir, category):
        """Validates and loads a plugin from a directory."""
        meta_file = os.path.join(plugin_dir, "plugin.json")
        
        # 1. Check for Metadata
        if not os.path.exists(meta_file):
            # logging.debug(f"[PluginManager] Skipping {plugin_dir}: No plugin.json found")
            return

        try:
            with open(meta_file, 'r') as f:
                metadata = json.load(f)
            
            # 2. Validate Metadata
            if "name" not in metadata or "entry" not in metadata:
                logging.warning(f"[PluginManager] Invalid plugin.json in {plugin_dir}: Missing 'name' or 'entry'")
                return
            
            plugin_name = metadata["name"]
            entry_file = metadata["entry"]
            
            # 3. Load Module
            entry_path = os.path.join(plugin_dir, entry_file)
            if not os.path.exists(entry_path):
                logging.warning(f"[PluginManager] Plugin {plugin_name} entry file not found: {entry_path}")
                return

            # Dynamic Import
            spec = importlib.util.spec_from_file_location(f"revealr_plugin_{plugin_name}", entry_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module # Register to sys.modules to allow relative imports inside plugin
                spec.loader.exec_module(module)
                
                if hasattr(module, "run") and callable(module.run):
                    self.plugins.append({
                        "name": plugin_name,
                        "metadata": metadata,
                        "module": module,
                        "category": category,
                        "path": plugin_dir
                    })
                    logging.debug(f"[PluginManager] Loaded [{category}] {plugin_name} ({metadata.get('version', '0.0.0')})")
                else:
                    logging.warning(f"[PluginManager] Plugin {plugin_name} skipped: Missing 'run' function.")

        except Exception as e:
            logging.error(f"[PluginManager] Error loading plugin from {plugin_dir}: {e}")

    def run_all_plugins(self, ip, port, service_name, banner, details, advanced_mode=False):
        """
        Runs all loaded plugins against a specific target.
        """
        aggregated_results = {}
        
        # Context object passed to plugins
        # Allows us to expand inputs later without changing signature
        context = {
            "target": ip,
            "port": port,
            "service": service_name,
            "banner": banner,
            "details": details,
            "advanced": advanced_mode # Pass the flag to plugins
        }

        for plugin in self.plugins:
            # Check inputs/filters from metadata if they exist
            # e.g. "inputs": ["service:http"]
            meta = plugin["metadata"]
            if not self._check_plugin_applicability(meta, service_name, port):
                continue

            # Inject a scoped debug helper for this plugin
            # Users can call context['debug']("checking X") -> [PluginName] checking X
            def scoped_debug(msg):
                logging.debug(f"[{plugin['name']}] {msg}")
            
            context['debug'] = scoped_debug

            try:
                # Execute
                result = plugin["module"].run(context)
                
                if result and isinstance(result, dict):
                    # logging.info(f"[PluginManager] '{plugin['name']}' matched on {ip}:{port}")
                    aggregated_results.update(result)
                    
                    # Update context for subsequent plugins (Pipeline)
                    # We merge findings into 'details' so later plugins can see them
                    context['details'].update(result)
            except Exception as e:
                logging.error(f"[PluginManager] Runtime error in {plugin['name']}: {e}")
        
        return aggregated_results

    def _check_plugin_applicability(self, meta, service_name, port):
        """Simple filter to avoid running HTTP plugins on SSH ports."""
        inputs = meta.get("inputs", [])
        if not inputs:
            return True # No filters, run everywhere (careful!)

        # Simple logic: If any input rule matches, run it.
        # Rules: "service:name", "port:80"
        match = False
        for rule in inputs:
            if rule.startswith("service:"):
                target_svc = rule.split(":")[1]
                if target_svc == "*" or target_svc.lower() in service_name.lower():
                    match = True
            elif rule.startswith("port:"):
                try:
                    target_port = int(rule.split(":")[1])
                    if target_port == port:
                        match = True
                except:
                    pass
            elif rule == "*":
                match = True
        
        return match
