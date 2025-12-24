import re
import json
import os
import logging

# Global pattern cache
PATTERNS_CACHE = None

def load_patterns():
    global PATTERNS_CACHE
    if PATTERNS_CACHE:
        return PATTERNS_CACHE

    # Locate signatures file
    # We assume CWD is project root, or try relative to plugin file
    possible_paths = [
        os.path.join("data", "signatures", "service_patterns.json"),
        os.path.join("..", "..", "..", "data", "signatures", "service_patterns.json"), # If CWD is plugin dir
    ]

    for path in possible_paths:
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    PATTERNS_CACHE = json.load(f)
                    return PATTERNS_CACHE
            except Exception as e:
                logging.error(f"Error parsing service signatures {path}: {e}")
    
    logging.warning("Service signatures file not found. Using empty set.")
    return {"ports": {}, "generic": []}

def run(context):
    """
    Parses banner to identify service and version using external signatures.
    """
    debug = context.get('debug', lambda x: None)
    debug("Parsing banner for service identification...")
    
    banner = context.get('banner', '')
    if not banner:
        return None
    
    port = context.get('port', 0)
    data = load_patterns()
    
    # 1. Port-Specific Patterns
    # Keys in JSON are strings
    port_str = str(port)
    patterns = data.get("ports", {}).get(port_str, [])
    
    for p in patterns:
        try:
            regex = p.get("regex")
            if not regex: continue
            
            match = re.search(regex, banner, re.IGNORECASE)
            if match:
                version_tmpl = p.get("version", "unknown")
                cpe_tmpl = p.get("cpe", "")
                
                version = "unknown"
                try:
                    # 1-based indexing logic
                    version = version_tmpl.format(None, *match.groups())
                except (IndexError, ValueError):
                     version = "unknown"

                # Generate CPE
                cpe = ""
                if cpe_tmpl:
                    try:
                         cpe = cpe_tmpl.format(None, *match.groups())
                    except:
                        pass
                
                result = {
                    "service_name": p.get("name", "unknown"),
                    "service_version": version,
                    "confidence": 0.95
                }
                if cpe:
                    result["cpe"] = cpe
                return result

        except Exception as e:
            debug(f"Regex error on pattern {p}: {e}")
            continue

    # 2. Generic Patterns
    generic_patterns = data.get("generic", [])
    for p in generic_patterns:
        try:
            regex = p.get("regex")
            match = re.search(regex, banner, re.IGNORECASE)
            if match:
                version_tmpl = p.get("version", "unknown")
                cpe_tmpl = p.get("cpe", "")
                
                version = "unknown"
                try:
                    version = version_tmpl.format(None, *match.groups())
                except:
                    version = "unknown"

                cpe = ""
                if cpe_tmpl:
                    try:
                         cpe = cpe_tmpl.format(None, *match.groups())
                    except:
                        pass

                result = {
                    "service_name": p.get("name", "unknown"),
                    "service_version": version,
                    "confidence": 0.5
                }
                if cpe:
                    result["cpe"] = cpe
                return result
        except:
            continue
            
    return None
