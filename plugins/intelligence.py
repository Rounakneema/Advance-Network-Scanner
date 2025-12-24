# plugins/intelligence.py
import sys
import json
import os
import logging
import re
import struct # For packing/unpacking binary lengths
import socket # For direct socket probes (e.g., SMTP, POP3, IMAP, NNTP)
import ssl # For basic SSL context for probes (e.g., SMTPS, POP3S, IMAPS)
import requests # For making HTTP/HTTPS requests (client-side probing)

# Disable insecure request warnings for requests.head(verify=False)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Configure logging for the Python script
logging.basicConfig(level=logging.ERROR, format='[Python Intelligence Script] %(levelname)s: %(message)s', stream=sys.stderr)

# --- IMPORTANT: Adjust sys.path for protobuf imports ---
generated_ipc_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'ipc'))
if generated_ipc_path not in sys.path:
    sys.path.insert(0, generated_ipc_path)

# Add plugins/probe directory to sys.path
probe_loader_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'probe'))
if probe_loader_dir not in sys.path:
    sys.path.insert(0, probe_loader_dir)


try:
    import revealr_pb2 as pb2
    import probes.probe_loader as probe_loader
    from loader import PluginManager # Import our new generic plugin manager
except ImportError as e:
    logging.error(f"FATAL: Protobuf or Probe Loader import failed: {e}")
    logging.error("sys.path: %s", sys.path)
    logging.error("Verify 'revealr_pb2.py' is in 'plugins/ipc/' and 'plugins/probe/probe_loader.py' is reachable via sys.path.")
    sys.exit(1)


# --- Load Custom Probes Database ---
CUSTOM_PROBES_FILE = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)), 'data', 'probes', 'custom_probes.json')
PROBE_DB = None
try:
    PROBE_DB = probe_loader.load_custom_probes(CUSTOM_PROBES_FILE)
    if PROBE_DB is None:
        logging.error("FATAL: Custom probes database could not be loaded. Service detection will be limited.")
except Exception as e:
    logging.error(f"FATAL: Error loading custom probes: {e}. Service detection will be limited.", exc_info=True)

# --- Initialize Plugin Manager ---
PLUGIN_MANAGER = None
try:
    # Use the directory containing this script (plugins/) as the base
    plugin_base_dir = os.path.dirname(__file__)
    PLUGIN_MANAGER = PluginManager(plugin_base_dir)
except Exception as e:
    logging.error(f"Error initializing PluginManager: {e}")


# --- Service Fingerprinting Logic (Custom Probes/Patterns defined here at module level) ---
# NOTE: These patterns are for string matching in the fallback `identify_service_from_banner`
# when PROBE_DB is not effective or loaded.
# --- Service Fingerprinting Logic ---
# MOVED TO PLUGINS: plugins/core/service/svc_banner_parser
SERVICE_PATTERNS = {}

# MOVED TO PLUGINS: plugins/core/network/net_os_fingerprint
OS_INFERENCE_PATTERNS = {}

def infer_os_from_service(service_name):
    """Infer OS based on service name (basic application exclusivity)."""
    lower_service_name = service_name.lower()
    for pattern, os_name in OS_INFERENCE_PATTERNS.items():
        if pattern in lower_service_name:
            return os_name
    return "unknown"


def identify_service_from_banner(port_number, banner_text):
    """
    Attempts to identify service and version from a raw banner using custom regex patterns.
    Returns (service_name, service_version).
    """
    service_name = "unknown"
    service_version = ""
    
    # Ensure banner_text is treated as string for pattern matching, but convert to bytes for byte regexes.
    if isinstance(banner_text, bytes):
        banner_bytes = banner_text
        banner_str = banner_text.decode('latin-1', errors='ignore')
    else:
        banner_bytes = banner_text.encode('latin-1', errors='ignore')
        banner_str = banner_text
    
    lower_banner_str = banner_str.lower()


    # --- Try matching against custom probes (byte regex) from PROBE_DB ---
    if PROBE_DB:
        # We iterate through ALL probes for banner matching because the initial banner
        # isn't specific to a probe. We try to find any match for any probe's pattern.
        
        # FIX: Prioritize more specific/common probes first if possible, then general ones.
        # This is a simplification without full Nmap probe selection, but better than random order.
        prioritized_probe_names = ["RDP_COOKIE", "HTTP_GET", "FTP_HELP", "SMTP_HELO", "POP3_USER", "IMAP_CAPABILITY", "NNTP_HELP", "MySQL_HANDSHAKE", "Redis_PING", "NULL", "GenericLines"]
        
        # Build a list of probes to check based on priority, then all others.
        probes_to_check = []
        for name in prioritized_probe_names:
            p = PROBE_DB.get_probe_by_name(name)
            if p: # Ensure probe exists in our loaded DB
                probes_to_check.append(p)
        
        # Add any other probes not specifically prioritized (shouldn't happen with full list)
        for p in PROBE_DB.probes:
            if p not in probes_to_check: # Check if already added
                probes_to_check.append(p)

        for probe_obj in probes_to_check:
            # First, check strong matches
            for match_rule in probe_obj.matches:
                match = match_rule.pattern.search(banner_bytes)
                if match:
                    service_name = match_rule.service
                    version_info_str = match_rule.version_info
                    if version_info_str and re.match(r"\$\d+", version_info_str):
                        try:
                            group_index = int(version_info_str[1:])
                            if group_index <= len(match.groups()):
                                captured_group = match.group(group_index)
                                if isinstance(captured_group, bytes):
                                    service_version = captured_group.decode('latin-1', errors='ignore')
                                else:
                                    service_version = captured_group
                        except (ValueError, IndexError):
                            pass
                    elif version_info_str:
                        service_version = version_info_str
                    return service_name, service_version # Return on first hard match
            
            # Then, check soft matches
            if hasattr(probe_obj, 'soft_matches'): 
                for soft_match_rule in probe_obj.soft_matches:
                    match = soft_match_rule.pattern.search(banner_bytes)
                    if match:
                        if service_name == "unknown" or "generic" in service_name.lower() or "banner:" in service_name.lower():
                            service_name = soft_match_rule.service
                            version_info_str = soft_match_rule.version_info
                            if version_info_str and re.match(r"\$\d+", version_info_str):
                                try:
                                    group_index = int(version_info_str[1:])
                                    if group_index <= len(match.groups()):
                                        captured_group = match.group(group_index)
                                        if isinstance(captured_group, bytes):
                                            service_version = captured_group.decode('latin-1', errors='ignore')
                                        else:
                                            service_version = captured_group
                                except (ValueError, IndexError):
                                    pass
                            elif version_info_str:
                                service_version = version_info_str


    # --- Fallback to simple port-based or generic banner string matching ---
    if service_name == "unknown":
        # Check simple string patterns for specific ports (when PROBE_DB doesn't give a match)
        if port_number in SERVICE_PATTERNS: 
            for pattern_str, name, version_group in SERVICE_PATTERNS[port_number]:
                pattern = re.compile(pattern_str, re.DOTALL | re.IGNORECASE)
                match = pattern.search(lower_banner_str) # Match against string banner
                if match:
                    service_name = name
                    if version_group:
                        if version_group.startswith("{") and version_group.endswith("}"):
                            try:
                                group_index = int(version_group[1:-1])
                                if group_index <= len(match.groups()):
                                    service_version = match.group(group_index)
                            except ValueError:
                                pass
                        else:
                            service_version = version_group
                    return service_name, service_version
        
        # Last resort: return truncated banner if still unknown
        if lower_banner_str:
            return f"banner: {lower_banner_str[:50]}", "" 

    return service_name, service_version

def probe_service_from_python(ip_address, port_number, protocol, initial_banner, scan_timing_level="default"):
    """
    Sends a basic application-layer probe based on port/protocol.
    Returns (service_name, service_version, details_dict).
    """
    service_name = "unknown"
    service_version = ""
    details = {}
    
    # Determine effective timeout based on scan_timing_level
    base_socket_timeout = 15 # Default for 'normal'
    base_http_timeout = 20   # Default for 'normal'

    # Define multipliers for scan timing levels (Nmap -T0 to -T5)
    SCAN_TIMING_MULTIPLIERS = {
        "paranoid": 3.0,   # -T0 in Nmap terms
        "stealthy": 2.0,   # -T1
        "polite":   1.5,   # -T2
        "normal":   1.0,   # -T3 (default)
        "aggressive": 0.8, # -T4
        "insane":   0.5,   # -T5
        "default":  1.0    # Ensure default is handled
    }
    multiplier = SCAN_TIMING_MULTIPLIERS.get(scan_timing_level.lower(), 1.0)
    effective_socket_timeout = base_socket_timeout * multiplier
    effective_http_timeout = base_http_timeout * multiplier
    
    # MOVED TO PLUGINS: plugins/core/service/svc_tls_inspector
    # TLS Probing is now handled by the plugin system.

    # HTTP/HTTPS Probing

    # MOVED TO PLUGINS: plugins/core/web/web_tech_stack
    # HTTP Probing is now handled by the plugin system.

    # Direct socket probes for text-based protocols (FTP, SMTP, POP3, IMAP, NNTP, etc.)
    if protocol == "tcp" and port_number in [21, 25, 110, 143, 119, 587, 465, 993, 995]: 
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(effective_socket_timeout) # Overall timeout
            
            is_ssl_port = port_number in [465, 993, 995]
            if is_ssl_port:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try:
                    sock = context.wrap_socket(sock, server_hostname=ip_address)
                    logging.info(f"  Python: Attempting SSL/TLS handshake for {ip_address}:{port_number}")
                except ssl.SSLError as e:
                    logging.warning(f"  Python SSL Handshake Failed for {ip_address}:{port_number}: {e}. Skipping application probe.")
                    details['ssl_handshake_error'] = str(e)
                    return "ssl/unknown", "", details # Indicate SSL port, but detection failed
            
            sock.connect((ip_address, port_number))

            full_response_bytes = b"" # Store response as bytes
            try:
                sock.settimeout(min(3, effective_socket_timeout / 2)) # Shorter timeout for initial read (allow banner to come in)
                initial_socket_banner_bytes = sock.recv(4096)
                full_response_bytes += initial_socket_banner_bytes
            except socket.timeout:
                pass # No initial response, or timed out

            # --- Custom Probe Selection & Execution ---
            probes_to_try = []
            if PROBE_DB:
                applicable_probes = PROBE_DB.get_probes_for_port(port_number, "tcp")
                
                generic_lines_probe = PROBE_DB.get_probe_by_name("GenericLines")
                null_probe = PROBE_DB.get_probe_by_name("NULL")

                if generic_lines_probe and port_number in generic_lines_probe.ports: # Check if port is in probe's ports
                    probes_to_try.append(generic_lines_probe)
                if null_probe and port_number in null_probe.ports: # Check if port is in probe's ports
                    probes_to_try.append(null_probe)

                # Add all other applicable probes from custom DB
                for p in applicable_probes:
                    if p.probename not in [x.probename for x in probes_to_try]: # Check if already added
                        probes_to_try.append(p)
            
            # Fallback to hardcoded simple probes if no custom probes loaded or applicable
            if not probes_to_try:
                # Create Probe objects for these hardcoded ones
                probes_to_try.append(probe_loader.Probe("GENERIC_NL", "TCP", "\r\n", [], [], [], soft_matches_data=[])) # Added soft_matches_data
                if port_number == 21: probes_to_try.append(probe_loader.Probe("FTP_HELP", "TCP", "HELP\r\n", [], [], [], soft_matches_data=[]))
                elif port_number in [25, 587, 465]: probes_to_try.append(probe_loader.Probe("SMTP_HELO", "TCP", "HELO revealr.scanner\r\n", [], [], [], soft_matches_data=[]))
                elif port_number == 119: probes_to_try.append(probe_loader.Probe("NNTP_HELP", "TCP", "HELP\r\n", [], [], [], soft_matches_data=[]))
                elif port_number in [110, 995]: probes_to_try.append(probe_loader.Probe("POP3_USER", "TCP", "USER anonymous\r\n", [], [], [], soft_matches_data=[]))
                elif port_number in [143, 993]: probes_to_try.append(probe_loader.Probe("IMAP_CAPA", "TCP", "a001 CAPABILITY\r\n", [], [], [], soft_matches_data=[]))
            
            logging.info(f"  Python: Preparing {len(probes_to_try)} probes for {ip_address}:{port_number}")

            # Execute probes sequentially
            for probe in probes_to_try:
                logging.info(f"  Python: Sending custom probe '{probe.probename}' to {ip_address}:{port_number}")
                
                try:
                    sock.settimeout(min(7, effective_socket_timeout / 2)) # Shorter timeout for individual probe send/recv
                    sock.sendall(probe.probestring) # probestring is already bytes from probe_loader.py
                    probe_socket_response_bytes = sock.recv(4096)
                    full_response_bytes += probe_socket_response_bytes
                    
                    name, version = identify_service_from_banner(port_number, full_response_bytes.decode('latin-1', errors='ignore'))
                    if name != "unknown":
                        if is_ssl_port and not name.startswith("ssl/"): name = "ssl/" + name
                        elif port_number == 587 and "submission" in name.lower() and not name.startswith("tls/"): name = "tls/" + name
                        return name, version, details # Found it!
                except socket.timeout:
                    logging.warning(f"  Python Socket Probe Response Timeout for {ip_address}:{port_number} (Probe: {probe.probename})")
                except Exception as e:
                    logging.warning(f"  Python Socket Probe Error for {ip_address}:{port_number} (Probe: {probe.probename}): {e}")
            
            sock.close()

            name, version = identify_service_from_banner(port_number, full_response_bytes.decode('latin-1', errors='ignore'))
            if name != "unknown":
                if is_ssl_port and not name.startswith("ssl/"): name = "ssl/" + name
                elif port_number == 587 and "submission" in name.lower() and not name.startswith("tls/"): name = "tls/" + name
                return name, version, details
            
            if not initial_banner and full_response_bytes:
                details['full_socket_banner'] = full_response_bytes.decode('latin-1', errors='ignore') # Store as string
                return f"banner: {details['full_socket_banner'][:50] if len(details['full_socket_banner']) > 50 else details['full_socket_banner']}", "", details

        except socket.timeout:
            logging.warning(f"  Python Socket Probe Timeout during connect for {ip_address}:{port_number}")
        except ConnectionRefusedError:
            logging.warning(f"  Python Socket Probe Connection Refused for {ip_address}:{port_number}")
        except Exception as e:
            logging.warning(f"  Python Socket Probe Error for {ip_address}:{port_number}: {e}")
    
    return service_name, service_version, details # Default unknown


# MOVED TO PLUGINS: plugins/core/web/web_tech_stack
# def probe_http_service(...): ...


# MOVED TO PLUGINS: plugins/core/service/svc_tls_inspector
# def probe_tls_certificate(ip, port, timeout): ...


def process_scan_result_script():
    """
    Reads a serialized ScanResultRequest from stdin, processes it,
    and writes enriched data (if any) to stdout.
    """
    # This initial log will always print, as it's outside the conditional level setting.
    logging.info("Python intelligence script started.") 

    try:
        length_bytes = sys.stdin.buffer.read(4)
        if not length_bytes or len(length_bytes) != 4:
            logging.error(f"FATAL: Failed to read 4-byte length prefix from stdin. Read {len(length_bytes)} bytes. Exiting.")
            sys.exit(1)
        
        message_length = struct.unpack('>I', length_bytes)[0]
        logging.debug(f"Python: Unpacked message length: {message_length} bytes.")
        
        serialized_request = sys.stdin.buffer.read(message_length)
        if len(serialized_request) != message_length:
            logging.error(f"FATAL: Read {len(serialized_request)} bytes, but expected {message_length} from stdin. Exiting.")
            sys.exit(1)

        request = pb2.ScanResultRequest()
        request.ParseFromString(serialized_request)

        # FIX: Set Python logging level based on Go's debug config
        if hasattr(request.scan_config, 'debug') and request.scan_config.debug:
            logging.getLogger().setLevel(logging.DEBUG) # If Go is debug, Python is DEBUG (show all)
            logging.info("Python: Debug mode enabled from Go config.")
        else:
            # FIX: If Go is NOT debug, Python is WARNING. This will suppress most general INFOs, but show IMPORTANT WARNINGS
            # If you want to suppress WARNINGS too by default, change to logging.ERROR
            logging.getLogger().setLevel(logging.WARNING) 
        
        logging.info(f"Received scan result for Host ID: {request.host.id}, IP: {request.host.ip_address} (Scan ID: {request.scan_id})")

        enriched_data = []

        for port in request.host.ports:
            original_service_name = port.service.name
            original_service_version = port.service.version
            details_dict = dict(port.details)
            raw_banner = details_dict.get("banner", "")

            # Default to Go's initial guess
            new_service_name, new_service_version, new_details = original_service_name, original_service_version, details_dict

            # Decode Advanced Mode from ScanTiming string (Workaround)
            raw_timing = request.scan_config.scan_timing
            scan_timing_level = raw_timing
            advanced_mode = False
            if "|advanced" in raw_timing:
                scan_timing_level = raw_timing.replace("|advanced", "")
                advanced_mode = True
                logging.info("Python: Advanced Mode ENABLED (via timing flag)")

            # --- Primary Python Intelligence (Banner-based & Probing) ---
            
            # Attempt to identify service from raw banner first
            inferred_name, inferred_version = identify_service_from_banner(port.port_number, raw_banner)
            if inferred_name != "unknown":
                new_service_name = inferred_name
                new_service_version = inferred_version
                logging.info(f"  Python: Banner identified {new_service_name} v{new_service_version} on {port.port_number}")
            else: # If banner-based inference failed or was 'unknown', try active probing from Python
                # Pass scan_timing_level to probe_service_from_python
                # The request.scan_config.scan_timing is the overall scan timing (e.g., "fast")
                probed_name, probed_version, probed_details = probe_service_from_python(
                    request.host.ip_address, 
                    port.port_number, 
                    port.protocol, 
                    raw_banner, 
                    scan_timing_level # Pass the cleaned scan_timing level
                )
                
                if probed_name != "unknown": # If Python probe found something specific
                    new_service_name = probed_name
                    new_service_version = probed_version
                    if probed_details: # Merge only if probe actually returned details
                        new_details.update(probed_details) 
                    logging.info(f"  Python: Probe identified {new_service_name} v{new_service_version} on {port.port_number}")
                elif original_service_name == "unknown" and raw_banner: # If Go & Python probe failed, but raw banner exists
                    new_service_name = f"banner: {raw_banner[:50] if len(raw_banner) > 50 else raw_banner}" # Fallback to truncated banner
            
            # --- End Primary Python Intelligence ---

            # Also infer OS based on the *final* service name
            inferred_os = infer_os_from_service(new_service_name)

            if inferred_os != "unknown":
                if 'os' not in new_details or new_details['os'] == "unknown": # Only add if not already present or unknown
                    new_details['os'] = inferred_os
                    logging.info(f"  Python: Inferred OS for {request.host.ip_address}:{port.port_number} -> {inferred_os}")

            # --- Plugin Execution ---
            if PLUGIN_MANAGER:
                plugin_results = PLUGIN_MANAGER.run_all_plugins(
                    request.host.ip_address, 
                    port.port_number, 
                    new_service_name, 
                    raw_banner, 
                    new_details,
                    advanced_mode=advanced_mode # Pass decoded advanced mode flag
                )
                if plugin_results:
                    # Check for core overrides from plugins
                    if "service_name" in plugin_results:
                         new_service_name = plugin_results.pop("service_name")
                    if "service_version" in plugin_results:
                         new_service_version = plugin_results.pop("service_version")
                    
                    # Merge remaining findings into details
                    new_details.update(plugin_results)
                    logging.info(f"  Python: Plugins added {len(plugin_results)} details for {port.port_number}")
            # --- End Plugin Execution ---

            # If detection changed or added details, prepare an update
            # Compare final new_service_name/version with original Go guess
            # and check if any new details were added.
            if new_service_name != original_service_name or \
               new_service_version != original_service_version or \
               len(new_details) > len(details_dict): # Check if any details were added/changed
                logging.info(f"  Enrichment update for {request.host.ip_address}:{port.port_number} - Go: {original_service_name} -> Python: {new_service_name} v{new_service_version}")
                # Serialize complex types in details map for Go compatibility (map[string]string)
                safe_details = {}
                for k, v in new_details.items():
                    if isinstance(v, (list, dict, bool, int, float)):
                        safe_details[k] = json.dumps(v)
                    else:
                        safe_details[k] = str(v)

                enriched_data.append({
                    "host_id": request.host.id, # Needs to be included for Go to correlate
                    "port_number": port.port_number,
                    "protocol": port.protocol,
                    "service_name": new_service_name,
                    "service_version": new_service_version,
                    "details": safe_details # Pass back potentially updated details map
                })
            
        # Serialize enriched data (if any) and write to stdout as JSON
        if enriched_data:
            json_output = json.dumps(enriched_data)
            sys.stdout.write(json_output)
            sys.stdout.flush()
            logging.info(f"Enriched data for {len(enriched_data)} ports sent to stdout.")
        else:
            logging.info("No enrichment data to send back.")

    except Exception as e:
        logging.error(f"Error in Python intelligence script: {e}", exc_info=True)
        error_response = {"error": str(e), "status": "failed"}
        sys.stdout.write(json.dumps(error_response))
        sys.stdout.flush()
        sys.exit(1)


if __name__ == '__main__':
    process_scan_result_script()