# plugins/probe/probe_loader.py
import json
import os
import logging
import re # Needed for compiling regex patterns in Match objects
import sys # For sys.stderr in logging config

logging.basicConfig(level=logging.INFO, format='[Probe Loader] %(levelname)s: %(message)s', stream=sys.stderr)
# In plugins/probe/probe_loader.py

# ... (existing imports and logging setup) ...

# --- Helper Function for String to Bytes Conversion (MOVED TO TOP) ---
# FIX: Define this helper function BEFORE any classes or functions that use it.
def _convert_string_to_bytes_with_escapes(pattern_str_raw: str) -> bytes:
    """
    Converts escaped sequences like \\x41 into raw bytes.
    """
    try:
        return pattern_str_raw.encode('latin-1').decode('unicode_escape').encode('latin-1')
    except Exception:
        return pattern_str_raw.encode('latin-1')
    
class Probe:
    """Represents a single custom probe definition."""
    # FIX: Ensure soft_matches_data is optional and defaults to None if not provided by JSON
    def __init__(self, probename, protocol, probestring_raw, ports, ssl_ports, matches_data, soft_matches_data=None, timeout=None):
        self.probename = probename
        self.protocol = protocol
        self.probestring = _convert_string_to_bytes_with_escapes(probestring_raw) # Convert probestring to bytes here
        self.ports = ports
        self.ssl_ports = ssl_ports
        self.timeout = timeout
        
        self.matches = [Match(m['service'], m['pattern'], m.get('version_info', ''), m.get('flags', '')) for m in matches_data]
        
        # FIX: Initialize soft_matches as an empty list if soft_matches_data is None or empty
        self.soft_matches = []
        if soft_matches_data:
            self.soft_matches = [Match(m['service'], m['pattern'], m.get('version_info', ''), m.get('flags', '')) for m in soft_matches_data]


    def __repr__(self):
        return f"Probe({self.probename} {self.protocol} ports={self.ports} sslports={self.ssl_ports} timeout={self.timeout})"


class Match:
    """Represents a single match rule for a probe."""
    def __init__(self, service, pattern_str, version_info="", flags=""):
        self.service = service
        self.pattern_str = pattern_str  # raw string from JSON
        self.version_info = version_info

        re_flags = re.DOTALL
        if 'i' in flags:
            re_flags |= re.IGNORECASE
        if 'm' in flags:
            re_flags |= re.MULTILINE

        try:
            # Compile as bytes regex for binary-safe matching
            self.pattern = re.compile(pattern_str.encode('latin-1', errors='ignore'), re_flags)
        except re.error as e:
            logging.error(
                f"Failed to compile regex for service '{service}': {e} -> Pattern: '{pattern_str}' Flags: '{flags}'"
            )
            # Fallback: literal byte match
            self.pattern = re.compile(re.escape(pattern_str).encode('latin-1', errors='ignore'))

class CustomProbeDB:
    """Holds the parsed custom probe database."""
    def __init__(self):
        self.probes = []
        self.probes_by_name = {}
        self.probes_by_port = {} # {port: {protocol: [probes]}}

    def add_probe(self, probe):
        self.probes.append(probe)
        self.probes_by_name[probe.probename] = probe

        for p in probe.ports:
            if p not in self.probes_by_port:
                self.probes_by_port[p] = {"tcp": [], "udp": []}
            self.probes_by_port[p][probe.protocol.lower()].append(probe)
        for p in probe.ssl_ports:
            if p not in self.probes_by_port:
                self.probes_by_port[p] = {"tcp": [], "udp": []}
            self.probes_by_port[p][probe.protocol.lower()].append(probe)

    def get_probes_for_port(self, port, protocol):
        """Returns a list of probes applicable to a given port and protocol."""
        return self.probes_by_port.get(port, {}).get(protocol.lower(), [])

    def get_probe_by_name(self, probename):
        """Returns a probe by its name."""
        return self.probes_by_name.get(probename)


def load_custom_probes(filepath):
    """Loads probes from a JSON file."""
    db = CustomProbeDB()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for probe_data in data:
                probe = Probe(
                    probename=probe_data['probename'],
                    protocol=probe_data['protocol'],
                    probestring_raw=probe_data['probestring'], # Pass raw string
                    ports=probe_data.get('ports', []),
                    ssl_ports=probe_data.get('sslports', []),
                    matches_data=probe_data.get('matches', []),
                    soft_matches_data=probe_data.get('soft_matches', []), # Pass soft_matches_data
                    timeout=probe_data.get('timeout')
                )
                db.add_probe(probe)
        logging.info(f"Successfully loaded {len(db.probes)} custom probes from {filepath}")
        return db
    except FileNotFoundError:
        logging.error(f"Error: Custom probes file not found at {filepath}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error: Malformed JSON in custom probes file {filepath}: {e}")
        return None
    except Exception as e:
        logging.error(f"Error loading custom probes from {filepath}: {e}", exc_info=True)
        return None