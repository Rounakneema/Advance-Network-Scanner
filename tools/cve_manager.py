
import sqlite3
import json
import os
import argparse
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'vuln_db', 'cves.db')

def init_db():
    """Initialize the SQLite database schema."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create table for CVE entries
    # We store one row per affected product range. A single CVE may have multiple rows.
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS cves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        product TEXT NOT NULL,
        vendor TEXT,
        version_min TEXT,  -- Inclusive start (e.g. "2.0")
        version_max TEXT,  -- Exclusive end (e.g. "2.4.50")
        severity TEXT,
        description TEXT,
        UNIQUE(cve_id, product, version_min, version_max)
    )
    ''')
    
    # Index for fast lookup
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_product ON cves(product)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cve_id ON cves(cve_id)')
    
    conn.commit()
    conn.close()
    logging.info(f"Database initialized at {DB_PATH}")

def normalize_product(vendor, product):
    """
    Normalize vendor/product to a consistent string key.
    Example: vendor='apache', product='http_server' -> 'apache_http_server'
    Example: vendor='openbsd', product='openssh' -> 'openssh' (special rule)
    """
    # Specific overrides to match our scanner's service names
    if product == 'http_server' and vendor == 'apache':
        return 'apache_http_server'
    if product == 'openssh':
        return 'openssh'
        
    # Default fallback
    return f"{vendor}_{product}".lower()

def parse_nvd_json(filepath):
    """Parse NVD JSON file and yield simplified CVE entries. Supports NVD 1.1 and 2.0."""
    logging.info(f"Parsing {filepath}...")
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Check version/format
    is_v2 = 'vulnerabilities' in data
    
    items = data.get('vulnerabilities', []) if is_v2 else data.get('CVE_Items', [])
    logging.info(f"Found {len(items)} items. Processing (Format: {'2.0' if is_v2 else '1.1'})...")
    
    for item in items:
        # Normalize item structure to simpler object
        cve_data = item.get('cve', {})
        
        # ID
        cve_id = "Unknown"
        if is_v2:
             cve_id = cve_data.get('id')
        else:
             cve_id = cve_data.get('CVE_data_meta', {}).get('ID')
             
        if not cve_id:
            continue
            
        # Description
        description = "No description"
        if is_v2:
            descs = cve_data.get('descriptions', [])
            if descs:
                description = descs[0].get('value', '')
        else:
            desc_data = cve_data.get('description', {}).get('description_data', [])
            if desc_data:
                description = desc_data[0].get('value', '')

        # Severity
        severity = "Unknown"
        if is_v2:
             metrics = cve_data.get('metrics', {})
             # V3.1
             if 'cvssMetricV31' in metrics:
                 severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
             # V2
             elif 'cvssMetricV2' in metrics:
                 severity = metrics['cvssMetricV2'][0]['baseSeverity'] # V2 might be different key in 2.0? Usually 'baseSeverity' or 'severity'
        else:
             impact = item.get('impact', {})
             if 'baseMetricV3' in impact:
                 severity = impact['baseMetricV3']['cvssV3']['baseSeverity']
             elif 'baseMetricV2' in impact:
                 severity = impact['baseMetricV2']['severity']
                 
        # Configurations / CPEs
        configs = cve_data.get('configurations', []) if is_v2 else item.get('configurations', {})
        nodes = []
        
        # 1.1 vs 2.0 structure slight diff in 'configurations'
        # 2.0: "configurations": [ { "nodes": [...] } ]
        # 1.1: "configurations": { "nodes": [...] }
        
        if is_v2:
             for config in configs:
                 nodes.extend(config.get('nodes', []))
        else:
             nodes = configs.get('nodes', [])
             
        for node in nodes:
            # We simplified handle "OR" operator for CPE matches
            if node.get('operator') == 'OR':
                for match in node.get('cpeMatch', []) if is_v2 else node.get('cpe_match', []):
                    # v2 uses 'cpeMatch', v1.1 'cpe_match'
                    if match.get('vulnerable'):
                        cpe_uri = match.get('criteria') if is_v2 else match.get('cpe23Uri') # v2 uses 'criteria', v1.1 'cpe23Uri'
                        if not cpe_uri:
                            continue
                            
                        # Parse CPE: cpe:2.3:part:vendor:product:version:update...
                        parts = cpe_uri.split(':')
                        if len(parts) < 5:
                            continue
                            
                        vendor = parts[3]
                        product_name = parts[4]
                        
                        norm_product = normalize_product(vendor, product_name)
                        
                        # Get version ranges
                        v_start = match.get('versionStartIncluding') or match.get('versionStartExcluding') or "*"
                        v_end = match.get('versionEndExcluding') # Exclusive end is most common
                        
                        # If specific version in CPE (not wildcards)
                        if parts[5] != '*' and parts[5] != '-':
                             v_start = parts[5]
                             v_end = parts[5] # Treating specific version as range [ver, ver] is tricky with < logic.
                             # For now, let's treat it as min=ver, max=ver (inclusive) logic requires handling 
                             # We will store it. The plugin must compare differently if min==max.
                             # Or we define max as "Next Version" but we don't know it.
                             # Alternative: Store exact version in separate field?
                             # Let's keep min/max. The plugin will check:
                             # if min == max: return ver == min
                             # else: return min <= ver < max
                        
                        if v_end or (v_start != '*'):
                             # Only store if we have SOME version constraint.
                             # Unconstrained matches (all versions) are noisy unless validated.
                             
                             yield {
                                'cve_id': cve_id,
                                'product': norm_product,
                                'vendor': vendor,
                                'version_min': v_start,
                                'version_max': v_end, # Can be None if exact version used above
                                'severity': severity,
                                'description': description
                            }

def import_nvd(filepath):
    """Import parsed data into SQLite."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    count = 0
    for entry in parse_nvd_json(filepath):
        try:
            cursor.execute('''
            INSERT OR IGNORE INTO cves (cve_id, product, vendor, version_min, version_max, severity, description)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                entry['cve_id'], 
                entry['product'], 
                entry['vendor'], 
                entry['version_min'], 
                entry['version_max'], 
                entry['severity'], 
                entry['description']
            ))
            count += 1
        except Exception as e:
            logging.error(f"Error inserting {entry['cve_id']}: {e}")
            
    conn.commit()
    conn.close()
    logging.info(f"Import complete. Imported {count} product-version ranges.")

def seed_defaults():
    """Seed the DB with the original manually curated CVEs (Fallbacks)."""
    defaults = [
        ("CVE-2021-41773", "apache_http_server", "apache", "2.4.49", "2.4.50", "Critical", "Apache HTTP Server Path Traversal & RCE"),
        ("CVE-2021-42013", "apache_http_server", "apache", "2.4.50", "2.4.51", "Critical", "Apache HTTP Server Path Traversal & RCE"),
        ("CVE-2014-0160", "openssl", "openssl", "1.0.1", "1.0.1g", "High", "Heartbleed (Information Disclosure)"),
        ("CVE-2019-10149", "exim", "exim", "4.0", "4.92", "Critical", "Exim 'The Return of the WIZARD' RCE"),
        ("CVE-2014-2653", "openssh", "openbsd", "0.0", "6.6.1p1", "Medium", "OpenSSH verify_host_key DNS bypass (Fixed in 6.7) - Range approx"), # Fixed in 6.7, effectively < 6.7 usually
        ("CVE-2014-2532", "openssh", "openbsd", "0.0", "6.6.1p1", "Medium", "OpenSSH AcceptEnv wildcard handling (Fixed in 6.6) - Range max")
    ]
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    for d in defaults:
         cursor.execute('''
            INSERT OR IGNORE INTO cves (cve_id, product, vendor, version_min, version_max, severity, description)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', d)
            
    conn.commit()
    conn.close()
    logging.info("Seeded default high-profile CVEs.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage Revealr CVE Database")
    parser.add_argument("--init", action="store_true", help="Initialize database")
    parser.add_argument("--seed", action="store_true", help="Seed with defaults")
    parser.add_argument("--import-json", type=str, help="Path to NVD JSON file to import")
    
    args = parser.parse_args()
    
    if args.init:
        init_db()
        
    if args.seed:
        seed_defaults()
        
    if args.import_json:
        if not os.path.exists(args.import_json):
            logging.error(f"File not found: {args.import_json}")
            sys.exit(1)
        import_nvd(args.import_json)
