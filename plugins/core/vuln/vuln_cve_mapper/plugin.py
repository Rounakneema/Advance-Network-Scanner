import re
import sqlite3
import os

def parse_version(v):
    """Parse version string into a comparable tuple of integers."""
    # Removes non-numeric (except dots) roughly or separates them?
    # Strategy: Split by dot, then try to extract leading integer from each part.
    # OpenSSH 6.6.1p1 -> 6.6.1.1?
    # Simple split regex:
    parts = []
    for part in re.split(r'[.-]', v):
        # Extract number if present
        match = re.match(r'^(\d+)', part)
        if match:
            parts.append(int(match.group(1)))
        else:
            # If purely text (e.g. 'beta'), ignore or treat as -1?
            # For this simplified scanner, we focus on numeric parts.
            pass
    return tuple(parts)

def version_compare(ver, criteria):
    """Return True if ver < criteria (lexicographically on int tuples)."""
    return parse_version(ver) < parse_version(criteria)

def normalize_product_name(service_name):
    """Normalize service banner name to CPE product key."""
    s = service_name.lower()
    if 'apache' in s and ('httpd' in s or 'server' in s):
        return 'apache_http_server'
    if 'ssh' in s or 'openssh' in s:
        return 'openssh'
    if 'nginx' in s:
        return 'nginx'
    if 'mysql' in s:
        return 'mysql_server' # Check NVD naming
    return s.replace(' ', '_')

def run(context):
    debug = context.get('debug', lambda x: None)
    
    # Locate DB
    # context['plugin_dir'] is not explicitly passed usually, but we can assume relative path
    # d:\GO\Projects\revealr\plugins\core\vuln\vuln_cve_mapper\plugin.py
    # DB: d:\GO\Projects\revealr\data\vuln_db\cves.db
    # We can perform a robust lookup relative to current file
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Go 4 levels up: plugins/core/vuln/vuln_cve_mapper -> plugins/core/vuln -> plugins/core -> plugins -> revealr words?
    # Actually: .../plugins/core/vuln/vuln_cve_mapper/../../../../data/vuln_db/cves.db
    db_path = os.path.join(current_dir, '..', '..', '..', '..', 'data', 'vuln_db', 'cves.db')
    db_path = os.path.abspath(db_path)
    
    if not os.path.exists(db_path):
        debug(f"CVE Database not found at {db_path}")
        return {"vulnerabilities_status": "CVE Database missing"}

    details = context.get('details', {})
    service_name = details.get('service_name') or context.get('service', '')
    service_version = details.get('service_version') or context.get('version', '')

    if not service_name or service_name == "unknown" or not service_version:
        return None

    norm_product = normalize_product_name(service_name)
    debug(f"Checking CVEs for: {service_name} ({norm_product}) v{service_version}")

    findings = {}
    cves = []
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT cve_id, version_min, version_max, severity, description FROM cves WHERE product = ?", (norm_product,))
        rows = cursor.fetchall()
        
        for row in rows:
            cve_id, v_min, v_max, severity, desc = row
            
            # Logic:
            # if v_max is specified: check if ver < v_max
            # AND if v_min != '*': check if ver >= v_min
            
            is_vulnerable = True
            
            # Check Max (Exclusive usually in our importer logic)
            if v_max:
                # If v_min == v_max, it's an EXACT match check (workaround from importer)
                if v_min == v_max:
                    is_vulnerable = (parse_version(service_version) == parse_version(v_max))
                # Normal range
                elif not version_compare(service_version, v_max):
                    # version >= max, so NOT vulnerable (assuming max is exclusive)
                    is_vulnerable = False
                    
            # Check Min (Inclusive)
            if is_vulnerable and v_min and v_min != '*':
                 # Must be >= v_min
                 # equivalent to NOT (ver < min)
                 if version_compare(service_version, v_min):
                     is_vulnerable = False
            
            if is_vulnerable:
                cves.append({
                    "id": cve_id,
                    "description": desc,
                    "severity": severity,
                    "matched_version": service_version
                })
                
        conn.close()
        
    except Exception as e:
        debug(f"DB Query Error: {e}")
        return {"vulnerabilities_status": f"DB Error: {e}"}

    if cves:
        findings['vulnerabilities'] = cves
    else:
        findings['vulnerabilities_status'] = "No CVEs found"
        
    return findings
