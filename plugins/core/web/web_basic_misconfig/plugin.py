import requests

# Disable warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Fallback endpoints to try if main page returns error
FALLBACK_ENDPOINTS = [
    "/health",
    "/healthz",
    "/status",
    "/api",
    "/api/health",
]

def run(context):
    """
    Checks headers and body for misconfigurations.
    Includes smart probing with fallback endpoints.
    """
    debug = context.get('debug', lambda x: None)
    debug("Auditing web security headers...")
    target = context.get('target')
    port = context.get('port')
    service_name = context.get('service_name', '').lower()
    
    protocol = "http"
    if "ssl" in service_name or "tls" in service_name or "https" in service_name or port in [443, 8443, 9443]:
        protocol = "https"
        
    base_url = f"{protocol}://{target}:{port}"
    
    findings = {}
    missing_headers = []
    
    def make_request(url, timeout=10):
        """Make request and return response or None."""
        try:
            return requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        except:
            return None
    
    # Primary request
    resp = make_request(base_url)
    
    # Check for protection/WAF indicators
    if resp:
        findings["http_status_code"] = resp.status_code
        
        # 503 often indicates WAF/Load Balancer protection
        if resp.status_code == 503:
            findings["protected_endpoint"] = True
            findings["protection_type"] = "service_unavailable"
            debug("Detected 503 - trying fallback endpoints...")
            
            # Try fallback endpoints
            for endpoint in FALLBACK_ENDPOINTS:
                fallback_resp = make_request(f"{base_url}{endpoint}", timeout=5)
                if fallback_resp and fallback_resp.status_code == 200:
                    findings["fallback_endpoint"] = endpoint
                    resp = fallback_resp  # Use this for header analysis
                    break
        
        # Common WAF signatures
        server_header = resp.headers.get('Server', '').lower()
        if any(waf in server_header for waf in ['cloudflare', 'akamai', 'incapsula', 'sucuri', 'barracuda']):
            findings["waf_detected"] = True
            findings["waf_vendor"] = resp.headers.get('Server')
        
        # Rate limiting detection
        if resp.status_code == 429:
            findings["rate_limited"] = True
    
    if not resp:
        return {"http_error": "Connection failed"} if findings else None
    
    headers = resp.headers
    
    # Check Headers
    if 'X-Content-Type-Options' not in headers:
        missing_headers.append("X-Content-Type-Options")
    
    if 'X-Frame-Options' not in headers:
        missing_headers.append("X-Frame-Options")
        
    if 'Content-Security-Policy' not in headers:
        missing_headers.append("Content-Security-Policy")
        
    if protocol == "https" and 'Strict-Transport-Security' not in headers:
        missing_headers.append("Strict-Transport-Security")
    
    # Additional security headers check
    if 'X-XSS-Protection' not in headers:
        missing_headers.append("X-XSS-Protection")

    if missing_headers:
        findings['missing_security_headers'] = missing_headers

    # Check Open Directory
    if "Index of /" in resp.text and "Parent Directory" in resp.text:
        findings['misconfig_open_dir'] = True
        findings['misconfig_open_dir_path'] = "/"
    
    # Server header leakage
    if 'Server' in headers:
        findings['web_server_header'] = headers['Server']
    
    # X-Powered-By leakage
    if 'X-Powered-By' in headers:
        findings['x_powered_by'] = headers['X-Powered-By']

    # --- Advanced Mode: Sensitive Path Inspection ---
    if context.get('advanced', False):
        debug("Advanced mode enabled: Checking for sensitive paths...")
        SENSITIVE_PATHS = [
            "/admin", "/login", "/dashboard", "/config", "/.git/HEAD", "/.env", "/backup", "/server-status"
        ]
        
        found_paths = []
        for path in SENSITIVE_PATHS:
            try:
                # Use a shorter timeout for fuzzing
                path_url = f"{base_url}{path}"
                p_resp = requests.get(path_url, timeout=3, verify=False, allow_redirects=False)
                
                # We consider it interesting if it exists (200) or redirects (3xx) or is forbidden (403)
                # But we filter out 404.
                if p_resp.status_code in [200, 401, 403]:
                    # Filter out if it's just the exact same page as root (soft 404 or SPA)
                    if len(p_resp.content) != len(resp.content):
                         found_paths.append(f"{path} ({p_resp.status_code})")
            except:
                pass
        
        if found_paths:
            findings['sensitive_paths_found'] = found_paths
            
    return findings if findings else None

