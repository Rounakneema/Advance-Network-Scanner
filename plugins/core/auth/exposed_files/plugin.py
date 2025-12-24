import requests

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

SENSITIVE_FILES = [
    ("/robots.txt", "User-agent:"), # Common, not always sensitive but interesting
    ("/.env", "DB_"), # High critical
    ("/.git/config", "[core]"), # High critical
    ("/backup.zip", None), # Binary, check 200 OK and content-type
    ("/web.config", "<configuration>"), # IIS
    ("/ds_store", None), # Mac
]

def run(context):
    debug = context.get('debug', lambda x: None)
    debug("Checking for exposed sensitive files...")
    target = context.get('target')
    port = context.get('port')
    service_name = context.get('service_name', '').lower()
    
    protocol = "http"
    if "ssl" in service_name or "tls" in service_name or "https" in service_name or port in [443, 8443, 9443]:
        protocol = "https"
        
    url_base = f"{protocol}://{target}:{port}"
    
    findings = {}
    exposed = []
    
    # Simple check, non-recursive
    for path, signature in SENSITIVE_FILES:
        try:
            url = f"{url_base}{path}"
            resp = requests.get(url, timeout=5, verify=False, allow_redirects=False)
            
            if resp.status_code == 200:
                is_valid = False
                if signature:
                    if signature in resp.text:
                        is_valid = True
                else:
                    # heuristic for binaries or generic
                    if int(resp.headers.get('Content-Length', 0)) > 100:
                        is_valid = True
                
                if is_valid:
                    exposed.append(path)
        except Exception:
            pass
            
    if exposed:
        findings['exposed_sensitive_files'] = exposed
        
    return findings if findings else None
