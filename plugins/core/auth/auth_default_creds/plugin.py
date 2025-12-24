import requests
import socket
# import paramiko # SSH? Standard python might not have it. Bundle?
# For now, stick to HTTP Basic Auth and maybe FTP via socket/ftplib.

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("tomcat", "s3cret"),
]

def check_http_basic(url, username, password):
    try:
        resp = requests.get(url, auth=(username, password), timeout=5, verify=False)
        return resp.status_code == 200
    except:
        return False

def run(context):
    debug = context.get('debug', lambda x: None)
    debug("Starting default credentials check...")
    target = context.get('target')
    port = context.get('port')
    service_name = context.get('service_name', '').lower()
    
    findings = {}
    
    # HTTP/HTTPS
    if "http" in service_name or port in [80, 443, 8080, 8443]:
        protocol = "https" if ("ssl" in service_name or port in [443, 8443]) else "http"
        url = f"{protocol}://{target}:{port}"
        
        # Check if Basic Auth is even required
        # If 401 is returned on normal request, then try brute.
        try:
             initial = requests.get(url, timeout=5, verify=False)
             if initial.status_code == 401:
                 findings['auth_detected'] = True
                 findings['auth_realm'] = initial.headers.get('WWW-Authenticate', 'unknown')
                 
                 # Only try brute-force in ADVANCED mode
                 is_advanced = context.get('advanced', False)
                 
                 if is_advanced:
                     debug("Advanced mode enabled: Attempting default credentials...")
                     # Try creds
                     for u, p in CREDS:
                         if check_http_basic(url, u, p):
                             findings['default_creds_found'] = True
                             findings['creds'] = f"{u}:{p}"
                             findings['auth_method'] = "HTTP Basic"
                             break
                 else:
                     debug("Standard mode: Skipping credential brute-force.")
        except:
            pass

    # FTP (using standard lib ftplib)
    if "ftp" in service_name or port == 21:
        import ftplib
        try:
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=5)
            try:
                ftp.login('anonymous', 'anonymous@example.com')
                findings['ftp_anonymous_login'] = True
                ftp.quit()
            except:
                pass
                # Could try admin/admin
        except:
             pass

    return findings if findings else None
