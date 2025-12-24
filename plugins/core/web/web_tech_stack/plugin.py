import requests
import re
import logging

# Disable warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def run(context):
    """
    Identifies web technologies.
    """
    debug = context.get('debug', lambda x: None)
    debug("Identifying web technology stack...")
    target = context.get('target')
    port = context.get('port')
    
    # Heuristic for protocol: if port ends in 443 or service name has ssl/tls
    # But context might not have service name easily accessible besides 'details'.
    # We can try HTTPS then HTTP.
    
    # Ideally, loader passes 'service_name' in context?
    # Checking loader.py: context = {'target': ip, 'port': port, 'service_name': ..., 'banner': ..., 'details': ...}
    service_name = context.get('service_name', '').lower()
    
    protocol = "http"
    if "ssl" in service_name or "tls" in service_name or "https" in service_name or port in [443, 8443, 9443]:
        protocol = "https"
        
    url = f"{protocol}://{target}:{port}"
    
    findings = {}
    timeout = 10 
    
    try:
        # Try HEAD first
        try:
            resp = requests.head(url, timeout=timeout, verify=False, allow_redirects=True)
        except requests.exceptions.RequestException:
            # Fallback to GET if HEAD fails (some servers block HEAD)
            resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)

        headers = resp.headers
        
        # 1. Server Header
        server = headers.get('Server', '')
        if server:
            findings['web_server_header'] = server
            # Normalize common ones to override service_name
            if 'apache' in server.lower():
                findings['service_name'] = "Apache httpd"
                v = re.search(r"Apache/([\d\.]+)", server)
                if v: findings['service_version'] = v.group(1)
            elif 'nginx' in server.lower():
                findings['service_name'] = "Nginx httpd"
                v = re.search(r"nginx/([\d\.]+)", server)
                if v: findings['service_version'] = v.group(1)
            elif 'iis' in server.lower():
                findings['service_name'] = "Microsoft IIS httpd"
                v = re.search(r"IIS/([\d\.]+)", server)
                if v: findings['service_version'] = v.group(1)
            elif 'cloudflare' in server.lower():
                findings['web_proxy'] = "Cloudflare"

        # 2. X-Powered-By
        xpb = headers.get('X-Powered-By', '')
        if xpb:
            findings['web_powered_by'] = xpb
            if 'php' in xpb.lower():
                findings['web_language'] = "PHP"
                v = re.search(r"PHP/([\d\.]+)", xpb)
                if v: findings['web_language_version'] = v.group(1)
            elif 'asp.net' in xpb.lower():
                findings['web_framework'] = "ASP.NET"
            elif 'express' in xpb.lower():
                 findings['web_framework'] = "Express.js"

        # 3. Cookies
        if 'Set-Cookie' in headers:
            cookies = headers['Set-Cookie']
            if 'JSESSIONID' in cookies:
                findings['web_framework'] = "Java Servlet/JSP"
            elif 'PHPSESSID' in cookies:
                findings['web_language'] = "PHP"
            elif 'ASP.NET_SessionId' in cookies:
                findings['web_framework'] = "ASP.NET"
            elif 'csrftoken' in cookies and 'django' not in findings.get('web_framework', '').lower():
                # Django often uses csrftoken, but not exclusive
                pass 

        # 4. Body Analysis (GET if we haven't)
        # Only fetch body if we suspect CMS or didn't get enough info
        # Or just do it always for robust CMS detection
        # Limit to first 20KB for speed
        if resp.request.method == 'HEAD':
             resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        
        body = resp.text[:20000].lower()
        
        if 'wp-content' in body or 'wp-includes' in body:
            findings['web_cms'] = "WordPress"
            findings['service_name'] = "WordPress" # Override
            # Try to find version
            v = re.search(r'content="wordpress ([\d\.]+)"', body)
            if v: findings['service_version'] = v.group(1)
            
        if 'joomla' in body or '/templates/system/css/system.css' in body:
            findings['web_cms'] = "Joomla"
            
        if 'drupal' in body or 'sites/all/modules' in body:
            findings['web_cms'] = "Drupal"
            
        # generator meta tag
        # <meta name="generator" content="Drupal 7 (http://drupal.org)" />
        gen_match = re.search(r'<meta name="generator" content="([^"]+)"', resp.text, re.IGNORECASE)
        if gen_match:
            findings['web_generator'] = gen_match.group(1)

    except Exception as e:
        # logging.debug(f"Web Tech Stack check failed: {e}")
        pass

    return findings if findings else None
