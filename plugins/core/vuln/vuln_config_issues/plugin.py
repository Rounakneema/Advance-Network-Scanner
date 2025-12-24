def run(context):
    debug = context.get('debug', lambda x: None)
    debug("Checking for configuration issues...")
    findings = {}
    issues = []
    
    details = context.get('details', {})
    
    # 1. SSL/TLS Config
    ssl_version = details.get('ssl_version', '')
    if ssl_version:
        # Standardize check
        weak_protocols = ["sslv2", "sslv3", "tlsv1", "tls 1.0", "tls 1.1"]
        for weak in weak_protocols:
            if weak in ssl_version.lower():
                issues.append({
                    "title": "Weak SSL/TLS Protocol",
                    "description": f"The server supports {ssl_version}, which is deprecated and insecure.",
                    "severity": "Medium"
                })
                break
                
    # 2. X-Powered-By leakage (Minor config issue)
    if 'X-Powered-By' in details:
        issues.append({
            "title": "Information Leakage (X-Powered-By)",
            "description": f"Server leaks technology info: {details['X-Powered-By']}",
            "severity": "Low"
        })

    if issues:
        findings['configuration_issues'] = issues
    else:
        findings['configuration_status'] = "No configuration issues found"
        
    return findings
