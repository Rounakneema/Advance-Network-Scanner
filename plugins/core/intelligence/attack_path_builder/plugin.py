def run(context):
    debug = context.get('debug', lambda x: None)
    debug("Building attack paths from findings...")
    findings = {}
    paths = []
    
    details = context.get('details', {})
    
    # Check for Vulnerabilities
    vulns = details.get('vulnerabilities', [])
    for v in vulns:
        if v['severity'] == "Critical" or v['severity'] == "High":
            paths.append({
                "title": f"Exploit {v['id']}",
                "likelihood": "High",
                "impact": "Critical",
                "steps": [
                    f"Target is vulnerable to {v['id']} ({v['description']})",
                    "Execute exploit (e.g., Metasploit module)",
                    "Gain RCE or Information Disclosure"
                ]
            })

    # Check for Exposures
    files = details.get('exposed_sensitive_files', [])
    if '/.env' in files or '/.git/config' in files:
         paths.append({
                "title": "Credential Harvesting via Exposure",
                "likelihood": "Medium",
                "impact": "High",
                "steps": [
                    "Download exposed configuration files (.env/.git)",
                    "Extract database credentials or API keys",
                    "Pivot to Database or Cloud Infrastructure"
                ]
         })

    # Check for Creds
    if details.get('default_creds_found'):
        creds = details.get('creds', 'unknown')
        paths.append({
            "title": "Access via Default Credentials",
            "likelihood": "Certain",
            "impact": "Critical",
            "steps": [
                f"Log in using discovered credentials ({creds})",
                "Access administrative interface",
                "Upload web shell or modify configuration"
            ]
        })

    if paths:
        findings['attack_paths'] = paths
    else:
        findings['attack_path_status'] = "No attack paths identified"
        
    return findings
