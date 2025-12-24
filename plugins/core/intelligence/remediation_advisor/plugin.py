def run(context):
    debug = context.get('debug', lambda x: None)
    debug("Generating remediation advice...")
    findings = {}
    advice = []
    
    details = context.get('details', {})
    
    # 1. Vulns
    vulns = details.get('vulnerabilities', [])
    for v in vulns:
        advice.append({
            "issue": f"Vulnerability {v['id']}",
            "action": "Patch Management",
            "fix": "Upgrade the software to the latest stable version immediately. Review vendor usage."
        })

    # 2. Exposure
    files = details.get('exposed_sensitive_files', [])
    if files:
         advice.append({
             "issue": "Sensitive File Exposure",
             "action": "Access Control",
             "fix": "Configure web server (Apache .htaccess, Nginx location) to deny access to .env, .git, and backup files."
         })

    # 3. Headers
    missing = details.get('missing_security_headers', [])
    if missing:
        advice.append({
            "issue": "Missing Security Headers",
            "action": "Hardening",
            "fix": f"Configure web server to send headers: {', '.join(missing)}."
        })

    # 4. Creds
    if details.get('default_creds_found'):
        advice.append({
            "issue": "Default Credentials",
            "action": "Password Rotation",
            "fix": "Change the default password for the account immediately."
        })

    # 5. SSL
    if "Weak SSL/TLS Protocol" in str(details.get('configuration_issues', [])):
        advice.append({
            "issue": "Weak SSL/TLS",
            "action": "Hardening",
            "fix": "Disable SSLv2/v3 and TLS 1.0/1.1 in server configuration. Enable TLS 1.2/1.3 only."
        })

    if advice:
        findings['remediation_advice'] = advice
    else:
        findings['remediation_status'] = "No remediation advice available"
        
    return findings
