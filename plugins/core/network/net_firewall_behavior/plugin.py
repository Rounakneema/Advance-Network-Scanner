def run(context):
    """
    Detects firewall behavior from port state and reason.
    """
    debug = context.get('debug', lambda x: None)
    debug("Checking packet filtering behavior...")
    details = context.get('details', {})
    state = details.get('state', '').lower()
    reason = details.get('reason', '').lower()
    
    findings = {}

    # Logic: Filtered usually implies firewall rule dropping packets
    if 'filtered' in state:
        findings['firewall_detected'] = True
        findings['firewall_type'] = "Packet Filtering"
        findings['firewall_reason'] = f"Port state is {state}"
        if 'no-response' in reason:
             findings['firewall_note'] = "Silent Drop"
        elif 'admin-prohibited' in reason:
             findings['firewall_note'] = "ICMP Admin Prohibited Reject"

    # Logic: Syn-Ack-Rst anomalies (harder without raw packet access here, but reason might hint)
    
    if findings:
        return findings
    
    return None
