import json
import os
import re
import logging

# Global Cache
OS_CACHE = None

def load_patterns():
    global OS_CACHE
    if OS_CACHE: return OS_CACHE

    possible_paths = [
        os.path.join("data", "signatures", "os_patterns.json"),
        os.path.join("..", "..", "..", "data", "signatures", "os_patterns.json"),
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    data = json.load(f)
                    OS_CACHE = data.get("patterns", [])
                    return OS_CACHE
            except Exception as e:
                logging.error(f"Error loading OS signatures: {e}")
    
    return []

# TTL to OS mapping
TTL_MAP = [
    (64, "Linux/Unix", 0.6),
    (128, "Windows", 0.6),
    (255, "Network Device", 0.5),
]

def guess_os_from_ttl(ttl_value):
    """Return (os_guess, confidence) based on TTL."""
    if not ttl_value:
        return None, 0
    try:
        ttl = int(ttl_value)
        for expected, os_name, conf in TTL_MAP:
            if abs(ttl - expected) <= 5:  # Allow small variance
                return os_name, conf
    except:
        pass
    return None, 0

# Evidence extraction patterns
EVIDENCE_PATTERNS = [
    # (regex, os_guess, weight)
    (r"ubuntu", "Ubuntu Linux", 0.4),
    (r"debian", "Debian Linux", 0.4),
    (r"centos", "CentOS Linux", 0.4),
    (r"redhat|rhel", "Red Hat Linux", 0.4),
    (r"fedora", "Fedora Linux", 0.4),
    (r"windows", "Windows", 0.5),
    (r"microsoft", "Windows", 0.4),
    (r"iis", "Windows", 0.7),
    (r"win32|win64", "Windows", 0.6),
    (r"freebsd", "FreeBSD", 0.5),
    (r"openbsd", "OpenBSD", 0.5),
    (r"linux", "Linux", 0.3),
    (r"unix", "Unix", 0.2),
]

def extract_evidence(text, source_weight=1.0):
    """Extract OS hints from text with weighted confidence."""
    evidence = []
    text_lower = text.lower()
    for pattern, os_guess, weight in EVIDENCE_PATTERNS:
        if re.search(pattern, text_lower):
            evidence.append({
                "os": os_guess,
                "confidence": weight * source_weight,
                "source": text[:50]  # Truncate for display
            })
    return evidence

def aggregate_evidence(evidence_list):
    """Aggregate evidence into final OS guess with confidence."""
    if not evidence_list:
        return "unknown", 0.0, []
    
    # Score by OS family
    scores = {}
    for ev in evidence_list:
        os_name = ev["os"]
        # Normalize to family (Ubuntu Linux -> Linux)
        family = os_name
        if "Linux" in os_name:
            family = "Linux"
        elif "Windows" in os_name:
            family = "Windows"
        elif "BSD" in os_name:
            family = "BSD"
            
        if family not in scores:
            scores[family] = {"total": 0, "specific": os_name, "evidence": []}
        scores[family]["total"] += ev["confidence"]
        scores[family]["evidence"].append(ev)
        # Keep most specific name
        if len(ev["os"]) > len(scores[family]["specific"]):
            scores[family]["specific"] = ev["os"]
    
    # Find winner
    best_family = max(scores.keys(), key=lambda k: scores[k]["total"])
    winner = scores[best_family]
    
    # Normalize confidence to [0, 1]
    final_conf = min(winner["total"], 1.0)
    
    return winner["specific"], final_conf, winner["evidence"]

def run(context):
    """
    Multi-source OS fingerprinting with evidence aggregation.
    """
    debug = context.get('debug', lambda x: None)
    debug("Inferring OS from service info...")
    
    evidence = []
    
    # Source 1: Service name
    service_name = context.get('service', '')
    if service_name:
        evidence.extend(extract_evidence(service_name, source_weight=0.8))
    
    # Source 2: Banner
    banner = context.get('banner', '')
    if banner:
        evidence.extend(extract_evidence(banner, source_weight=1.0))
    
    # Source 3: Details (enriched data from other plugins)
    details = context.get('details', {})
    
    # Check HTTP headers
    for key in ['web_server_header', 'server', 'x-powered-by']:
        if key in details:
            evidence.extend(extract_evidence(str(details[key]), source_weight=0.9))
    
    # Check service_name from previous enrichment
    if 'service_name' in details:
        evidence.extend(extract_evidence(details['service_name'], source_weight=0.7))
    
    # Source 4: TTL (if available from Go scanner)
    ttl = details.get('ttl')
    if ttl:
        os_from_ttl, ttl_conf = guess_os_from_ttl(ttl)
        if os_from_ttl:
            evidence.append({
                "os": os_from_ttl,
                "confidence": ttl_conf,
                "source": f"TTL={ttl}"
            })
    
    # Legacy pattern matching from os_patterns.json
    patterns = load_patterns()
    for p in patterns:
        match_str = p.get("match", "").lower()
        if match_str:
            # Check in banner and service
            if match_str in banner.lower() or match_str in service_name.lower():
                evidence.append({
                    "os": p.get("os", "unknown"),
                    "confidence": 0.85,
                    "source": f"pattern:{match_str}"
                })
    
    # Aggregate all evidence
    final_os, confidence, evidence_used = aggregate_evidence(evidence)
    
    if final_os != "unknown" and confidence > 0.2:
        result = {
            "os": final_os,
            "os_confidence": round(confidence, 2)
        }
        
        # Add CPE if available from patterns
        for p in patterns:
            if p.get("os", "").lower() in final_os.lower():
                if p.get("cpe"):
                    result["os_cpe"] = p["cpe"]
                    break
        
        # Add evidence summary (for debugging/transparency)
        if evidence_used and len(evidence_used) > 0:
            sources = list(set([ev.get("source", "")[:30] for ev in evidence_used[:3]]))
            result["os_evidence"] = sources
        
        return result
    
    return None

