import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
import json
import requests
import random
import time
import socket
from scapy.all import IP, TCP, sr1

logger = logging.getLogger('recon_tool')

WAF_SIGNATURES = {
    'Cloudflare': ['cf-ray', 'cloudflare'],
    'ModSecurity': ['mod_security', '403 forbidden'],
    'AWS WAF': ['x-amzn-requestid', 'aws-waf'],
}

def sanitize_target(target: str) -> str:
    if not target or not isinstance(target, str):
        logger.error("Invalid target: empty or not a string")
        raise ValueError("Target must be a non-empty string")
    target = target.strip()
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    domain_pattern = r'^[a-z0-9][a-z0-9-]{0,61}[a-z0-9](?:\.[a-z]{2,})+$'
    if not (re.match(ip_pattern, target) or re.match(domain_pattern, target)):
        logger.error(f"Invalid IP or domain: {target}")
        raise ValueError("Invalid IP or domain format")
    return target

def sanitize_port(port: int) -> int:
    if not isinstance(port, int) or not 1 <= port <= 65535:
        logger.error(f"Invalid port: {port}")
        raise ValueError("Port must be an integer between 1 and 65535")
    return port

def probe_firewall(target: str, port: int, stealth: bool, proxies: Optional[Dict]) -> Dict[str, Any]:
    if stealth:
        time.sleep(random.uniform(0.5, 3.0))
    
    try:
        protocol = 'https' if port in [443, 8443] else 'http'
        url = f"{protocol}://{target}:{port}" if port not in [80, 443] else f"{protocol}://{target}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124',
            'X-Forwarded-For': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        }
        response = requests.get(url, headers=headers, proxies=proxies, timeout=10, verify=False, allow_redirects=False)
        
        waf_detected = None
        for waf, signatures in WAF_SIGNATURES.items():
            if any(s in str(response.headers).lower() or s in response.text.lower() for s in signatures):
                waf_detected = waf
                break
        
        return {
            'port': port,
            'status_code': response.status_code,
            'waf': waf_detected,
            'response_time': response.elapsed.total_seconds()
        }
    except requests.exceptions.RequestException:
        pass
    
    try:
        pkt = IP(dst=target)/TCP(dport=port, flags='S')
        resp = sr1(pkt, timeout=2, verbose=0)
        if resp:
            return {
                'port': port,
                'tcp_response': 'open' if resp.haslayer(TCP) and resp[TCP].flags == 0x12 else 'filtered',
                'response_time': time.time() - pkt.sent_time
            }
        return {'port': port, 'tcp_response': 'no_response'}
    except Exception as e:
        logger.debug(f"Packet probe failed for {target}:{port}: {e}")
        return {'port': port, 'tcp_response': 'error'}

def firewall_detect(target: str, ports: List[int], prior_findings: Dict[str, Any] = None, stealth: bool = False, proxies: Optional[Dict[str, str]] = None, cache_file: Optional[str] = None) -> Dict[str, Any]:
    try:
        target = sanitize_target(target)
        ports = [sanitize_port(p) for p in ports] if ports else prior_findings.get('port_scan', {}).get('open_ports', [80, 443])
        prior_findings = prior_findings or {}
        logger.info(f"Starting firewall detection on {target} for ports {ports}")

        if cache_file:
            cache_path = Path(cache_file).resolve()
            try:
                if cache_path.exists():
                    with open(cache_path, 'r', encoding='utf-8') as f:
                        cached_data = json.load(f)
                        if cached_data.get('target') == target and sorted(cached_data.get('ports', [])) == sorted(ports):
                            logger.debug(f"Using cached firewall detection results from {cache_path}")
                            return cached_data['results']
            except (OSError, json.JSONDecodeError) as e:
                logger.warning(f"Failed to read firewall detection cache: {e}")

        results = {'target': target, 'ports': []}
        
        for port in ports:
            result = probe_firewall(target, port, stealth, proxies)
            results['ports'].append(result)
            logger.debug(f"Firewall probe for port {port} on {target}: {result}")

        results['analysis'] = analyze_firewall_findings(results['ports'])
        
        if cache_file:
            try:
                cache_path.parent.mkdir(exist_ok=True)
                with open(cache_path, 'w', encoding='utf-8') as f:
                    json.dump({'target': target, 'ports': ports, 'results': results}, f, indent=2)
                logger.debug(f"Cached firewall detection results to {cache_path}")
            except OSError as e:
                logger.warning(f"Failed to write firewall detection cache: {e}")

        logger.info(f"Firewall detection completed for {target}")
        return results

    except ValueError as e:
        raise
    except Exception as e:
        logger.error(f"Firewall detection failed for {target}: {e}")
        raise RuntimeError(f"Firewall detection failed: {e}")

def analyze_firewall_findings(ports: List[Dict]) -> Dict[str, Any]:
    risk_score = 0
    findings = []
    
    for port in ports:
        if port.get('waf'):
            risk_score += 5
            findings.append({'port': port['port'], 'issue': f"WAF detected: {port['waf']}", 'evasion': 'Use slow scans or proxy chains'})
        elif port.get('tcp_response') == 'filtered':
            risk_score += 3
            findings.append({'port': port['port'], 'issue': 'Port filtered', 'evasion': 'Try different timing or source IPs'})
    
    risk_level = 'High' if risk_score >= 10 else 'Medium' if risk_score >= 5 else 'Low'
    return {'risk_score': risk_score, 'risk_level': risk_level, 'findings': findings}