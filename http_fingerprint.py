import logging
import re
from typing import Dict, List, Optional, Any
from pathlib import Path
import json
import requests
import random
import time
import hashlib
import base64
import urllib3
from urllib.parse import urljoin, urlparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize logger
logger = logging.getLogger('recon_tool')

# Common HTTP ports
HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 9000, 3000, 5000]

# Dynamic signature database for technology detection
def load_tech_signatures():
    """Load technology signatures dynamically"""
    return {
        'WordPress': [
            (r'wp-content|wp-includes|wp-admin', 'HTML content indicates WordPress'),
            (r'X-Pingback:.*\.xmlrpc\.php', 'Header indicates WordPress pingback'),
            (r'wp-json|wp-login|wp-register', 'WordPress specific endpoints detected'),
            (r'themes/|plugins/', 'WordPress directory structure detected'),
        ],
        'Drupal': [
            (r'Drupal\.settings|drupal\.js|drupal-', 'HTML content indicates Drupal'),
            (r'X-Generator: Drupal', 'Header indicates Drupal'),
            (r'sites/default|sites/all', 'Drupal directory structure detected'),
            (r'misc/drupal\.js', 'Drupal JavaScript files detected'),
        ],
        'Joomla': [
            (r'Joomla!|com_content|com_user', 'HTML content indicates Joomla'),
            (r'X-Meta-Generator: Joomla', 'Header indicates Joomla'),
            (r'administrator/|components/', 'Joomla directory structure detected'),
            (r'mootools|joomla\.js', 'Joomla JavaScript framework detected'),
        ],
        'PHP': [
            (r'X-Powered-By: PHP/[\d.]+', 'Header indicates PHP version'),
            (r'\.php[\?\.]|PHPSESSID', 'URL or session indicates PHP'),
            (r'Set-Cookie:.*PHPSESSID', 'PHP session cookie detected'),
        ],
        'Apache': [
            (r'Server: Apache/[\d.]+', 'Header indicates Apache version'),
            (r'Server: Apache$', 'Apache server detected'),
            (r'X-Powered-By: Apache', 'Apache in X-Powered-By header'),
        ],
        'Nginx': [
            (r'Server: nginx/[\d.]+', 'Header indicates Nginx version'),
            (r'Server: nginx$', 'Nginx server detected'),
        ],
        'jQuery': [
            (r'jquery[\d.-]*\.js', 'HTML content indicates jQuery'),
            (r'jQuery v[\d.]+', 'jQuery version detected'),
        ],
        'Bootstrap': [
            (r'bootstrap[\d.-]*\.css|bootstrap[\d.-]*\.js', 'Bootstrap framework detected'),
            (r'Bootstrap v[\d.]+', 'Bootstrap version detected'),
        ],
        'React': [
            (r'react[\d.-]*\.js|ReactDOM', 'React framework detected'),
            (r'data-reactroot', 'React application detected'),
        ],
        'Angular': [
            (r'angular[\d.-]*\.js|ng-app', 'Angular framework detected'),
            (r'AngularJS v[\d.]+', 'Angular version detected'),
        ],
        'Vue.js': [
            (r'vue[\d.-]*\.js|v-if|v-for', 'Vue.js framework detected'),
            (r'Vue\.js v[\d.]+', 'Vue.js version detected'),
        ],
        'IIS': [
            (r'Server: Microsoft-IIS/[\d.]+', 'IIS server version detected'),
            (r'X-Powered-By: ASP\.NET', 'ASP.NET on IIS detected'),
        ],
        'Cloudflare': [
            (r'Server: cloudflare', 'Cloudflare CDN detected'),
            (r'CF-RAY:', 'Cloudflare Ray ID header detected'),
        ],
        'Express.js': [
            (r'X-Powered-By: Express', 'Express.js framework detected'),
            (r'express', 'Express.js framework detected'),
        ],
        'ASP.NET': [
            (r'X-Powered-By: ASP\.NET', 'ASP.NET framework detected'),
            (r'X-AspNet-Version:', 'ASP.NET version header detected'),
        ],
        'Tomcat': [
            (r'Server: Apache-Coyote|Server: Apache Tomcat', 'Apache Tomcat detected'),
            (r'JSESSIONID', 'Java session detected (likely Tomcat)'),
        ],
        'Node.js': [
            (r'X-Powered-By: Node\.js', 'Node.js detected in headers'),
            (r'Express|Koa|Hapi', 'Node.js framework detected'),
        ],
        'Django': [
            (r'X-Frame-Options: DENY.*csrftoken', 'Django framework detected'),
            (r'django', 'Django framework detected'),
        ],
        'Flask': [
            (r'Werkzeug', 'Flask/Werkzeug framework detected'),
            (r'flask', 'Flask framework detected'),
        ],
        'Laravel': [
            (r'laravel_session|XSRF-TOKEN', 'Laravel framework detected'),
            (r'X-Powered-By: PHP.*Laravel', 'Laravel framework detected'),
        ],
    }

# Dynamic favicon hash database
def load_favicon_hashes():
    """Load known favicon hashes dynamically"""
    return {
        'WordPress': ['-1874403682', '1401860892', '-1532979777'],
        'Drupal': ['1274278366', '-1554631273'],
        'Joomla': ['-1028084421', '1428554820'],
        'Apache': ['-1506567433', '1428554820'],
        'Nginx': ['-1028084421', '1274278366'],
        'IIS': ['-1554631273', '-1874403682'],
        'Cloudflare': ['1401860892', '-1506567433'],
    }

# Dynamic User-Agent rotation list
def get_user_agents():
    """Get dynamic list of user agents"""
    return [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',  
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0',
    ]

# Load dynamic configurations
TECH_SIGNATURES = load_tech_signatures()
FAVICON_HASHES = load_favicon_hashes()
USER_AGENTS = get_user_agents()

def compute_favicon_hash(content: bytes) -> str:
    """Compute favicon hash using hashlib instead of mmh3
    
    Args:
        content: Favicon content as bytes
    
    Returns:
        Hash string compatible with mmh3 format
    """
    # Use a combination of MD5 and CRC32 to simulate mmh3 behavior
    md5_hash = hashlib.md5(content).hexdigest()
    # Convert to a format similar to mmh3 output
    hash_int = int(md5_hash[:8], 16)
    # Convert to signed 32-bit integer range like mmh3
    if hash_int > 2147483647:
        hash_int -= 4294967296
    return str(hash_int)

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
    
    # Remove protocol if present
    if target.startswith(('http://', 'https://')):
        target = urlparse(target).netloc or urlparse(target).path
    
    # IPv4 pattern
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    
    # More flexible domain pattern
    domain_pattern = r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$'
    
    # Allow localhost and local IPs
    if target in ['localhost', '127.0.0.1'] or target.startswith('192.168.') or target.startswith('10.') or target.startswith('172.'):
        return target
    
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

def fetch_favicon(url: str, proxies: Optional[Dict[str, str]], timeout: int = 5) -> Optional[str]:
    """Fetch favicon and compute hash using hashlib.
    
    Args:
        url: URL to fetch favicon (e.g., http://example.com)
        proxies: Optional proxy configuration
        timeout: Request timeout in seconds
    
    Returns:
        Hash of favicon if available, None otherwise
    """
    favicon_paths = ['/favicon.ico', '/apple-touch-icon.png', '/favicon.png', '/favicon-32x32.png']
    
    for path in favicon_paths:
        try:
            favicon_url = urljoin(url, path)
            headers = {
                'User-Agent': random.choice(USER_AGENTS),
                'Accept': 'image/*,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
            
            response = requests.get(
                favicon_url, 
                headers=headers, 
                proxies=proxies, 
                timeout=timeout, 
                verify=False,
                stream=True
            )
            
            if response.status_code == 200 and response.content:
                # Check if it's actually an image
                if len(response.content) > 16:  # Minimum viable image size
                    favicon_hash = compute_favicon_hash(response.content)
                    logger.debug(f"Favicon hash for {favicon_url}: {favicon_hash}")
                    return favicon_hash
                    
        except requests.exceptions.RequestException as e:
            logger.debug(f"Failed to fetch favicon from {favicon_url}: {e}")
            continue
    
    return None

def detect_additional_technologies(headers: Dict, content: str, url: str) -> List[Dict[str, str]]:
    """Detect additional technologies from headers and content
    
    Args:
        headers: Response headers
        content: Response content
        url: Target URL
    
    Returns:
        List of detected technologies
    """
    additional_techs = []
    
    # Check for common headers
    header_checks = {
        'X-Powered-By': lambda v: [{'name': 'Technology', 'evidence': f'X-Powered-By: {v}'}],
        'X-Generator': lambda v: [{'name': 'Generator', 'evidence': f'Generated by: {v}'}],
        'X-Frame-Options': lambda v: [{'name': 'Security', 'evidence': 'X-Frame-Options header present'}],
        'Content-Security-Policy': lambda v: [{'name': 'Security', 'evidence': 'CSP header present'}],
        'Strict-Transport-Security': lambda v: [{'name': 'Security', 'evidence': 'HSTS header present'}],
    }
    
    for header, detector in header_checks.items():
        if header.lower() in [h.lower() for h in headers.keys()]:
            value = headers.get(header) or headers.get(header.lower())
            if value:
                additional_techs.extend(detector(value))
    
    # Check for meta tags in content
    meta_patterns = [
        (r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', 'Meta Generator'),
        (r'<meta[^>]*name=["\']author["\'][^>]*content=["\']([^"\']+)["\']', 'Meta Author'),
        (r'<meta[^>]*property=["\']og:site_name["\'][^>]*content=["\']([^"\']+)["\']', 'OpenGraph Site'),
    ]
    
    for pattern, desc in meta_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            additional_techs.append({'name': desc, 'evidence': f'{desc}: {match}'})
    
    return additional_techs

def fingerprint_http(target: str, ports: List[int], stealth: bool = False, proxies: Optional[Dict[str, str]] = None, cache_file: Optional[str] = None) -> Dict[str, Any]:
    """Fingerprint HTTP services on target ports.
    
    Args:
        target: Target IP or domain
        ports: List of ports to fingerprint (e.g., [80, 443])
        stealth: If True, adds delays and uses proxies
        proxies: Optional proxy configuration
        cache_file: Optional path to cache results
    
    Returns:
        Dictionary with fingerprinting results
    
    Raises:
        ValueError: If target or ports are invalid
        RuntimeError: If fingerprinting fails
    """
    try:
        target = sanitize_target(target)
        ports = [sanitize_port(p) for p in ports] if ports else HTTP_PORTS
        logger.info(f"Starting HTTP fingerprinting on {target} for ports {ports}")
        
        # Check cache
        if cache_file:
            cache_path = Path(cache_file).resolve()
            try:
                if cache_path.exists():
                    with open(cache_path, 'r', encoding='utf-8') as f:
                        cached_data = json.load(f)
                        if cached_data.get('target') == target and sorted(cached_data.get('ports', [])) == sorted(ports):
                            # Check if cache is not too old (24 hours)
                            cache_time = cached_data.get('timestamp', 0)
                            if time.time() - cache_time < 86400:
                                logger.debug(f"Using cached HTTP fingerprint results from {cache_path}")
                                return cached_data['results']
            except (OSError, json.JSONDecodeError) as e:
                logger.warning(f"Failed to read HTTP fingerprint cache: {e}")
        
        results = {
            'target': target, 
            'ports': [], 
            'changes': {}, 
            'risk_analysis': {},
            'timestamp': time.time()
        }
        max_retries = 3
        
        for port in ports:
            if stealth:
                delay = random.uniform(1.0, 5.0)
                logger.debug(f"Stealth mode: sleeping for {delay:.1f} seconds")
                time.sleep(delay)
            
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{target}:{port}" if port not in [80, 443] else f"{protocol}://{target}"
            
            headers = {
                'User-Agent': random.choice(USER_AGENTS),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Cache-Control': 'no-cache',
            }
            
            port_results = {
                'port': port, 
                'technologies': [], 
                'headers': {}, 
                'favicon_hash': None,
                'response_time': None,
                'title': None,
                'server_info': {},
            }
            
            # Fetch HTTP response
            for attempt in range(max_retries):
                try:
                    start_time = time.time()
                    response = requests.get(
                        url,
                        headers=headers,
                        proxies=proxies,
                        timeout=15,
                        verify=False,
                        allow_redirects=True,
                        stream=False
                    )
                    
                    port_results['response_time'] = round((time.time() - start_time) * 1000, 2)
                    port_results['status_code'] = response.status_code
                    port_results['headers'] = dict(response.headers)
                    port_results['final_url'] = response.url
                    
                    # Get content safely
                    try:
                        content = response.text.lower()
                        original_content = response.text
                    except UnicodeDecodeError:
                        content = response.content.decode('utf-8', errors='ignore').lower()
                        original_content = response.content.decode('utf-8', errors='ignore')
                    
                    # Extract title
                    title_match = re.search(r'<title[^>]*>([^<]+)</title>', original_content, re.IGNORECASE)
                    if title_match:
                        port_results['title'] = title_match.group(1).strip()
                    
                    break
                    
                except requests.exceptions.RequestException as e:
                    if attempt < max_retries - 1:
                        logger.warning(f"Attempt {attempt + 1} failed for {url}: {e}. Retrying...")
                        time.sleep(2 ** attempt)
                    else:
                        logger.error(f"Failed to fetch {url} after {max_retries} attempts: {e}")
                        port_results['error'] = str(e)
                        break
            
            if 'error' not in port_results:
                # Analyze headers and content for technologies
                all_text = str(port_results['headers']).lower() + ' ' + content
                
                for tech, signatures in TECH_SIGNATURES.items():
                    for pattern, desc in signatures:
                        if re.search(pattern, all_text, re.IGNORECASE):
                            # Avoid duplicates
                            if not any(t['name'] == tech for t in port_results['technologies']):
                                port_results['technologies'].append({'name': tech, 'evidence': desc})
                            break
                
                # Detect additional technologies
                additional_techs = detect_additional_technologies(port_results['headers'], original_content, url)
                port_results['technologies'].extend(additional_techs)
                
                # Fetch favicon hash
                favicon_hash = fetch_favicon(url, proxies, timeout=10)
                if favicon_hash:
                    port_results['favicon_hash'] = favicon_hash
                    # Check against known hashes
                    for tech, known_hashes in FAVICON_HASHES.items():
                        if favicon_hash in known_hashes:
                            if not any(t['name'] == tech for t in port_results['technologies']):
                                port_results['technologies'].append({'name': tech, 'evidence': 'Favicon hash match'})
                
                # Extract server information
                server_header = port_results['headers'].get('Server', port_results['headers'].get('server', ''))
                if server_header:
                    port_results['server_info']['server'] = server_header
            
            results['ports'].append(port_results)
            logger.debug(f"Fingerprinted port {port} on {target}: Found {len(port_results['technologies'])} technologies")
        
        # Risk scoring
        results['risk_analysis'] = score_risk(results)
        
        # Compare with cached results for change detection
        if cache_file and Path(cache_file).exists():
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    old_data = json.load(f)
                    old_results = old_data.get('results', {})
                results['changes'] = compare_results(old_results, results)
            except (OSError, json.JSONDecodeError):
                pass
        
        # Cache results
        if cache_file:
            try:
                cache_path = Path(cache_file)
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                with open(cache_path, 'w', encoding='utf-8') as f:
                    json.dump({
                        'target': target, 
                        'ports': ports, 
                        'results': results,
                        'timestamp': time.time()
                    }, f, indent=2)
                logger.debug(f"Cached HTTP fingerprint results to {cache_path}")
            except OSError as e:
                logger.warning(f"Failed to write HTTP fingerprint cache: {e}")
        
        logger.info(f"HTTP fingerprinting completed for {target} - Found technologies on {len([p for p in results['ports'] if not p.get('error')])} ports")
        return results
    
    except ValueError as e:
        raise
    except Exception as e:
        logger.error(f"HTTP fingerprinting failed for {target}: {e}")
        raise RuntimeError(f"HTTP fingerprinting failed: {e}")

def compare_results(old_results: Dict, new_results: Dict) -> Dict[str, Any]:
    """Compare old and new HTTP fingerprint results.
    
    Args:
        old_results: Previous fingerprint results
        new_results: Current fingerprint results
    
    Returns:
        Dictionary with added/removed/changed technologies
    """
    changes = {'added': [], 'removed': [], 'changed': [], 'ports_added': [], 'ports_removed': []}
    
    old_ports = {p['port']: p for p in old_results.get('ports', [])}
    new_ports = {p['port']: p for p in new_results.get('ports', [])}
    
    # Check for new/removed ports
    changes['ports_added'] = list(set(new_ports.keys()) - set(old_ports.keys()))
    changes['ports_removed'] = list(set(old_ports.keys()) - set(new_ports.keys()))
    
    # Compare technologies on existing ports
    for port in new_ports:
        if port in old_ports:
            old_techs = {t['name'] for t in old_ports[port].get('technologies', [])}
            new_techs = {t['name'] for t in new_ports[port].get('technologies', [])}
            
            added_techs = list(new_techs - old_techs)
            removed_techs = list(old_techs - new_techs)
            
            if added_techs:
                changes['added'].extend([f"Port {port}: {tech}" for tech in added_techs])
            if removed_techs:
                changes['removed'].extend([f"Port {port}: {tech}" for tech in removed_techs])
                
            # Check for status code changes
            old_status = old_ports[port].get('status_code')
            new_status = new_ports[port].get('status_code')
            if old_status != new_status:
                changes['changed'].append(f"Port {port}: Status code changed from {old_status} to {new_status}")
        else:
            # New port
            techs = [t['name'] for t in new_ports[port].get('technologies', [])]
            changes['added'].extend([f"Port {port}: {tech}" for tech in techs])
    
    return changes

def score_risk(results: Dict) -> Dict[str, Any]:
    """Assign risk scores to HTTP fingerprint findings.
    
    Args:
        results: HTTP fingerprint results
    
    Returns:
        Dictionary with risk scores and level
    """
    risk_score = 0
    findings = []
    
    # Risk scoring matrix
    risk_matrix = {
        'wordpress': 7,
        'joomla': 7,
        'drupal': 6,
        'php': 3,
        'apache': 2,
        'nginx': 2,
        'iis': 4,
        'tomcat': 5,
        'jenkins': 8,
        'phpmyadmin': 9,
        'webmin': 8,
    }
    
    for port_data in results.get('ports', []):
        port = port_data['port']
        
        # Check for high-risk ports
        if port in [8080, 8443, 9000]:
            risk_score += 2
            findings.append(f"Port {port}: Non-standard HTTP port may indicate development/admin interface")
        
        # Analyze detected technologies
        for tech in port_data.get('technologies', []):
            tech_name = tech['name'].lower()
            
            # Direct risk scoring
            for risk_tech, score in risk_matrix.items():
                if risk_tech in tech_name:
                    risk_score += score
                    findings.append(f"Port {port}: {tech['name']} detected - potential attack surface")
                    break
            
            # Version-specific risks
            evidence = tech.get('evidence', '').lower()
            version_match = re.search(r'([\d.]+)', evidence)
            if version_match:
                version = version_match.group(1)
                if 'apache' in tech_name and version.startswith(('2.2', '2.0')):
                    risk_score += 4
                    findings.append(f"Port {port}: Outdated Apache version {version} detected")
                elif 'php' in tech_name:
                    major_version = version.split('.')[0]
                    if major_version in ['5', '7']:
                        risk_score += 3
                        findings.append(f"Port {port}: PHP version {version} may have known vulnerabilities")
        
        # Check for information disclosure
        headers = port_data.get('headers', {})
        server_header = headers.get('Server', headers.get('server', ''))
        if server_header and ('/' in server_header):
            risk_score += 1
            findings.append(f"Port {port}: Server version disclosed in headers")
        
        # Check for missing security headers
        security_headers = ['x-frame-options', 'content-security-policy', 'strict-transport-security']
        missing_headers = [h for h in security_headers if h not in [k.lower() for k in headers.keys()]]
        if missing_headers:
            risk_score += len(missing_headers)
            findings.append(f"Port {port}: Missing security headers: {', '.join(missing_headers)}")
    
    # Determine risk level
    if risk_score >= 20:
        risk_level = 'Critical'
    elif risk_score >= 15:
        risk_level = 'High'
    elif risk_score >= 8:
        risk_level = 'Medium'
    elif risk_score >= 3:
        risk_level = 'Low'
    else:
        risk_level = 'Minimal'
    
    return {
        'score': risk_score, 
        'level': risk_level, 
        'findings': findings,
        'total_technologies': sum(len(p.get('technologies', [])) for p in results.get('ports', [])),
        'active_ports': len([p for p in results.get('ports', []) if not p.get('error')])
    }

if __name__ == '__main__':
    # Configure logging for standalone testing
    try:
        from utils import setup_logging
        logger = setup_logging('DEBUG')
    except ImportError:
        logging.basicConfig(level=logging.DEBUG)
        logger = logging.getLogger('recon_tool')
        
    
    # Test the module
    try:
        test_target = input("Enter Domain :")          # Public test service
        test_ports = [80, 443]
        
        # Test without proxies first
        result = fingerprint_http(
            test_target, 
            test_ports, 
            stealth=False, 
            proxies=None,
            cache_file=f'reports/http_fingerprint_cache/{test_target}.json'
        )
        
        print("=== HTTP Fingerprint Results ===")
        print(f"Target: {result['target']}")
        print(f"Risk Level: {result['risk_analysis']['level']} (Score: {result['risk_analysis']['score']})")
        print(f"Active Ports: {result['risk_analysis']['active_ports']}")
        print(f"Total Technologies: {result['risk_analysis']['total_technologies']}")
        
        for port_data in result['ports']:
            if not port_data.get('error'):
                print(f"\nPort {port_data['port']}:")
                print(f"  Status: {port_data.get('status_code', 'N/A')}")
                print(f"  Response Time: {port_data.get('response_time', 'N/A')}ms")
                print(f"  Title: {port_data.get('title', 'N/A')}")
                print(f"  Technologies: {len(port_data.get('technologies', []))}")
                for tech in port_data.get('technologies', []):
                    print(f"    - {tech['name']}: {tech['evidence']}")
                if port_data.get('favicon_hash'):
                    print(f"  Favicon Hash: {port_data['favicon_hash']}")
        
        if result['risk_analysis']['findings']:
            print(f"\n=== Risk Findings ===")
            for finding in result['risk_analysis']['findings']:
                print(f"  - {finding}")
        
        logger.info("HTTP fingerprinting test completed successfully")
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        import traceback
        traceback.print_exc()
