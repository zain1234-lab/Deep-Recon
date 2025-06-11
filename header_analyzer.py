import logging
import re
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path
import json
import requests
import random
import time
import hashlib
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import threading
import asyncio
import aiohttp
import ssl

# Initialize logger
logger = logging.getLogger('recon_tool')

# Thread-safe cache
_cache_lock = threading.RLock()

# Dynamic port detection based on service fingerprinting
def get_dynamic_http_ports() -> List[int]:
    """Dynamically determine common HTTP ports based on current web standards."""
    common_ports = [80, 443, 8080, 8443, 8000, 8008, 3000, 5000, 9000, 9443]
    alternate_ports = [81, 82, 83, 280, 300, 591, 593, 832, 981, 1010, 1311, 2082, 2087, 2095, 2096, 2480, 3128, 3333, 4243, 4567, 4711, 4712, 5104, 5108, 6543, 7000, 7396, 7474, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8009, 8010, 8011, 8012, 8013, 8014, 8015, 8016, 8017, 8018, 8019, 8020, 8021, 8022, 8025, 8030, 8040, 8042, 8050, 8060, 8070, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099, 8100, 8180, 8181, 8243, 8280, 8281, 8333, 8403, 8443, 8500, 8800, 8834, 8880, 8888, 8983, 9000, 9001, 9002, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9800, 9981, 12443, 16080, 18091, 18092, 20720]
    return common_ports + random.sample(alternate_ports, min(10, len(alternate_ports)))

HTTP_PORTS = get_dynamic_http_ports()

# Enhanced security headers with dynamic validation and intelligence
def get_dynamic_security_headers() -> Dict[str, Dict]:
    """Get dynamically updated security headers based on current web security standards."""
    return {
        'Strict-Transport-Security': {
            'desc': 'Enforces HTTPS connections (HSTS)',
            'check': lambda h: _validate_hsts(h),
            'missing_risk': 'High',
            'missing_exploit': 'Allows man-in-the-middle attacks without HTTPS enforcement',
            'invalid_risk': 'Medium',
            'invalid_exploit': 'Weak HSTS configuration may be bypassed',
            'recommendation': 'Set max-age to at least 31536000 (1 year) with includeSubDomains'
        },
        'Content-Security-Policy': {
            'desc': 'Restricts resource loading to prevent XSS',
            'check': lambda h: _validate_csp(h),
            'missing_risk': 'High',
            'missing_exploit': 'Enables cross-site scripting (XSS) attacks',
            'invalid_risk': 'Medium',
            'invalid_exploit': 'Weak CSP may allow unsafe resource loading',
            'recommendation': 'Implement strict CSP with nonce/hash-based script sources'
        },
        'X-Frame-Options': {
            'desc': 'Prevents clickjacking by restricting framing',
            'check': lambda h: h.lower() in ['deny', 'sameorigin'],
            'missing_risk': 'High',
            'missing_exploit': 'Allows clickjacking attacks',
            'invalid_risk': 'Medium',
            'invalid_exploit': 'Invalid X-Frame-Options may allow framing',
            'recommendation': 'Use DENY or SAMEORIGIN, consider migrating to CSP frame-ancestors'
        },
        'X-Content-Type-Options': {
            'desc': 'Prevents MIME-type sniffing',
            'check': lambda h: h.lower() == 'nosniff',
            'missing_risk': 'Medium',
            'missing_exploit': 'Allows MIME-type sniffing attacks',
            'invalid_risk': 'Low',
            'invalid_exploit': 'Invalid setting may weaken protections',
            'recommendation': 'Set to nosniff'
        },
        'X-XSS-Protection': {
            'desc': 'Legacy XSS filter (deprecated but still checked)',
            'check': lambda h: '1; mode=block' in h.lower() or '0' in h.lower(),
            'missing_risk': 'Low',
            'missing_exploit': 'May allow XSS in older browsers',
            'invalid_risk': 'Low',
            'invalid_exploit': 'Weak XSS protection may be ineffective',
            'recommendation': 'Set to 0 (disabled) as modern CSP is preferred'
        },
        'Referrer-Policy': {
            'desc': 'Controls referrer information sent to other sites',
            'check': lambda h: _validate_referrer_policy(h),
            'missing_risk': 'Medium',
            'missing_exploit': 'Leaks referrer data to external sites',
            'invalid_risk': 'Low',
            'invalid_exploit': 'Weak policy may leak sensitive URLs',
            'recommendation': 'Use strict-origin-when-cross-origin or no-referrer'
        },
        'Permissions-Policy': {
            'desc': 'Controls browser feature access',
            'check': lambda h: len(h.strip()) > 0,
            'missing_risk': 'Medium',
            'missing_exploit': 'Allows unrestricted access to browser features',
            'invalid_risk': 'Low',
            'invalid_exploit': 'Weak permissions policy may expose sensitive features',
            'recommendation': 'Restrict unnecessary features like camera, microphone, geolocation'
        },
        'Cross-Origin-Embedder-Policy': {
            'desc': 'Enables cross-origin isolation',
            'check': lambda h: h.lower() in ['require-corp', 'credentialless'],
            'missing_risk': 'Low',
            'missing_exploit': 'May allow cross-origin attacks in modern browsers',
            'invalid_risk': 'Low',
            'invalid_exploit': 'Weak COEP may reduce isolation',
            'recommendation': 'Use require-corp for enhanced security'
        },
        'Cross-Origin-Opener-Policy': {
            'desc': 'Prevents cross-origin window references',
            'check': lambda h: h.lower() in ['same-origin', 'same-origin-allow-popups'],
            'missing_risk': 'Low',
            'missing_exploit': 'May allow cross-origin window manipulation',
            'invalid_risk': 'Low',
            'invalid_exploit': 'Weak COOP may reduce isolation',
            'recommendation': 'Use same-origin for maximum protection'
        }
    }

def _validate_hsts(header_value: str) -> bool:
    """Intelligently validate HSTS header."""
    if not header_value:
        return 
        False
    header_lower = header_value.lower()
    if 'max-age' not in header_lower:
        return False
    
    max_age_match = re.search(r'max-age=(\d+)', header_lower)
    if not max_age_match:
        return False
    
    max_age = int(max_age_match.group(1))
    # Good: >= 1 year, Excellent: >= 2 years
    return max_age >= 31536000

def _validate_csp(header_value: str) -> bool:
    """Intelligently validate CSP header."""
    if not header_value:
        return False
    
    header_lower = header_value.lower()
    dangerous_keywords = ['unsafe-inline', 'unsafe-eval', '*', 'data:', 'http:']
    has_strict_directives = any(directive in header_lower for directive in ['default-src', 'script-src', 'object-src'])
    has_dangerous = any(keyword in header_lower for keyword in dangerous_keywords)
    
    return has_strict_directives and not has_dangerous

def _validate_referrer_policy(header_value: str) -> bool:
    """Intelligently validate Referrer Policy."""
    if not header_value:
        return False
    
    secure_policies = [
        'no-referrer', 'same-origin', 'strict-origin', 
        'strict-origin-when-cross-origin', 'no-referrer-when-downgrade'
    ]
    return header_value.lower().strip() in secure_policies

# Dynamic User-Agent generation
def generate_user_agents() -> List[str]:
    """Generate diverse, realistic user agents."""
    chrome_versions = ['120.0.0.0', '119.0.0.0', '118.0.0.0', '117.0.0.0']
    firefox_versions = ['120.0', '119.0', '118.0', '117.0']
    safari_versions = ['17.1', '17.0', '16.6', '16.5']
    
    user_agents = []
    
    # Chrome variants
    for version in chrome_versions:
        user_agents.extend([
            f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36',
            f'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36',
            f'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36'
        ])
    
    # Firefox variants
    for version in firefox_versions:
        user_agents.extend([
            f'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{version}) Gecko/20100101 Firefox/{version}',
            f'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:{version}) Gecko/20100101 Firefox/{version}',
            f'Mozilla/5.0 (X11; Linux x86_64; rv:{version}) Gecko/20100101 Firefox/{version}'
        ])
    
    # Safari variants
    for version in safari_versions:
        user_agents.append(f'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version} Safari/605.1.15')
    
    return user_agents

USER_AGENTS = generate_user_agents()

def sanitize_target(target: str) -> str:
    """Enhanced target validation with support for URLs and internationalized domains."""
    if not target or not isinstance(target, str):
        logger.error("Invalid target: empty or not a string")
        raise ValueError("Target must be a non-empty string")
    
    target = target.strip()
    
    # Handle URLs
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        target = parsed.hostname or parsed.netloc
    
    # Enhanced IP validation (IPv4 and IPv6)
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'
    
    # Enhanced domain validation (including internationalized domains)
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    
    if not (re.match(ipv4_pattern, target) or re.match(ipv6_pattern, target) or re.match(domain_pattern, target, re.IGNORECASE)):
        logger.error(f"Invalid IP or domain: {target}")
        raise ValueError("Invalid IP or domain format")
    
    return target

def sanitize_port(port: int) -> int:
    """Enhanced port validation with additional checks."""
    if not isinstance(port, int) or not 1 <= port <= 65535:
        logger.error(f"Invalid port: {port}")
        raise ValueError("Port must be an integer between 1 and 65535")
    
    # Warn about commonly blocked ports
    blocked_ports = [25, 135, 139, 445, 1433, 1521, 3389, 5432]
    if port in blocked_ports:
        logger.warning(f"Port {port} is commonly blocked by firewalls")
    
    return port

def intelligent_risk_assessment(findings: List[Dict], headers: Dict[str, str], target: str) -> Dict[str, Any]:
    """Intelligent risk assessment based on multiple factors."""
    base_score = sum({'High': 10, 'Medium': 5, 'Low': 2}[f['risk']] for f in findings)
    
    # Intelligence factors
    multipliers = 1.0
    context = []
    
    # Check for high-value targets (common enterprise domains)
    enterprise_indicators = ['admin', 'api', 'portal', 'dashboard', 'secure', 'login', 'auth']
    if any(indicator in target.lower() for indicator in enterprise_indicators):
        multipliers *= 1.3
        context.append("Enterprise/Administrative target detected")
    
    # Check for development/staging environments
    dev_indicators = ['dev', 'test', 'staging', 'beta', 'demo']
    if any(indicator in target.lower() for indicator in dev_indicators):
        multipliers *= 1.5
        context.append("Development/Staging environment detected (higher risk)")
    
    # Technology stack analysis
    tech_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator']
    exposed_tech = [h for h in tech_headers if h in headers]
    if exposed_tech:
        multipliers *= 1.2
        context.append(f"Technology disclosure detected: {', '.join(exposed_tech)}")
    
    # Check for outdated or vulnerable signatures
    server_header = headers.get('Server', '').lower()
    vulnerable_servers = ['apache/2.2', 'nginx/1.0', 'iis/6.0', 'iis/7.0']
    if any(vuln in server_header for vuln in vulnerable_servers):
        multipliers *= 1.4
        context.append("Potentially outdated server version detected")
    
    final_score = int(base_score * multipliers)
    
    # Dynamic risk levels based on intelligent assessment
    if final_score >= 25:
        risk_level = 'Critical'
    elif final_score >= 15:
        risk_level = 'High'
    elif final_score >= 8:
        risk_level = 'Medium'
    elif final_score >= 3:
        risk_level = 'Low'
    else:
        risk_level = 'Minimal'
    
    return {
        'base_score': base_score,
        'intelligence_multiplier': multipliers,
        'final_score': final_score,
        'risk_level': risk_level,
        'context': context
    }

def analyze_headers(headers: Dict[str, str], target: str = "") -> Dict[str, Any]:
    """Enhanced header analysis with intelligent assessment."""
    SECURITY_HEADERS = get_dynamic_security_headers()
    findings = []
    
    # Security headers analysis
    for header, config in SECURITY_HEADERS.items():
        value = None
        # Case-insensitive header lookup
        for h_name, h_value in headers.items():
            if h_name.lower() == header.lower():
                value = h_value
                break
        
        if not value:
            findings.append({
                'header': header,
                'issue': 'Missing',
                'description': config['desc'],
                'risk': config['missing_risk'],
                'exploit': config['missing_exploit'],
                'recommendation': config.get('recommendation', 'Implement this security header')
            })
        elif not config['check'](value):
            findings.append({
                'header': header,
                'issue': 'Invalid or weak configuration',
                'description': config['desc'],
                'risk': config['invalid_risk'],
                'exploit': config['invalid_exploit'],
                'value': value,
                'recommendation': config.get('recommendation', 'Review and strengthen configuration')
            })
    
    # Information disclosure analysis
    disclosure_headers = {
        'Server': {'pattern': r'[\d.]+', 'risk': 'Medium', 'desc': 'Server version disclosure'},
        'X-Powered-By': {'pattern': r'.*', 'risk': 'Medium', 'desc': 'Technology stack disclosure'},
        'X-AspNet-Version': {'pattern': r'.*', 'risk': 'Medium', 'desc': 'ASP.NET version disclosure'},
        'X-Generator': {'pattern': r'.*', 'risk': 'Low', 'desc': 'CMS/Generator disclosure'},
        'X-Drupal-Cache': {'pattern': r'.*', 'risk': 'Low', 'desc': 'Drupal CMS disclosure'},
        'X-Varnish': {'pattern': r'.*', 'risk': 'Low', 'desc': 'Varnish cache disclosure'}
    }
    
    for header, header_info in disclosure_headers.items():
        value = headers.get(header)
        if value and (header_info['pattern'] == r'.*' or re.search(header_info['pattern'], value)):
            findings.append({
                'header': header,
                'issue': 'Information disclosure',
                'description': header_info['desc'],
                'risk': header_info['risk'],
                'exploit': f'Exposes {header_info["desc"].lower()} which may aid targeted attacks',
                'value': value,
                'recommendation': f'Remove or obfuscate {header} header'
            })
    
    # Intelligent risk assessment
    risk_assessment = intelligent_risk_assessment(findings, headers, target)
    
    return {
        'findings': findings,
        'risk_assessment': risk_assessment,
        'timestamp': datetime.now().isoformat()
    }

def get_cache_key(target: str, ports: List[int]) -> str:
    """Generate a unique cache key for target and ports."""
    data = f"{target}:{':'.join(map(str, sorted(ports)))}"
    return hashlib.md5(data.encode()).hexdigest()

def is_cache_valid(cache_data: Dict, max_age_hours: int = 24) -> bool:
    """Check if cached data is still valid."""
    if 'timestamp' not in cache_data:
        return False
    
    cache_time = datetime.fromisoformat(cache_data['timestamp'])
    return datetime.now() - cache_time < timedelta(hours=max_age_hours)

async def fetch_headers_async(session: aiohttp.ClientSession, url: str, headers: Dict[str, str], 
                            proxy: Optional[str] = None, timeout: int = 10) -> Tuple[int, Dict[str, str], Optional[str]]:
    """Asynchronously fetch headers from a URL."""
    try:
        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        async with session.get(url, headers=headers, proxy=proxy, timeout=timeout_obj, 
                              ssl=True) as response:
            return response.status, dict(response.headers), None
    except Exception as e:
        return 0, {}, str(e)

def header_analyzer(target: str, ports: Optional[List[int]] = None, stealth: bool = False, 
                   proxies: Optional[Dict[str, str]] = None, cache_file: Optional[str] = None,
                   max_workers: int = 10, timeout: int = 10, use_async: bool = True) -> Dict[str, Any]:
    """Enhanced HTTP header analyzer with async support and intelligent caching."""
    try:
        target = sanitize_target(target)
        if ports is None:
            ports = HTTP_PORTS[:8]  # Use top 8 dynamic ports if none specified
        else:
            ports = [sanitize_port(p) for p in ports]
        
        logger.info(f"Starting enhanced HTTP header analysis on {target} for ports {ports}")
        
        # Intelligent caching
        cache_key = get_cache_key(target, ports)
        cache_path = None
        
        if cache_file:
            cache_path = Path(cache_file).resolve()
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            
            with _cache_lock:
                try:
                    if cache_path.exists():
                        with open(cache_path, 'r', encoding='utf-8') as f:
                            cached_data = json.load(f)
                            if (cached_data.get('cache_key') == cache_key and 
                                is_cache_valid(cached_data)):
                                logger.debug(f"Using valid cached results from {cache_path}")
                                return cached_data['results']
                except (OSError, json.JSONDecodeError) as e:
                    logger.warning(f"Failed to read cache: {e}")
        
        results = {
            'target': target, 
            'ports': [], 
            'changes': {},
            'scan_metadata': {
                'timestamp': datetime.now().isoformat(),
                'stealth_mode': stealth,
                'async_mode': use_async,
                'total_ports': len(ports)
            }
        }
        
        if use_async:
            # Async implementation for better performance
            results['ports'] = asyncio.run(_analyze_ports_async(target, ports, stealth, proxies, timeout))
        else:
            # Threaded implementation for compatibility
            results['ports'] = _analyze_ports_threaded(target, ports, stealth, proxies, timeout, max_workers)
        
        # Compare with previous results
        if cache_path and cache_path.exists():
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    old_data = json.load(f)
                    if 'results' in old_data:
                        results['changes'] = compare_results(old_data['results'], results)
            except (OSError, json.JSONDecodeError):
                pass
        
        # Cache results with metadata
        if cache_path:
            with _cache_lock:
                try:
                    cache_data = {
                        'cache_key': cache_key,
                        'timestamp': datetime.now().isoformat(),
                        'results': results
                    }
                    with open(cache_path, 'w', encoding='utf-8') as f:
                        json.dump(cache_data, f, indent=2)
                    logger.debug(f"Cached results to {cache_path}")
                except OSError as e:
                    logger.warning(f"Failed to write cache: {e}")
        
        logger.info(f"Enhanced header analysis completed for {target}")
        return results
    
    except ValueError as e:
        raise
    except Exception as e:
        logger.error(f"Header analysis failed for {target}: {e}")
        raise RuntimeError(f"Header analysis failed: {e}")

async def _analyze_ports_async(target: str, ports: List[int], stealth: bool, 
                              proxies: Optional[Dict[str, str]], timeout: int) -> List[Dict[str, Any]]:
    """Async port analysis for improved performance."""
    connector = aiohttp.TCPConnector(limit=20, limit_per_host=5, ssl=False)
    timeout_obj = aiohttp.ClientTimeout(total=timeout)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj) as session:
        tasks = []
        
        for port in ports:
            if stealth:
                await asyncio.sleep(random.uniform(0.1, 0.5))
            
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{target}:{port}" if port not in [80, 443] else f"{protocol}://{target}"
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            proxy = proxies.get(protocol) if proxies else None
            
            task = _analyze_single_port_async(session, port, url, headers, proxy, timeout, target)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle exceptions in results
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    'port': ports[i],
                    'error': str(result)
                })
            else:
                processed_results.append(result)
        
        return processed_results

async def _analyze_single_port_async(session: aiohttp.ClientSession, port: int, url: str, 
                                   headers: Dict[str, str], proxy: Optional[str], timeout: int, target: str) -> Dict[str, Any]:
    """Analyze a single port asynchronously."""
    port_results = {'port': port, 'analysis': {}, 'headers': {}}
    
    try:
        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        async with session.get(url, headers=headers, proxy=proxy, timeout=timeout_obj, ssl=False) as response:
            port_results['status_code'] = response.status
            port_results['headers'] = dict(response.headers)
            port_results['analysis'] = analyze_headers(port_results['headers'], target)
            
    except asyncio.TimeoutError:
        port_results['error'] = f"Timeout after {timeout} seconds"
    except aiohttp.ClientError as e:
        port_results['error'] = f"Client error: {str(e)}"
    except Exception as e:
        port_results['error'] = f"Unexpected error: {str(e)}"
    
    return port_results

def _analyze_ports_threaded(target: str, ports: List[int], stealth: bool, 
                          proxies: Optional[Dict[str, str]], timeout: int, max_workers: int) -> List[Dict[str, Any]]:
    """Threaded port analysis for compatibility."""
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {}
        
        for port in ports:
            if stealth:
                time.sleep(random.uniform(0.1, 0.5))
            
            future = executor.submit(_analyze_single_port_sync, target, port, proxies, timeout)
            future_to_port[future] = port
        
        for future in as_completed(future_to_port):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                port = future_to_port[future]
                results.append({'port': port, 'error': str(e)})
    
    return sorted(results, key=lambda x: x['port'])

def _analyze_single_port_sync(target: str, port: int, proxies: Optional[Dict[str, str]], timeout: int) -> Dict[str, Any]:
    """Analyze a single port synchronously."""
    protocol = 'https' if port in [443, 8443] else 'http'
    url = f"{protocol}://{target}:{port}" if port not in [80, 443] else f"{protocol}://{target}"
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    
    port_results = {'port': port, 'analysis': {}, 'headers': {}}
    
    try:
        response = requests.get(
            url,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            verify=False,
            allow_redirects=True
        )
        port_results['status_code'] = response.status_code
        port_results['headers'] = dict(response.headers)
        port_results['analysis'] = analyze_headers(port_results['headers'], target)
        
    except requests.exceptions.RequestException as e:
        port_results['error'] = str(e)
    
    return port_results

def compare_results(old_results: Dict, new_results: Dict) -> Dict[str, Any]:
    """Enhanced result comparison with change intelligence."""
    changes = {
        'added_findings': [],
        'removed_findings': [], 
        'changed_findings': [],
        'new_ports': [],
        'removed_ports': [],
        'risk_changes': {}
    }
    
    old_ports = {p['port']: p for p in old_results.get('ports', []) if 'error' not in p}
    new_ports = {p['port']: p for p in new_results.get('ports', []) if 'error' not in p}
    
    # Port changes
    changes['new_ports'] = list(set(new_ports.keys()) - set(old_ports.keys()))
    changes['removed_ports'] = list(set(old_ports.keys()) - set(new_ports.keys()))
    
    # Finding changes per port
    for port in set(old_ports.keys()) & set(new_ports.keys()):
        old_findings = {f['header']: f for f in old_ports[port].get('analysis', {}).get('findings', [])}
        new_findings = {f['header']: f for f in new_ports[port].get('analysis', {}).get('findings', [])}
        
        added = set(new_findings.keys()) - set(old_findings.keys())
        removed = set(old_findings.keys()) - set(new_findings.keys())
        
        if added:
            changes['added_findings'].extend([{'port': port, 'header': h, 'finding': new_findings[h]} for h in added])
        if removed:
            changes['removed_findings'].extend([{'port': port, 'header': h, 'finding': old_findings[h]} for h in removed])
    
    return changes

if __name__ == '__main__':
    # Enhanced standalone testing
    try:
        from utils import setup_logging
        logger = setup_logging('DEBUG')
    except ImportError:
        logging.basicConfig(level=logging.DEBUG)
        logger = logging.getLogger('recon_tool')
    
    # Test with dynamic configuration
    try:
        test_target = input("Enter Target IP: ")  # More reliable test target
        test_ports = [80, 443]
        
        result = header_analyzer(
            target=test_target,
            ports=test_ports,
            stealth=True,
            cache_file='reports/header_cache/test_analysis.json',
            use_async=True,
            max_workers=5
        )
        
        # Display intelligent results
        print("\n" + "="*60)
        print(f"ENHANCED HEADER ANALYSIS RESULTS FOR {test_target}")
        print("="*60)
        
        for port_result in result['ports']:
            if 'error' not in port_result:
                analysis = port_result.get('analysis', {})
                risk_assessment = analysis.get('risk_assessment', {})
                
                print(f"\nPort {port_result['port']} ({port_result.get('status_code', 'N/A')})")
                print(f"Risk Level: {risk_assessment.get('risk_level', 'Unknown')}")
                print(f"Risk Score: {risk_assessment.get('final_score', 0)}")
                
                if risk_assessment.get('context'):
                    print("Intelligence Context:")
                    for ctx in risk_assessment['context']:
                        print(f"  - {ctx}")
                
                findings = analysis.get('findings', [])
                if findings:
                    print(f"Security Issues Found: {len(findings)}")
                    for finding in findings[:3]:  # Show top 3 findings
                        print(f"  • {finding['header']}: {finding['issue']} ({finding['risk']} risk)")
                        if 'recommendation' in finding:
                            print(f"    → {finding['recommendation']}")
                else:
                    print("No security issues detected")
            else:
                print(f"\nPort {port_result['port']}: {port_result['error']}")
        
        logger.info("Enhanced header analysis test completed successfully")
        
    except Exception as e:
        logger.error(f"Enhanced test failed: {e}")
        import traceback
        traceback.print_exc()
