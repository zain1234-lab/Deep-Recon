import logging
import re
import hashlib
import base64
import urllib.parse
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from pathlib import Path
import json
import requests
import random
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import statistics
from datetime import datetime, timedelta
import socket
import ssl
import gzip
from urllib.robotparser import RobotFileParser
import mimetypes
from difflib import SequenceMatcher
import xml.etree.ElementTree as ET
import csv
import html
from queue import Queue

# Initialize logger
logger = logging.getLogger('recon_tool')

# Common HTTP ports
HTTP_PORTS = [80, 443, 8080, 8443]

# Default wordlist (subset for standalone use)
DEFAULT_WORDLIST = [
    'admin', 'login', 'wp-admin', 'wp-login.php', 'phpinfo.php', '.env', '.git', 'config', 
    'backup', 'uploads', 'manager', 'dashboard', 'api', 'test', 'dev'
]

# CMS-specific wordlist additions
CMS_WORDLISTS = {
    'WordPress': ['wp-content', 'wp-includes', 'wp-admin', 'wp-login.php', 'xmlrpc.php', 'wp-config.php', 'wp-json'],
    'Drupal': ['sites/default', 'misc/drupal.js', 'user/login', 'admin/config', 'core/misc/drupal.js'],
    'Joomla': ['administrator', 'components', 'modules', 'templates', 'libraries', 'configuration.php'],
    'Magento': ['admin', 'app/etc/config.xml', 'downloader', 'skin', 'js/mage'],
    'Django': ['admin/', 'static/', 'media/', 'api/', '__debug__/'],
    'Laravel': ['public/', 'storage/', 'vendor/', 'artisan', '.env'],
    'Express': ['node_modules/', 'public/', 'views/', 'routes/', 'package.json'],
    'Spring': ['actuator/', 'swagger-ui/', 'h2-console/', 'metrics/', 'health/']
}

# Technology-specific paths
TECH_WORDLISTS = {
    'PHP': ['phpinfo.php', 'info.php', 'test.php', 'config.php', 'index.php'],
    'ASP.NET': ['web.config', 'global.asax', 'bin/', 'App_Data/', 'Default.aspx'],
    'Java': ['WEB-INF/', 'META-INF/', 'servlet/', 'jsp/', 'struts/'],
    'Python': ['__pycache__/', '*.pyc', 'requirements.txt', 'setup.py', 'wsgi.py'],
    'Ruby': ['Gemfile', 'config.ru', 'app/', 'lib/', 'public/'],
    'Node.js': ['package.json', 'node_modules/', 'server.js', 'app.js', 'public/']
}

# User-Agent rotation list with realistic patterns
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0'
]

# WAF signatures for detection
WAF_SIGNATURES = {
    'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid', 'cf-cache-status'],
    'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id', 'x-amzn-trace-id'],
    'Akamai': ['akamai', 'x-akamai', 'ak-'], 
    'Incapsula': ['incap_ses', 'visid_incap', 'x-iinfo'],
    'Sucuri': ['x-sucuri', 'sucuri'],
    'ModSecurity': ['mod_security', 'modsecurity'],
    'F5 BIG-IP': ['f5-', 'bigip', 'x-wa-info']
}

# Sensitive file patterns with risk levels
SENSITIVE_PATTERNS = {
    'critical': [
        r'\.env$', r'\.git/config$', r'web\.config$', r'\.htaccess$', r'\.htpasswd$',
        r'wp-config\.php$', r'configuration\.php$', r'config\.php$', r'settings\.py$',
        r'database\.yml$', r'production\.json$', r'\.aws/credentials$', r'id_rsa$',
        r'\.ssh/.*$', r'backup\.(sql|gz|tar|zip)$', r'dump\.(sql|gz)$'
    ],
    'high': [
        r'admin', r'login', r'dashboard', r'manager', r'control', r'panel',
        r'phpinfo\.php$', r'info\.php$', r'test\.php$', r'debug', r'trace',
        r'error_log$', r'access_log$', r'logs?/', r'temp/', r'tmp/', r'cache/'
    ],
    'medium': [
        r'readme', r'changelog', r'license', r'install', r'setup',
        r'robots\.txt$', r'sitemap\.xml$', r'crossdomain\.xml$', r'humans\.txt$'
    ]
}

@dataclass
class ProxyStatus:
    """Track proxy health and performance"""
    url: str
    healthy: bool = True
    response_time: float = 0.0
    success_count: int = 0
    failure_count: int = 0
    last_used: datetime = field(default_factory=datetime.now)
    
    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        return self.success_count / total if total > 0 else 0.0

@dataclass
class ResponseProfile:
    """Profile HTTP responses for similarity detection"""
    status_code: int
    content_hash: str
    content_length: int
    headers_hash: str
    response_time: float
    similarity_group: Optional[str] = None
    content_type: Optional[str] = None
    risk_score: float = 0.0

@dataclass
class TechnologyFingerprint:
    """Store detected technology information"""
    name: str
    version: Optional[str] = None
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)

class WAFDetector:
    """Advanced WAF detection and bypass techniques"""
    
    def __init__(self):
        self.detected_wafs = set()
        self.bypass_techniques = []
    
    def detect_waf(self, response: requests.Response, url: str) -> List[str]:
        """Detect WAF presence from response"""
        detected = []
        
        headers_str = str(response.headers).lower()
        for waf_name, signatures in WAF_SIGNATURES.items():
            if any(sig.lower() in headers_str for sig in signatures):
                detected.append(waf_name)
        
        content = response.text.lower()
        waf_content_patterns = {
            'Cloudflare': ['cloudflare', 'cf-ray', 'attention required'],
            'Incapsula': ['incapsula', 'blocked by', 'incident id'],
            'ModSecurity': ['mod_security', 'modsecurity', 'not acceptable'],
            'Sucuri': ['sucuri', 'access denied', 'blocked by sucuri']
        }
        
        for waf_name, patterns in waf_content_patterns.items():
            if any(pattern in content for pattern in patterns):
                detected.append(waf_name)
        
        if response.status_code in [406, 429, 503] and response.elapsed.total_seconds() > 2:
            detected.append('Generic WAF')
        
        self.detected_wafs.update(detected)
        return detected
    
    def get_bypass_headers(self) -> Dict[str, str]:
        """Generate headers for WAF bypass"""
        bypass_headers = {}
        
        if self.detected_wafs:
            bypass_headers.update({
                'X-Originating-IP': '127.0.0.1',
                'X-Forwarded-For': '127.0.0.1',
                'X-Remote-IP': '127.0.0.1',
                'X-Remote-Addr': '127.0.0.1',
                'X-Client-IP': '127.0.0.1',
                'X-Real-IP': '127.0.0.1',
                'CF-Connecting-IP': '127.0.0.1',
                'True-Client-IP': '127.0.0.1'
            })
            if 'Cloudflare' in self.detected_wafs:
                bypass_headers['User-Agent'] = random.choice(USER_AGENTS)
        return bypass_headers

class TechnologyDetector:
    """Advanced technology stack detection"""
    
    def __init__(self):
        self.signatures = self._load_signatures()
        self.detected_technologies = []
    
    def _load_signatures(self) -> Dict[str, Dict]:
        """Load technology detection signatures"""
        return {
            'WordPress': {
                'headers': ['x-powered-by.*wordpress', 'x-wp-'],
                'content': ['wp-content', 'wp-includes', '/wp-json/', 'wp-embed.min.js'],
                'meta': ['generator.*wordpress', 'wp-block-'],
                'paths': ['wp-admin', 'wp-login.php', 'xmlrpc.php']
            },
            'Drupal': {
                'headers': ['x-drupal-cache', 'x-generator.*drupal'],
                'content': ['Drupal.settings', 'drupal.js', 'sites/default'],
                'meta': ['generator.*drupal'],
                'paths': ['user/login', 'admin/config']
            },
            'Joomla': {
                'headers': ['x-content-encoded-by.*joomla'],
                'content': ['joomla', 'option=com_', 'task='],
                'meta': ['generator.*joomla'],
                'paths': ['administrator', 'components']
            },
            'Laravel': {
                'headers': ['x-powered-by.*laravel'],
                'content': ['laravel_token', 'laravel_session'],
                'cookies': ['laravel_session'],
                'paths': ['artisan', 'public', 'storage']
            },
            'Django': {
                'headers': ['x-frame-options.*django'],
                'content': ['csrfmiddlewaretoken', 'django'],
                'cookies': ['csrftoken', 'sessionid'],
                'paths': ['admin/', 'static/']
            },
            'Express': {
                'headers': ['x-powered-by.*express'],
                'content': ['express', 'node.js'],
                'paths': ['node_modules', 'package.json']
            },
            'Spring': {
                'headers': ['x-application-context', 'x-spring'],
                'content': ['spring', 'jsessionid'],
                'paths': ['actuator', 'spring-boot']
            },
            'ASP.NET': {
                'headers': ['x-powered-by.*asp.net', 'x-aspnet-version'],
                'content': ['__doPostBack', 'asp.net', 'webforms'],
                'paths': ['web.config', 'bin/', 'App_Data/']
            },
            'PHP': {
                'headers': ['x-powered-by.*php', 'server.*php'],
                'content': ['<?php', 'phpsessid'],
                'cookies': ['phpsessid'],
                'paths': ['index.php', 'config.php']
            }
        }
    
    def detect_from_response(self, response: requests.Response, url: str) -> List[TechnologyFingerprint]:
        """Detect technologies from HTTP response"""
        detected = []
        
        for tech_name, signatures in self.signatures.items():
            confidence = 0.0
            indicators = []
            
            if 'headers' in signatures:
                for pattern in signatures['headers']:
                    for header, value in response.headers.items():
                        if re.search(pattern, f"{header}: {value}", re.IGNORECASE):
                            confidence += 0.3
                            indicators.append(f"Header: {header}")
            
            if 'content' in signatures:
                content = response.text.lower()
                for pattern in signatures['content']:
                    if pattern.lower() in content:
                        confidence += 0.2
                        indicators.append(f"Content: {pattern}")
            
            if 'meta' in signatures:
                for pattern in signatures['meta']:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        confidence += 0.25
                        indicators.append(f"Meta: {pattern}")
            
            if 'cookies' in signatures:
                for cookie in signatures['cookies']:
                    if cookie.lower() in response.cookies:
                        confidence += 0.2
                        indicators.append(f"Cookie: {cookie}")
            
            if confidence > 0.2:
                tech = TechnologyFingerprint(
                    name=tech_name,
                    confidence=min(confidence, 1.0),
                    indicators=indicators,
                    paths=signatures.get('paths', [])
                )
                detected.append(tech)
        
        self.detected_technologies.extend(detected)
        return detected

class ResponseAnalyzer:
    """Analyze and classify HTTP responses"""
    
    def __init__(self):
        self.response_profiles = []
        self.similarity_groups = defaultdict(list)
        self.baseline_responses = {}
    
    def analyze_response(self, response: requests.Response, url: str) -> ResponseProfile:
        """Create response profile for analysis"""
        content_hash = hashlib.md5(response.content).hexdigest()
        headers_hash = hashlib.md5(str(sorted(response.headers.items())).encode()).hexdigest()
        content_type = response.headers.get('Content-Type', 'unknown')
        
        risk_score = 0.0
        for risk_level, patterns in SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    risk_score += {'critical': 0.9, 'high': 0.6, 'medium': 0.3}[risk_level]
        
        profile = ResponseProfile(
            status_code=response.status_code,
            content_hash=content_hash,
            content_length=len(response.content),
            headers_hash=headers_hash,
            response_time=response.elapsed.total_seconds(),
            content_type=content_type,
            risk_score=risk_score
        )
        
        self._group_similar_responses(profile)
        self.response_profiles.append(profile)
        
        return profile
    
    def _group_similar_responses(self, profile: ResponseProfile):
        """Group responses by similarity"""
        for group_id, group_profiles in self.similarity_groups.items():
            if group_profiles:
                sample_profile = group_profiles[0]
                content_similarity = SequenceMatcher(None, sample_profile.content_hash, profile.content_hash).ratio()
                if (profile.status_code == sample_profile.status_code and
                    abs(profile.content_length - sample_profile.content_length) < 100 and
                    content_similarity > 0.8):
                    profile.similarity_group = group_id
                    group_profiles.append(profile)
                    return
        
        group_id = f"group_{len(self.similarity_groups)}"
        profile.similarity_group = group_id
        self.similarity_groups[group_id].append(profile)
    
    def is_interesting_response(self, profile: ResponseProfile) -> bool:
        """Determine if response is worth investigating"""
        if profile.similarity_group:
            group_size = len(self.similarity_groups[profile.similarity_group])
            if group_size > 10:
                return False
        
        if profile.status_code not in [200, 404, 403, 301, 302]:
            return True
        
        if profile.risk_score > 0.5:
            return True
        
        if profile.content_length > 0:
            avg_size = statistics.mean([p.content_length for p in self.response_profiles if p.status_code == profile.status_code] or [profile.content_length])
            if abs(profile.content_length - avg_size) > avg_size * 0.5:
                return True
        
        return profile.status_code in [200, 403, 301, 302]

class ProxyManager:
    """Manage proxy rotation and health checking"""
    
    def __init__(self, proxies: Optional[List[str]] = None):
        self.proxies = []
        self.current_proxy_index = 0
        self.lock = threading.Lock()
        
        if proxies:
            for proxy_url in proxies:
                self.proxies.append(ProxyStatus(url=proxy_url))
    
    def get_next_proxy(self) -> Optional[Dict[str, str]]:
        """Get next healthy proxy"""
        if not self.proxies:
            return None
        
        with self.lock:
            healthy_proxies = [p for p in self.proxies if p.healthy]
            if not healthy_proxies:
                return None
            
            proxy = healthy_proxies[self.current_proxy_index % len(healthy_proxies)]
            self.current_proxy_index += 1
            
            proxy.last_used = datetime.now()
            return {'http': proxy.url, 'https': proxy.url}
    
    def mark_proxy_status(self, proxy_url: str, success: bool, response_time: float = 0.0):
        """Update proxy health status"""
        with self.lock:
            for proxy in self.proxies:
                if proxy.url == proxy_url:
                    if success:
                        proxy.success_count += 1
                        proxy.response_time = response_time
                        proxy.healthy = True
                    else:
                        proxy.failure_count += 1
                        if proxy.success_rate < 0.5:
                            proxy.healthy = False
                    break

class RateLimiter:
    """Adaptive rate limiting with WAF detection"""
    
    def __init__(self, base_delay: float = 0.1):
        self.base_delay = base_delay
        self.current_delay = base_delay
        self.consecutive_errors = 0
        self.last_request_time = 0
        self.lock = threading.Lock()
    
    def wait(self):
        """Wait according to current rate limit"""
        with self.lock:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            
            if time_since_last < self.current_delay:
                time.sleep(self.current_delay - time_since_last)
            
            self.last_request_time = time.time()
    
    def adjust_rate(self, response_code: int, response_time: float):
        """Adjust rate limiting based on response"""
        with self.lock:
            if response_code == 429:  # Too Many Requests
                self.consecutive_errors += 1
                self.current_delay = min(self.current_delay * 2, 10.0)
                logger.warning(f"Rate limit detected, increasing delay to {self.current_delay}s")
            elif response_code in [503, 502, 504]:  # Server errors
                self.consecutive_errors += 1
                self.current_delay = min(self.current_delay * 1.5, 5.0)
            elif 200 <= response_code < 300:  # Success
                if self.consecutive_errors > 0:
                    self.consecutive_errors = max(0, self.consecutive_errors - 1)
                    if self.consecutive_errors == 0:
                        self.current_delay = max(self.base_delay, self.current_delay * 0.8)
            
            # Adjust based on response time
            if response_time > 2.0:
                self.current_delay = min(self.current_delay * 1.2, 3.0)
            elif response_time < 0.5 and self.consecutive_errors == 0:
                self.current_delay = max(self.base_delay, self.current_delay * 0.9)

def sanitize_target(target: str) -> str:
    """Validate and sanitize target (IP or domain)"""
    if not target or not isinstance(target, str):
        logger.error("Invalid target: empty or not a string")
        raise ValueError("Target must be a non-empty string")
    
    target = target.strip()
    
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    
    if not (re.match(ip_pattern, target) or re.match(ipv6_pattern, target) or re.match(domain_pattern, target)):
        logger.error(f"Invalid IP or domain: {target}")
        raise ValueError("Invalid IP or domain format")
    
    return target

def sanitize_port(port: int) -> int:
    """Validate port number"""
    if not isinstance(port, int) or not 1 <= port <= 65535:
        logger.error(f"Invalid port: {port}")
        raise ValueError("Port must be an integer between 1 and 65535")
    return port

def load_wordlist(wordlist_path: Optional[str] = None, cms: Optional[str] = None) -> List[str]:
    """Load wordlist for directory enumeration"""
    wordlist = DEFAULT_WORDLIST.copy()
    
    if cms and cms in CMS_WORDLISTS:
        wordlist.extend(CMS_WORDLISTS[cms])
        logger.debug(f"Added CMS-specific paths for {cms}")
    
    for tech, paths in TECH_WORDLISTS.items():
        if cms and tech.lower() in cms.lower():
            wordlist.extend(paths)
            logger.debug(f"Added technology-specific paths for {tech}")
    
    if wordlist_path:
        try:
            wordlist_file = Path(wordlist_path)
            if wordlist_file.exists():
                with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                    custom_words = []
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if '\t' in line:
                                line = line.split('\t')[0]
                            custom_words.append(line)
                        if len(custom_words) > 10000:
                            logger.warning(f"Wordlist truncated to 10000 entries")
                            break
                    wordlist.extend(custom_words)
                    logger.info(f"Loaded {len(custom_words)} paths from custom wordlist")
            else:
                logger.warning(f"Wordlist file not found: {wordlist_path}")
        except OSError as e:
            logger.error(f"Failed to load wordlist {wordlist_path}: {e}")
            raise
    
    return sorted(list(set(wordlist)))

def extract_robots_txt(target: str, port: int) -> List[str]:
    """Extract paths from robots.txt"""
    paths = []
    try:
        protocol = 'https' if port in [443, 8443] else 'http'
        robots_url = f"{protocol}://{target}:{port}/robots.txt" if port not in [80, 443] else f"{protocol}://{target}/robots.txt"
        
        response = requests.get(robots_url, timeout=10, verify=False)
        if response.status_code == 200:
            for line in response.text.split('\n'):
                line = line.strip()
                if line.startswith(('Disallow:', 'Allow:')):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        paths.append(path.lstrip('/'))
            logger.debug(f"Extracted {len(paths)} paths from robots.txt")
    except Exception as e:
        logger.debug(f"Failed to fetch robots.txt: {e}")
    
    return paths

def generate_intelligent_paths(detected_technologies: List[TechnologyFingerprint]) -> List[str]:
    """Generate paths based on detected technologies"""
    paths = []
    
    for tech in detected_technologies:
        if tech.confidence > 0.5:
            if tech.name in TECH_WORDLISTS:
                paths.extend(TECH_WORDLISTS[tech.name])
            if tech.name in CMS_WORDLISTS:
                paths.extend(CMS_WORDLISTS[tech.name])
            if tech.version:
                version_paths = [
                    f"v{tech.version}/",
                    f"version{tech.version}/",
                    f"{tech.name.lower()}-{tech.version}/",
                    f"{tech.version}/"
                ]
                paths.extend(version_paths)
    
    return list(set(paths))

class PluginManager:
    """Manage custom plugins for extensibility"""
    
    def __init__(self, plugin_dir: Optional[str] = None):
        self.plugins = {}
        self.plugin_dir = Path(plugin_dir) if plugin_dir else None
    
    def load_plugins(self):
        """Load plugins from plugin directory"""
        if not self.plugin_dir or not self.plugin_dir.exists():
            return
        
        for plugin_file in self.plugin_dir.glob("*.py"):
            try:
                module_name = plugin_file.stem
                spec = importlib.util.spec_from_file_location(module_name, plugin_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                if hasattr(module, 'process'):
                    self.plugins[module_name] = module.process
                    logger.info(f"Loaded plugin: {module_name}")
            except Exception as e:
                logger.error(f"Failed to load plugin {plugin_file}: {e}")

    def run_plugin(self, plugin_name: str, data: Any) -> Any:
        """Run a specific plugin with data"""
        if plugin_name in self.plugins:
            try:
                return self.plugins[plugin_name](data)
            except Exception as e:
                logger.error(f"Plugin {plugin_name} failed: {e}")
        return data

def export_results(results: Dict[str, Any], output_dir: str, formats: List[str]) -> List[str]:
    """Export results to specified formats"""
    output_files = []
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = f"dir_enum_{results['target']}_{timestamp}"
    
    for fmt in formats:
        file_path = output_path / f"{base_filename}.{fmt}"
        try:
            if fmt == 'json':
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2)
            elif fmt == 'xml':
                root = ET.Element("dir_enum_results")
                for key, value in results.items():
                    child = ET.SubElement(root, key)
                    child.text = str(value)
                ET.ElementTree(root).write(file_path, encoding='utf-8', xml_declaration=True)
            elif fmt == 'csv':
                with open(file_path, 'w', encoding='utf-8', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['path', 'status_code', 'content_length', 'risk_score'])
                    writer.writeheader()
                    for port_data in results['ports']:
                        for finding in port_data.get('findings', []):
                            writer.writerow({
                                'path': finding['path'],
                                'status_code': finding['status_code'],
                                'content_length': finding['content_length'],
                                'risk_score': finding['risk_score']
                            })
            elif fmt == 'html':
                html_content = f"""
                <html><head><title>Directory Enumeration Results</title>
                <style>table {{ border-collapse: collapse; width: 100%; }} th, td {{ border: 1px solid black; padding: 8px; }}</style>
                </head><body>
                <h1>Directory Enumeration Results: {results['target']}</h1>
                <table><tr><th>Path</th><th>Status Code</th><th>Content Length</th><th>Risk Score</th></tr>
                """
                for port_data in results['ports']:
                    for finding in port_data.get('findings', []):
                        html_content += f"<tr><td>{html.escape(finding['path'])}</td><td>{finding['status_code']}</td><td>{finding['content_length']}</td><td>{finding['risk_score']}</td></tr>"
                html_content += "</table></body></html>"
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            output_files.append(str(file_path))
            logger.info(f"Exported results to {file_path}")
        except Exception as e:
            logger.error(f"Failed to export results to {fmt}: {e}")
    
    return output_files

def dir_enum(target: str, ports: List[int], wordlist_path: Optional[str] = None, stealth: bool = False, proxies: Optional[Dict[str, str]] = None, cache_file: Optional[str] = None, cms: Optional[str] = None, output_dir: str = './enum_results', formats: List[str] = ['json']) -> Dict[str, Any]:
    """Enumerate directories and files on HTTP services"""
    try:
        start_time = datetime.now()
        target = sanitize_target(target)
        ports = [sanitize_port(p) for p in ports] if ports else HTTP_PORTS
        
        logger.info(f"Starting directory enumeration on {target} for ports {ports}")
        
        waf_detector = WAFDetector()
        tech_detector = TechnologyDetector()
        response_analyzer = ResponseAnalyzer()
        rate_limiter = RateLimiter(0.1 if stealth else 0.01)
        proxy_manager = ProxyManager([proxies['http']] if proxies else None)
        plugin_manager = PluginManager()
        
        if cache_file:
            cache_path = Path(cache_file).resolve()
            try:
                if cache_path.exists():
                    with open(cache_path, 'r', encoding='utf-8') as f:
                        cached_data = json.load(f)
                        cache_time = datetime.fromisoformat(cached_data.get('timestamp', '1970-01-01'))
                        if (cached_data.get('target') == target and 
                            sorted(cached_data.get('ports', [])) == sorted(ports) and
                            datetime.now() - cache_time < timedelta(hours=24)):
                            logger.info(f"Using cached results from {cache_path}")
                            return cached_data['results']
            except Exception as e:
                logger.warning(f"Failed to read cache: {e}")
        
        results = {
            'target': target,
            'ports': [],
            'technologies': [],
            'waf_detected': [],
            'scan_info': {
                'start_time': start_time.isoformat(),
                'stealth_mode': stealth,
                'total_requests': 0,
                'successful_requests': 0
            }
        }
        
        wordlist = load_wordlist(wordlist_path, cms)
        wordlist.extend(extract_robots_txt(target, ports[0]))
        
        def create_request_session() -> requests.Session:
            session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=20,
                pool_maxsize=20,
                max_retries=3
            )
            session.mount('http://', adapter)
            session.mount('https://', adapter)
            return session
        
        for port in ports:
            port_results = {'port': port, 'findings': []}
            protocol = 'https' if port in [443, 8443] else 'http'
            base_url = f"{protocol}://{target}:{port}" if port not in [80, 443] else f"{protocol}://{target}"
            
            session = create_request_session()
            
            with ThreadPoolExecutor(max_workers=10 if stealth else 20) as executor:
                futures = []
                for path in wordlist:
                    url = f"{base_url}/{path.lstrip('/')}"
                    
                    def make_request(url: str, method: str = 'GET'):
                        headers = {
                            'User-Agent': random.choice(USER_AGENTS),
                            'Accept': '*/*',
                            'Accept-Encoding': 'gzip, deflate',
                        }
                        headers.update(waf_detector.get_bypass_headers())
                        
                        rate_limiter.wait()
                        proxy = proxy_manager.get_next_proxy() if proxy_manager else None
                        
                        try:
                            start = time.time()
                            response = session.request(
                                method=method,
                                url=url,
                                headers=headers,
                                proxies=proxy,
                                timeout=10,
                                verify=False,
                                allow_redirects=True
                            )
                            response_time = time.time() - start
                            
                            results['scan_info']['total_requests'] += 1
                            if 200 <= response.status_code < 400:
                                results['scan_info']['successful_requests'] += 1
                            
                            rate_limiter.adjust_rate(response.status_code, response_time)
                            if proxy:
                                proxy_manager.mark_proxy_status(proxy['http'], success=True, response_time=response_time)
                            
                            profile = response_analyzer.analyze_response(response, url)
                            if response_analyzer.is_interesting_response(profile):
                                techs = tech_detector.detect_from_response(response, url)
                                results['technologies'].extend([asdict(t) for t in techs])
                                
                                wafs = waf_detector.detect_waf(response, url)
                                results['waf_detected'].extend(wafs)
                                
                                port_results['findings'].append({
                                    'path': path,
                                    'url': url,
                                    'status_code': response.status_code,
                                    'content_length': profile.content_length,
                                    'content_type': profile.content_type,
                                    'risk_score': profile.risk_score,
                                    'response_time': response_time
                                })
                            
                        except Exception as e:
                            logger.debug(f"Request to {url} failed: {e}")
                            if proxy:
                                proxy_manager.mark_proxy_status(proxy['http'], success=False)
                            rate_limiter.adjust_rate(500, 0)
                    
                    futures.append(executor.submit(make_request, url))
                
                for future in as_completed(futures):
                    future.result()
            
            results['ports'].append(port_results)
            session.close()
        
        intelligent_paths = generate_intelligent_paths(tech_detector.detected_technologies)
        if intelligent_paths:
            wordlist.extend(intelligent_paths)
            for port in ports:
                port_results = next(p for p in results['ports'] if p['port'] == port)
                session = create_request_session()
                
                with ThreadPoolExecutor(max_workers=5) as executor:
                    futures = []
                    for path in intelligent_paths:
                        url = f"{base_url}/{path.lstrip('/')}"
                        futures.append(executor.submit(make_request, url))
                    for future in as_completed(futures):
                        future.result()
                
                session.close()
        
        results['summary'] = {
            'total_findings': sum(len(p['findings']) for p in results['ports']),
            'risk_summary': {
                'critical': sum(1 for p in results['ports'] for f in p['findings'] if f['risk_score'] >= 0.9),
                'high': sum(1 for p in results['ports'] for f in p['findings'] if 0.6 <= f['risk_score'] < 0.9),
                'medium': sum(1 for p in results['ports'] for f in p['findings'] if 0.3 <= f['risk_score'] < 0.6),
                'low': sum(1 for p in results['ports'] for f in p['findings'] if f['risk_score'] < 0.3)
            }
        }
        
        if cache_file:
            try:
                with open(cache_path, 'w', encoding='utf-8') as f:
                    json.dump({
                        'timestamp': datetime.now().isoformat(),
                        'target': target,
                        'ports': ports,
                        'results': results
                    }, f, indent=2)
                logger.info(f"Saved results to cache: {cache_path}")
            except Exception as e:
                logger.error(f"Failed to save cache: {e}")
        
        output_files = export_results(results, output_dir, formats)
        results['output_files'] = output_files
        
        return results
    
    except Exception as e:
        logger.error(f"Directory enumeration failed: {e}")
        raise RuntimeError(f"Enumeration failed: {e}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    try:
        result = dir_enum(
            target=input("Target :"),
            ports=[80, 443],
            wordlist_path=None,
            stealth=True,
            proxies={'http': 'http://proxy:8080'},
            cache_file="dir_enum_cache.json",
            cms="WordPress",
            output_dir="./enum_results",
            formats=['json', 'html']
        )
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error: {e}")
