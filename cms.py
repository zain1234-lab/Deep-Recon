import logging
import re
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path
import json
import requests
import random
import time
import hashlib
import base64
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime, timedelta
import sqlite3
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
import yaml
import socket
import ssl
import subprocess
import tempfile
import os
import mimetypes
from collections import defaultdict, Counter
import difflib
import argparse
logger = logging.getLogger('recon_tool')

@dataclass
class ComponentInfo:
    name: str
    version: Optional[str] = None
    confidence: float = 0.0
    fingerprints: List[str] = None
    last_updated: Optional[str] = None
    security_status: str = "unknown"
    
    def __post_init__(self):
        if self.fingerprints is None:
            self.fingerprints = []

@dataclass
class VulnerabilityInfo:
    cve_id: Optional[str] = None
    description: str = ""
    severity: str = "unknown"
    cvss_score: float = 0.0
    exploit_available: bool = False
    patch_available: bool = False
    affected_versions: List[str] = None
    references: List[str] = None
    
    def __post_init__(self):
        if self.affected_versions is None:
            self.affected_versions = []
        if self.references is None:
            self.references = []

# Comprehensive CMS profiles with advanced detection patterns
CMS_PROFILES = {
    'WordPress': {
        'plugin_paths': [
            '/wp-content/plugins/{slug}/readme.txt',
            '/wp-content/plugins/{slug}/',
            '/wp-content/plugins/{slug}/index.php',
            '/wp-content/plugins/{slug}/{slug}.php',
            '/wp-content/plugins/{slug}/plugin.php',
            '/wp-content/plugins/{slug}/assets/css/style.css',
            '/wp-content/plugins/{slug}/assets/js/script.js'
        ],
        'theme_paths': [
            '/wp-content/themes/{slug}/style.css',
            '/wp-content/themes/{slug}/',
            '/wp-content/themes/{slug}/index.php',
            '/wp-content/themes/{slug}/functions.php',
            '/wp-content/themes/{slug}/screenshot.png',
            '/wp-content/themes/{slug}/theme.json'
        ],
        'user_paths': [
            '/wp-json/wp/v2/users',
            '/?rest_route=/wp/v2/users',
            '/wp-json/wp/v2/users?per_page=100',
            '/author-sitemap.xml',
            '/?author=1',
            '/?author=2',
            '/?author=3',
            '/wp-admin/admin-ajax.php?action=get_users'
        ],
        'config_paths': [
            '/wp-config.php',
            '/wp-config.php.bak',
            '/wp-config.txt',
            '/.wp-config.php.swp',
            '/wp-config-sample.php'
        ],
        'backup_paths': [
            '/wp-content/backup/',
            '/wp-content/backups/',
            '/backups/',
            '/backup.sql',
            '/wp-content/uploads/backup.zip'
        ],
        'sensitive_paths': [
            '/wp-admin/',
            '/wp-login.php',
            '/wp-content/debug.log',
            '/wp-content/uploads/',
            '/.htaccess',
            '/robots.txt',
            '/sitemap.xml',
            '/readme.html',
            '/license.txt'
        ],
        'fingerprints': [
            (r'wp-content', 'WordPress content directory', 0.9),
            (r'wp-includes', 'WordPress includes directory', 0.9),
            (r'wp-admin', 'WordPress admin directory', 0.9),
            (r'<meta name="generator" content="WordPress ([^"]*)"', 'WordPress generator meta tag', 1.0),
            (r'/wp-json/', 'WordPress REST API', 0.8),
            (r'wp-emoji-release\.min\.js', 'WordPress emoji script', 0.7),
            (r'wp_enqueue_script', 'WordPress script enqueue', 0.6)
        ],
        'vuln_checks': [
            (r'WordPress\s*([\d.]+)', lambda v: compare_versions(v, '6.4') < 0, 'Outdated WordPress version', 'High', 'Exploit known CVEs, privilege escalation, or RCE'),
            (r'wp-config\.php', lambda v: True, 'WordPress configuration file exposed', 'Critical', 'Database credentials and sensitive information disclosure'),
            (r'debug\.log', lambda v: True, 'WordPress debug log exposed', 'Medium', 'Information disclosure about system paths and errors'),
            (r'xmlrpc\.php', lambda v: True, 'XML-RPC enabled', 'Medium', 'Brute force attacks and DDoS amplification')
        ],
        'version_patterns': [
            r'<meta name="generator" content="WordPress ([^"]*)"',
            r'wp-includes/js/wp-emoji-release\.min\.js\?ver=([^"]*)',
            r'/wp-content/themes/[^/]+/style\.css\?ver=([^"]*)',
            r'WordPress ([0-9.]+)',
            r'"version":"([^"]*)"'
        ]
    },
    'Joomla': {
        'plugin_paths': [
            '/components/com_{slug}/',
            '/administrator/components/com_{slug}/',
            '/plugins/system/{slug}/',
            '/plugins/content/{slug}/',
            '/plugins/user/{slug}/',
            '/modules/mod_{slug}/',
            '/administrator/modules/mod_{slug}/'
        ],
        'theme_paths': [
            '/templates/{slug}/',
            '/templates/{slug}/templateDetails.xml',
            '/templates/{slug}/index.php',
            '/administrator/templates/{slug}/'
        ],
        'user_paths': [
            '/index.php?option=com_users&view=profile',
            '/administrator/index.php?option=com_users',
            '/api/index.php/v1/users',
            '/index.php?option=com_users&view=registration'
        ],
        'config_paths': [
            '/configuration.php',
            '/configuration.php.bak',
            '/configuration.txt',
            '/.configuration.php.swp'
        ],
        'backup_paths': [
            '/administrator/backups/',
            '/tmp/',
            '/cache/',
            '/logs/'
        ],
        'sensitive_paths': [
            '/administrator/',
            '/installation/',
            '/tmp/',
            '/cache/',
            '/logs/',
            '/cli/',
            '/.htaccess',
            '/web.config'
        ],
        'fingerprints': [
            (r'/media/system/js/core\.js', 'Joomla core JavaScript', 0.9),
            (r'<meta name="generator" content="Joomla!', 'Joomla generator meta tag', 1.0),
            (r'/administrator/templates/', 'Joomla administrator templates', 0.8),
            (r'option=com_', 'Joomla component structure', 0.7),
            (r'Joomla\.JText', 'Joomla JavaScript text', 0.6)
        ],
        'vuln_checks': [
            (r'Joomla!?\s*([\d.]+)', lambda v: compare_versions(v, '4.4') < 0, 'Outdated Joomla version', 'High', 'Exploit known CVEs or privilege escalation'),
            (r'configuration\.php', lambda v: True, 'Joomla configuration file exposed', 'Critical', 'Database credentials disclosure'),
            (r'/installation/', lambda v: True, 'Installation directory accessible', 'High', 'Reinstallation attack vector'),
            (r'/tmp/.*\.php', lambda v: True, 'PHP files in temp directory', 'Medium', 'Potential backdoor or malicious uploads')
        ],
        'version_patterns': [
            r'<meta name="generator" content="Joomla! - Open Source Content Management - Version ([^"]*)"',
            r'Joomla! ([0-9.]+)',
            r'/media/system/js/core\.js\?([0-9.]+)',
            r'"version":"([^"]*)"'
        ]
    },
    'Drupal': {
        'plugin_paths': [
            '/modules/{slug}/',
            '/sites/all/modules/{slug}/',
            '/sites/default/modules/{slug}/',
            '/core/modules/{slug}/',
            '/modules/contrib/{slug}/',
            '/modules/custom/{slug}/'
        ],
        'theme_paths': [
            '/themes/{slug}/',
            '/sites/all/themes/{slug}/',
            '/sites/default/themes/{slug}/',
            '/core/themes/{slug}/',
            '/themes/contrib/{slug}/',
            '/themes/custom/{slug}/'
        ],
        'user_paths': [
            '/user',
            '/users',
            '/admin/people',
            '/api/user',
            '/jsonapi/user/user'
        ],
        'config_paths': [
            '/sites/default/settings.php',
            '/sites/default/settings.local.php',
            '/.env',
            '/sites/default/files/config_*/'
        ],
        'backup_paths': [
            '/sites/default/files/backup_migrate/',
            '/sites/default/private/',
            '/sites/default/files/private/'
        ],
        'sensitive_paths': [
            '/admin/',
            '/node/add',
            '/sites/default/files/',
            '/core/',
            '/vendor/',
            '/.htaccess',
            '/robots.txt',
            '/sitemap.xml'
        ],
        'fingerprints': [
            (r'Drupal\.settings', 'Drupal settings JavaScript', 0.9),
            (r'<meta name="generator" content="Drupal', 'Drupal generator meta tag', 1.0),
            (r'/sites/default/files/', 'Drupal files directory', 0.8),
            (r'/core/misc/drupal\.js', 'Drupal core JavaScript', 0.9),
            (r'X-Generator: Drupal', 'Drupal X-Generator header', 1.0)
        ],
        'vuln_checks': [
            (r'Drupal\s*([\d.]+)', lambda v: compare_versions(v, '10.1') < 0, 'Outdated Drupal version', 'High', 'Exploit known CVEs, RCE, or privilege escalation'),
            (r'settings\.php', lambda v: True, 'Drupal settings file exposed', 'Critical', 'Database credentials and configuration disclosure'),
            (r'/sites/default/files/.*\.php', lambda v: True, 'PHP files in files directory', 'High', 'Potential backdoor or arbitrary code execution'),
            (r'\.module', lambda v: True, 'Module files accessible', 'Low', 'Source code disclosure')
        ],
        'version_patterns': [
            r'<meta name="generator" content="Drupal ([^"]*)"',
            r'Drupal ([0-9.]+)',
            r'/core/misc/drupal\.js\?v=([^"]*)',
            r'"version":"([^"]*)"'
        ]
    },
    'Magento': {
        'plugin_paths': [
            '/app/code/community/{slug}/',
            '/app/code/local/{slug}/',
            '/app/code/{slug}/',
            '/vendor/{slug}/'
        ],
        'theme_paths': [
            '/app/design/frontend/{slug}/',
            '/skin/frontend/{slug}/',
            '/pub/static/frontend/{slug}/'
        ],
        'user_paths': [
            '/admin/',
            '/customer/account/',
            '/rest/V1/customers',
            '/api/rest/customers'
        ],
        'config_paths': [
            '/app/etc/local.xml',
            '/app/etc/env.php',
            '/app/etc/config.php'
        ],
        'backup_paths': [
            '/var/backups/',
            '/var/log/',
            '/media/backup/'
        ],
        'sensitive_paths': [
            '/admin/',
            '/downloader/',
            '/app/etc/',
            '/var/',
            '/lib/',
            '/shell/'
        ],
        'fingerprints': [
            (r'Mage\.', 'Magento JavaScript', 0.8),
            (r'/skin/frontend/', 'Magento skin directory', 0.9),
            (r'X-Magento-Tags', 'Magento cache tags header', 1.0),
            (r'var/cache', 'Magento cache directory', 0.7)
        ],
        'vuln_checks': [
            (r'Magento\s*([\d.]+)', lambda v: compare_versions(v, '2.4.6') < 0, 'Outdated Magento version', 'High', 'Known security vulnerabilities'),
            (r'downloader/', lambda v: True, 'Magento downloader exposed', 'Critical', 'Arbitrary file upload and RCE'),
            (r'app/etc/local\.xml', lambda v: True, 'Configuration file exposed', 'Critical', 'Database credentials disclosure')
        ],
        'version_patterns': [
            r'Magento/([0-9.]+)',
            r'"version":"([^"]*)"',
            r'Magento ver\. ([0-9.]+)'
        ]
    }
}

# Advanced vulnerability database
VULNERABILITY_DB = {
    'WordPress': {
        'patterns': [
            {
                'pattern': r'wp-config\.php',
                'vuln': VulnerabilityInfo(
                    description="WordPress configuration file exposed",
                    severity="Critical",
                    cvss_score=9.8,
                    exploit_available=True,
                    references=["https://owasp.org/www-project-top-ten/"]
                )
            },
            {
                'pattern': r'debug\.log',
                'vuln': VulnerabilityInfo(
                    description="WordPress debug log exposed",
                    severity="Medium",
                    cvss_score=5.3,
                    references=["https://wordpress.org/support/article/debugging-in-wordpress/"]
                )
            }
        ]
    }
}

def compare_versions(v1: str, v2: str) -> int:
    """Advanced version comparison with support for pre-release versions"""
    def normalize_version(v):
        # Handle pre-release versions (alpha, beta, rc)
        v = re.sub(r'[^\d.]', '', v)
        parts = [int(x) for x in v.split('.') if x.isdigit()]
        return parts + [0] * (4 - len(parts))  # Pad to 4 parts
    
    try:
        v1_parts = normalize_version(v1)
        v2_parts = normalize_version(v2)
        
        for i in range(max(len(v1_parts), len(v2_parts))):
            p1 = v1_parts[i] if i < len(v1_parts) else 0
            p2 = v2_parts[i] if i < len(v2_parts) else 0
            if p1 < p2:
                return -1
            elif p1 > p2:
                return 1
        return 0
    except (ValueError, IndexError):
        return 0

def sanitize_target(target: str) -> str:
    """Enhanced target validation with comprehensive checks"""
    if not target or not isinstance(target, str):
        logger.error("Invalid target: empty or not a string")
        raise ValueError("Target must be a non-empty string")
    
    target = target.strip().lower()
    
    # Remove protocol if present
    if target.startswith(('http://', 'https://')):
        target = urlparse(target).netloc or urlparse(target).path
    
    # Enhanced validation patterns
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    domain_pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
    
    # Check for localhost/private IPs
    private_ranges = [
        r'^127\.',
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[01])\.',
        r'^192\.168\.',
        r'^169\.254\.',
        r'^::1$',
        r'^fe80:',
        r'^fc00:',
        r'^fd00:'
    ]
    
    is_valid = re.match(ip_pattern, target) or re.match(domain_pattern, target)
    
    if not is_valid:
        logger.error(f"Invalid IP or domain format: {target}")
        raise ValueError("Invalid IP or domain format")
    
    # Warn about private/local addresses
    for pattern in private_ranges:
        if re.match(pattern, target):
            logger.warning(f"Target appears to be a private/local address: {target}")
            break
    
    return target

def sanitize_port(port: int) -> int:
    """Enhanced port validation with service detection"""
    if not isinstance(port, int) or not 1 <= port <= 65535:
        logger.error(f"Invalid port: {port}")
        raise ValueError("Port must be an integer between 1 and 65535")
    
    # Warn about uncommon ports
    common_web_ports = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]
    if port not in common_web_ports:
        logger.debug(f"Using uncommon web port: {port}")
    
    return port

def get_ssl_info(target: str, port: int) -> Dict[str, Any]:
    """Extract SSL certificate information"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                return {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'version': cert.get('version'),
                    'serial_number': cert.get('serialNumber'),
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter'),
                    'san': cert.get('subjectAltName', [])
                }
    except Exception as e:
        logger.debug(f"Failed to get SSL info for {target}:{port}: {e}")
        return {}

def advanced_fingerprint(content: str, headers: Dict[str, str], cms_profiles: Dict) -> Dict[str, float]:
    """Advanced CMS fingerprinting with confidence scoring"""
    scores = defaultdict(float)
    
    # Header-based detection
    header_indicators = {
        'WordPress': ['wp-', 'wordpress'],
        'Joomla': ['joomla', 'com_'],
        'Drupal': ['drupal', 'x-drupal'],
        'Magento': ['magento', 'x-magento']
    }
    
    for cms, indicators in header_indicators.items():
        for header, value in headers.items():
            for indicator in indicators:
                if indicator.lower() in f"{header} {value}".lower():
                    scores[cms] += 0.3
    
    # Content-based fingerprinting
    for cms, profile in cms_profiles.items():
        for pattern, description, confidence in profile.get('fingerprints', []):
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                scores[cms] += confidence * len(matches) * 0.1
    
    # Normalize scores
    max_score = max(scores.values()) if scores else 0
    if max_score > 0:
        scores = {cms: score/max_score for cms, score in scores.items()}
    
    return dict(scores)

def detect_technologies(content: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Detect web technologies using advanced pattern matching"""
    technologies = []
    
    # JavaScript frameworks and libraries
    js_patterns = {
        'jQuery': r'jquery[.-]([0-9.]+)',
        'React': r'react[.-]([0-9.]+)',
        'Angular': r'angular[.-]([0-9.]+)',
        'Vue.js': r'vue[.-]([0-9.]+)',
        'Bootstrap': r'bootstrap[.-]([0-9.]+)'
    }
    
    for tech, pattern in js_patterns.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            technologies.append({
                'name': tech,
                'version': matches[0] if matches else None,
                'type': 'JavaScript Framework/Library'
            })
    
    # Server technologies from headers
    server_header = headers.get('Server', '')
    if server_header:
        server_patterns = {
            'Apache': r'Apache/([0-9.]+)',
            'Nginx': r'nginx/([0-9.]+)',
            'IIS': r'Microsoft-IIS/([0-9.]+)',
            'PHP': r'PHP/([0-9.]+)'
        }
        
        for tech, pattern in server_patterns.items():
            match = re.search(pattern, server_header, re.IGNORECASE)
            if match:
                technologies.append({
                    'name': tech,
                    'version': match.group(1),
                    'type': 'Web Server/Runtime'
                })
    
    return technologies

def fetch_component(url: str, proxies: Optional[Dict], timeout: int = 10, headers: Dict = None) -> Optional[Dict]:
    """Enhanced component fetching with retry logic and advanced analysis"""
    max_retries = 3
    backoff_factor = 0.3
    
    session = requests.Session()
    session.headers.update(headers or {})
    
    for attempt in range(max_retries):
        try:
            response = session.get(
                url, 
                proxies=proxies, 
                timeout=timeout, 
                verify=False, 
                allow_redirects=True,
                stream=True
            )
            
            # Check content length
            content_length = response.headers.get('content-length')
            if content_length and int(content_length) > 10 * 1024 * 1024:  # 10MB limit
                logger.warning(f"Content too large for {url}: {content_length} bytes")
                return None
            
            # Read content with size limit
            content = ''
            size = 0
            for chunk in response.iter_content(chunk_size=8192, decode_unicode=True):
                if chunk:
                    content += chunk
                    size += len(chunk)
                    if size > 5 * 1024 * 1024:  # 5MB limit
                        break
            
            result = {
                'url': url,
                'status_code': response.status_code,
                'content': content,
                'headers': dict(response.headers),
                'encoding': response.encoding,
                'size': size,
                'response_time': response.elapsed.total_seconds(),
                'redirect_history': [r.url for r in response.history]
            }
            
            # Content analysis
            if response.status_code in [200, 403, 404]:
                result['content_type'] = response.headers.get('content-type', '').split(';')[0]
                result['last_modified'] = response.headers.get('last-modified')
                result['etag'] = response.headers.get('etag')
                
                # Hash for change detection
                result['content_hash'] = hashlib.sha256(content.encode()).hexdigest()
                
                # Extract metadata from content
                if 'html' in result['content_type']:
                    result['title'] = extract_title(content)
                    result['meta_tags'] = extract_meta_tags(content)
                elif 'json' in result['content_type']:
                    try:
                        result['json_data'] = json.loads(content)
                    except json.JSONDecodeError:
                        pass
            
            if response.status_code in [200, 403]:
                return result
            
            return None
            
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                sleep_time = backoff_factor * (2 ** attempt)
                logger.debug(f"Retry {attempt + 1} for {url} after {sleep_time}s: {e}")
                time.sleep(sleep_time)
            else:
                logger.debug(f"Failed to fetch {url} after {max_retries} attempts: {e}")
                return None
    
    return None

def extract_title(html_content: str) -> Optional[str]:
    """Extract title from HTML content"""
    title_match = re.search(r'<title[^>]*>([^<]*)</title>', html_content, re.IGNORECASE)
    return title_match.group(1).strip() if title_match else None

def extract_meta_tags(html_content: str) -> Dict[str, str]:
    """Extract meta tags from HTML content"""
    meta_tags = {}
    meta_pattern = r'<meta\s+(?:[^>]*?\s+)?(?:name|property)=["\']([^"\']*)["\'][^>]*?\s+content=["\']([^"\']*)["\'][^>]*?/?>'
    
    for match in re.finditer(meta_pattern, html_content, re.IGNORECASE):
        name, content = match.groups()
        meta_tags[name.lower()] = content
    
    return meta_tags

def detect_cms_version(content: str, headers: Dict[str, str], cms: str) -> Optional[str]:
    """Advanced CMS version detection"""
    if cms not in CMS_PROFILES:
        return None
    
    patterns = CMS_PROFILES[cms].get('version_patterns', [])
    
    # Check content for version patterns
    for pattern in patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            return matches[0]
    
    # Check headers
    for header, value in headers.items():
        for pattern in patterns:
            matches = re.findall(pattern, f"{header}: {value}", re.IGNORECASE)
            if matches:
                return matches[0]
    
    return None

def enumerate_plugins(base_url: str, cms: str, plugin_slugs: List[str], 
                     proxies: Optional[Dict], headers: Dict, stealth: bool) -> List[Dict]:
    """Advanced plugin enumeration with intelligent detection"""
    plugins = []
    
    if cms not in CMS_PROFILES:
        return plugins
    
    plugin_paths = CMS_PROFILES[cms]['plugin_paths']
    
    # Use ThreadPoolExecutor for concurrent requests
    max_workers = 5 if stealth else 20
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        
        for slug in plugin_slugs:
            for path_template in plugin_paths:
                path = path_template.format(slug=slug)
                url = urljoin(base_url, path)
                
                if stealth:
                    time.sleep(random.uniform(0.1, 0.5))
                
                future = executor.submit(fetch_component, url, proxies, 10, headers)
                futures[future] = {'slug': slug, 'path': path, 'url': url}
        
        for future in as_completed(futures):
            data = futures[future]
            result = future.result()
            
            if result and result['status_code'] in [200, 403]:
                plugin_info = {
                    'slug': data['slug'],
                    'url': data['url'],
                    'status_code': result['status_code'],
                    'size': result['size'],
                    'last_modified': result.get('last_modified'),
                    'response_time': result['response_time']
                }
                
                # Extract version information
                if result['status_code'] == 200:
                    version = extract_plugin_version(result['content'], cms, data['slug'])
                    if version:
                        plugin_info['version'] = version
                    
                    # Check for known vulnerabilities
                    vulns = check_plugin_vulnerabilities(data['slug'], version, cms)
                    if vulns:
                        plugin_info['vulnerabilities'] = vulns
                
                plugins.append(plugin_info)
    
    return plugins

def extract_plugin_version(content: str, cms: str, slug: str) -> Optional[str]:
    """Extract plugin version from content"""
    version_patterns = [
        r'Version:\s*([0-9.]+)',
        r'version["\']?\s*[:=]\s*["\']([0-9.]+)["\']',
        r'v([0-9.]+)',
        r'([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
    ]
    
    for pattern in version_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            return matches[0]
    
    return None

def check_plugin_vulnerabilities(plugin_slug: str, version: Optional[str], cms: str) -> List[Dict]:
    """Check for known plugin vulnerabilities"""
    vulnerabilities = []
    
    # This would typically query a vulnerability database
    # For now, return example vulnerabilities for common plugins
    vulnerable_plugins = {
        'WordPress': {
            'akismet': ['< 4.2.0'],
            'jetpack': ['< 11.0'],
            'yoast-seo': ['< 19.0']
        }
    }
    
    if cms in vulnerable_plugins and plugin_slug in vulnerable_plugins[cms]:
        vuln_versions = vulnerable_plugins[cms][plugin_slug]
        if version:
            for vuln_version in vuln_versions:
                if '<' in vuln_version:
                    max_version = vuln_version.replace('<', '').strip()
                    if compare_versions(version, max_version) < 0:
                        vulnerabilities.append({
                            'plugin': plugin_slug,
                            'version': version,
                            'vulnerability': f"Vulnerable version {version} < {max_version}",
                            'severity': 'Medium'
                        })
    
    return vulnerabilities

def enumerate_themes(base_url: str, cms: str, theme_slugs: List[str], 
                    proxies: Optional[Dict], headers: Dict, stealth: bool) -> List[Dict]:
    """Advanced theme enumeration"""
    themes = []
    
    if cms not in CMS_PROFILES:
        return themes
    
    theme_paths = CMS_PROFILES[cms]['theme_paths']
    max_workers = 3 if stealth else 10
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        
        for slug in theme_slugs:
            for path_template in theme_paths:
                path = path_template.format(slug=slug)
                url = urljoin(base_url, path)
                
                if stealth:
                    time.sleep(random.uniform(0.2, 0.8))
                
                future = executor.submit(fetch_component, url, proxies, 10, headers)
                futures[future] = {'slug': slug, 'path': path, 'url': url}
        
        for future in as_completed(futures):
            data = futures[future]
            result = future.result()
            
            if result and result['status_code'] in [200, 403]:
                theme_info = {
                    'slug': data['slug'],
                    'url': data['url'],
                    'status_code': result['status_code'],
                    'size': result['size'],
                    'last_modified': result.get('last_modified')
                }
                
                if result['status_code'] == 200:
                    version = extract_theme_version(result['content'], cms)
                    if version:
                        theme_info['version'] = version
                
                themes.append(theme_info)
    
    return themes

def extract_theme_version(content: str, cms: str) -> Optional[str]:
    """Extract theme version from content"""
    if cms == 'WordPress':
        # WordPress theme style.css header
        version_match = re.search(r'Version:\s*([0-9.]+)', content)
        if version_match:
            return version_match.group(1)
    
    return None

def enumerate_users(base_url: str, cms: str, proxies: Optional[Dict], headers: Dict) -> List[Dict]:
    """Advanced user enumeration with multiple techniques"""
    users = []
    
    if cms not in CMS_PROFILES:
        return users
    
    user_paths = CMS_PROFILES[cms]['user_paths']
    
    for path in user_paths:
        url = urljoin(base_url, path)
        result = fetch_component(url, proxies, 10, headers)
        
        if result and result['status_code'] == 200:
            extracted_users = extract_users_from_content(result['content'], cms, url)
            users.extend(extracted_users)
    
    # Remove duplicates
    unique_users = []
    seen_usernames = set()
    
    for user in users:
        username = user.get('username', '').lower()
        if username and username not in seen_usernames:
            seen_usernames.add(username)
            unique_users.append(user)
    
    return unique_users

def extract_users_from_content(content: str, cms: str, url: str) -> List[Dict]:
    """Extract users from various content types"""
    users = []
    
    # Try JSON first
    try:
        data = json.loads(content)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    username = item.get('slug') or item.get('name') or item.get('username')
                    if username:
                        users.append({
                            'username': username,
                            'display_name': item.get('name', ''),
                            'url': url,
                            'id': item.get('id'),
                            'roles': item.get('roles', [])
                        })
    except json.JSONDecodeError:
        pass
    
    # HTML parsing for user links
    if cms == 'WordPress':
        # Author archive links
        author_links = re.findall(r'/author/([^/"\s]+)', content)
        for username in author_links:
            users.append({
                'username': username,
                'url': url,
                'detection_method': 'author_archive'
            })
    
    return users

def scan_sensitive_files(base_url: str, cms: str, proxies: Optional[Dict], 
                        headers: Dict, stealth: bool) -> List[Dict]:
    """Scan for sensitive files and configurations"""
    sensitive_files = []
    
    if cms not in CMS_PROFILES:
        return sensitive_files
    
    file_categories = ['config_paths', 'backup_paths', 'sensitive_paths']
    
    for category in file_categories:
        paths = CMS_PROFILES[cms].get(category, [])
        
        for path in paths:
            url = urljoin(base_url, path)
            
            if stealth:
                time.sleep(random.uniform(0.3, 1.0))
            
            result = fetch_component(url, proxies, 10, headers)
            
            if result:
                file_info = {
                    'path': path,
                    'url': url,
                    'status_code': result['status_code'],
                    'category': category,
                    'size': result['size']
                }
                
                # Analyze content for sensitive information
                if result['status_code'] == 200:
                    sensitivity_score = analyze_content_sensitivity(result['content'], path)
                    file_info['sensitivity_score'] = sensitivity_score
                    
                    if sensitivity_score > 0.5:
                        file_info['risk_level'] = 'High'
                    elif sensitivity_score > 0.2:
                        file_info['risk_level'] = 'Medium'
                    else:
                        file_info['risk_level'] = 'Low'
                
                sensitive_files.append(file_info)
    
    return sensitive_files

def analyze_content_sensitivity(content: str, path: str) -> float:
    """Analyze content for sensitive information"""
    score = 0.0
    
    # Check for database credentials
    db_patterns = [
        r'DB_PASSWORD\s*=\s*["\']([^"\']+)["\']',
        r'database.*password\s*[=:]\s*["\']([^"\']+)["\']',
        r'mysql.*password\s*[=:]\s*["\']([^"\']+)["\']'
    ]
    
    for pattern in db_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            score += 0.4
    
    # Check for API keys
    api_patterns = [
        r'api[_-]?key\s*[=:]\s*["\']([^"\']+)["\']',
        r'secret[_-]?key\s*[=:]\s*["\']([^"\']+)["\']',
        r'access[_-]?token\s*[=:]\s*["\']([^"\']+)["\']'
    ]
    
    for pattern in api_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            score += 0.3
    
    # Check for file paths
    if re.search(r'/[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+', content):
        score += 0.1
    
    # Check for error messages
    error_patterns = [
        r'fatal error',
        r'stack trace',
        r'exception',
        r'warning:'
    ]
    
    for pattern in error_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            score += 0.2
    
    return min(score, 1.0)

def perform_advanced_security_checks(base_url: str, cms: str, proxies: Optional[Dict], 
                                   headers: Dict) -> List[Dict]:
    """Perform advanced security checks"""
    security_issues = []
    
    # Check for common security headers
    security_headers = [
        'X-Frame-Options',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'Referrer-Policy'
    ]
    
    result = fetch_component(base_url, proxies, 10, headers)
    if result:
        missing_headers = []
        for header in security_headers:
            if header not in result['headers']:
                missing_headers.append(header)
        
        if missing_headers:
            security_issues.append({
                'type': 'missing_security_headers',
                'severity': 'Medium',
                'description': f"Missing security headers: {', '.join(missing_headers)}",
                'headers': missing_headers
            })
    
    # Check for directory indexing
    common_dirs = ['/wp-content/', '/wp-includes/', '/uploads/', '/themes/', '/plugins/']
    
    for directory in common_dirs:
        if cms == 'WordPress' or directory in ['/uploads/', '/themes/', '/plugins/']:
            url = urljoin(base_url, directory)
            result = fetch_component(url, proxies, 10, headers)
            
            if result and result['status_code'] == 200:
                if 'index of' in result['content'].lower():
                    security_issues.append({
                        'type': 'directory_indexing',
                        'severity': 'Medium',
                        'description': f"Directory indexing enabled: {directory}",
                        'url': url
                    })
    
    return security_issues

def generate_wordlist(cms: str, base_plugins: List[str] = None) -> List[str]:
    """Generate intelligent wordlist based on CMS and context"""
    wordlist = []
    
    # Base common plugins/themes
    common_components = {
        'WordPress': [
            'akismet', 'jetpack', 'yoast-seo', 'wordfence', 'elementor',
            'woocommerce', 'contact-form-7', 'updraftplus', 'wpforms',
            'twentytwentyone', 'twentytwentytwo', 'twentytwentythree',
            'astra', 'oceanwp', 'generatepress', 'kadence'
        ],
        'Joomla': [
            'com_content', 'com_users', 'com_menus', 'com_modules',
            'beez3', 'protostar', 'cassiopeia', 'atum'
        ],
        'Drupal': [
            'views', 'ctools', 'token', 'pathauto', 'admin_menu',
            'bartik', 'seven', 'olivero', 'claro'
        ]
    }
    
    if cms in common_components:
        wordlist.extend(common_components[cms])
    
    # Add base plugins if provided
    if base_plugins:
        wordlist.extend(base_plugins)
    
    # Generate variations
    variations = []
    for word in wordlist:
        variations.extend([
            word,
            word.replace('-', '_'),
            word.replace('_', '-'),
            word.replace('-', ''),
            word.replace('_', '')
        ])
    
    return list(set(variations))

def cms_recon(target: str, ports: List[int], prior_findings: Dict[str, Any] = None, 
             stealth: bool = False, proxies: Optional[Dict[str, str]] = None, 
             cache_file: Optional[str] = None, plugin_list: Optional[str] = None) -> Dict[str, Any]:
    """Enhanced CMS reconnaissance with advanced capabilities"""
    try:
        target = sanitize_target(target)
        ports = [sanitize_port(p) for p in ports] if ports else [80, 443, 8080, 8443]
        prior_findings = prior_findings or {}
        
        logger.info(f"Starting enhanced CMS reconnaissance on {target} for ports {ports}")
        
        # Initialize cache
        cache_data = None
        if cache_file:
            cache_path = Path(cache_file).resolve()
            try:
                if cache_path.exists():
                    with open(cache_path, 'r', encoding='utf-8') as f:
                        cache_data = json.load(f)
                        if (cache_data.get('target') == target and 
                            sorted(cache_data.get('ports', [])) == sorted(ports) and
                            cache_data.get('timestamp', 0) > time.time() - 3600):  # 1 hour cache
                            logger.debug(f"Using cached CMS recon results from {cache_path}")
                            return cache_data['results']
            except (OSError, json.JSONDecodeError) as e:
                logger.warning(f"Failed to read CMS recon cache: {e}")
        
        results = {
            'target': target,
            'ports': [],
            'changes': {},
            'timestamp': datetime.now().isoformat(),
            'scan_duration': 0,
            'total_requests': 0,
            'fingerprinting_confidence': {}
        }
        
        start_time = time.time()
        
        # Enhanced user agent rotation
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0'
        ]
        
        headers = {
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # Load plugin list
        plugin_slugs = []
        if plugin_list:
            try:
                with open(plugin_list, 'r', encoding='utf-8') as f:
                    plugin_slugs = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                logger.info(f"Loaded {len(plugin_slugs)} plugins from {plugin_list}")
            except OSError as e:
                logger.error(f"Failed to load plugin list {plugin_list}: {e}")
        
        # CMS detection from prior findings
        detected_cms = {}
        for port_data in prior_findings.get('http_fingerprint', {}).get('ports', []):
            if port_data['port'] in ports:
                port = port_data['port']
                protocol = 'https' if port in [443, 8443] else 'http'
                base_url = f"{protocol}://{target}:{port}" if port not in [80, 443] else f"{protocol}://{target}"
                
                # Get initial page for fingerprinting
                initial_result = fetch_component(base_url, proxies, 10, headers)
                if initial_result:
                    cms_scores = advanced_fingerprint(
                        initial_result['content'], 
                        initial_result['headers'], 
                        CMS_PROFILES
                    )
                    
                    if cms_scores:
                        best_cms = max(cms_scores.items(), key=lambda x: x[1])
                        if best_cms[1] > 0.3:  # Minimum confidence threshold
                            detected_cms[port] = {
                                'cms': best_cms[0],
                                'confidence': best_cms[1],
                                'all_scores': cms_scores
                            }
                            results['fingerprinting_confidence'][port] = cms_scores
        
        request_count = 0
        
        for port in ports:
            if stealth:
                time.sleep(random.uniform(1.0, 3.0))
            
            port_start_time = time.time()
            protocol = 'https' if port in [443, 8443] else 'http'
            base_url = f"{protocol}://{target}:{port}" if port not in [80, 443] else f"{protocol}://{target}"
            
            port_results = {
                'port': port,
                'protocol': protocol,
                'base_url': base_url,
                'cms': None,
                'cms_version': None,
                'cms_confidence': 0.0,
                'components': {
                    'plugins': [],
                    'themes': [],
                    'users': []
                },
                'vulnerabilities': [],
                'security_issues': [],
                'sensitive_files': [],
                'technologies': [],
                'ssl_info': {},
                'response_analysis': {},
                'scan_stats': {
                    'requests_made': 0,
                    'scan_duration': 0,
                    'errors': 0
                }
            }
            
            # SSL information for HTTPS ports
            if protocol == 'https':
                port_results['ssl_info'] = get_ssl_info(target, port)
            
            # Check if CMS was detected for this port
            if port in detected_cms:
                cms_info = detected_cms[port]
                port_results['cms'] = cms_info['cms']
                port_results['cms_confidence'] = cms_info['confidence']
                
                cms = cms_info['cms']
                logger.info(f"CMS detected for {target}:{port}: {cms} (confidence: {cms_info['confidence']:.2f})")
                
                # Get initial page for version detection
                initial_result = fetch_component(base_url, proxies, 10, headers)
                if initial_result:
                    request_count += 1
                    port_results['scan_stats']['requests_made'] += 1
                    
                    # Detect CMS version
                    version = detect_cms_version(initial_result['content'], initial_result['headers'], cms)
                    if version:
                        port_results['cms_version'] = version
                        logger.info(f"CMS version detected: {version}")
                    
                    # Detect other technologies
                    port_results['technologies'] = detect_technologies(
                        initial_result['content'], 
                        initial_result['headers']
                    )
                    
                    # Response analysis
                    port_results['response_analysis'] = {
                        'response_time': initial_result['response_time'],
                        'content_length': initial_result['size'],
                        'server_header': initial_result['headers'].get('Server', ''),
                        'powered_by': initial_result['headers'].get('X-Powered-By', ''),
                        'title': initial_result.get('title', ''),
                        'meta_generator': initial_result.get('meta_tags', {}).get('generator', '')
                    }
                
                # Generate comprehensive plugin list
                if not plugin_slugs:
                    plugin_slugs = generate_wordlist(cms)
                
                # Plugin enumeration
                logger.info(f"Enumerating plugins for {cms} on {target}:{port}")
                plugins = enumerate_plugins(base_url, cms, plugin_slugs, proxies, headers, stealth)
                port_results['components']['plugins'] = plugins
                request_count += len(plugins)
                port_results['scan_stats']['requests_made'] += len(plugins)
                
                # Theme enumeration
                theme_slugs = generate_wordlist(cms)
                themes = enumerate_themes(base_url, cms, theme_slugs, proxies, headers, stealth)
                port_results['components']['themes'] = themes
                request_count += len(themes)
                port_results['scan_stats']['requests_made'] += len(themes)
                
                # User enumeration
                users = enumerate_users(base_url, cms, proxies, headers)
                port_results['components']['users'] = users
                request_count += 5  # Approximate requests for user enumeration
                port_results['scan_stats']['requests_made'] += 5
                
                # Sensitive file scanning
                sensitive_files = scan_sensitive_files(base_url, cms, proxies, headers, stealth)
                port_results['sensitive_files'] = sensitive_files
                request_count += len(sensitive_files)
                port_results['scan_stats']['requests_made'] += len(sensitive_files)
                
                # Advanced security checks
                security_issues = perform_advanced_security_checks(base_url, cms, proxies, headers)
                port_results['security_issues'] = security_issues
                
                # Vulnerability checks based on CMS version and components
                if port_results['cms_version']:
                    cms_config = CMS_PROFILES[cms]
                    for check, is_vuln_func, desc, risk, exploit in cms_config['vuln_checks']:
                        if is_vuln_func(port_results['cms_version']):
                            port_results['vulnerabilities'].append({
                                'type': 'cms_version',
                                'description': desc,
                                'version': port_results['cms_version'],
                                'risk': risk,
                                'exploit': exploit,
                                'cvss_score': 7.5 if risk == 'High' else 5.0 if risk == 'Medium' else 2.5
                            })
                
                # Check plugin vulnerabilities
                for plugin in port_results['components']['plugins']:
                    if 'vulnerabilities' in plugin:
                        for vuln in plugin['vulnerabilities']:
                            vuln['component_type'] = 'plugin'
                            port_results['vulnerabilities'].append(vuln)
            
            else:
                logger.debug(f"No CMS detected for {target}:{port}")
                port_results['cms'] = None
                
                # Still perform basic checks
                initial_result = fetch_component(base_url, proxies, 10, headers)
                if initial_result:
                    request_count += 1
                    port_results['scan_stats']['requests_made'] += 1
                    port_results['technologies'] = detect_technologies(
                        initial_result['content'], 
                        initial_result['headers']
                    )
            
            # Analysis and risk assessment
            port_results['analysis'] = analyze_cms_findings(
                port_results['components'],
                port_results['vulnerabilities'],
                port_results['security_issues'],
                port_results['sensitive_files']
            )
            
            # Scan statistics
            port_results['scan_stats']['scan_duration'] = time.time() - port_start_time
            
            results['ports'].append(port_results)
            logger.info(f"CMS recon completed for port {port}: {len(port_results['vulnerabilities'])} vulnerabilities, {len(port_results['components']['plugins'])} plugins, {len(port_results['components']['users'])} users")
        
        # Overall scan statistics
        results['scan_duration'] = time.time() - start_time
        results['total_requests'] = request_count
        
        # Change detection
        if cache_data and 'results' in cache_data:
            results['changes'] = detect_changes(cache_data['results'], results)
        
        # Cache results
        if cache_file:
            try:
                cache_path.parent.mkdir(exist_ok=True)
                with open(cache_path, 'w', encoding='utf-8') as f:
                    json.dump({
                        'target': target,
                        'ports': ports,
                        'results': results,
                        'timestamp': time.time()
                    }, f, indent=2)
                logger.debug(f"Cached CMS recon results to {cache_path}")
            except OSError as e:
                logger.warning(f"Failed to write CMS recon cache: {e}")
        
        logger.info(f"Enhanced CMS reconnaissance completed for {target} in {results['scan_duration']:.2f}s with {request_count} requests")
        return results
    
    except ValueError as e:
        raise
    except Exception as e:
        logger.error(f"CMS reconnaissance failed for {target}: {e}")
        raise RuntimeError(f"CMS reconnaissance failed: {e}")

def detect_changes(old_results: Dict, new_results: Dict) -> Dict[str, Any]:
    """Detect changes between scan results"""
    changes = {
        'new_vulnerabilities': [],
        'fixed_vulnerabilities': [],
        'new_plugins': [],
        'removed_plugins': [],
        'version_changes': [],
        'new_users': [],
        'removed_users': []
    }
    
    # Compare ports
    old_ports = {p['port']: p for p in old_results.get('ports', [])}
    new_ports = {p['port']: p for p in new_results.get('ports', [])}
    
    for port in new_ports:
        if port in old_ports:
            old_port = old_ports[port]
            new_port = new_ports[port]
            
            # Version changes
            if old_port.get('cms_version') != new_port.get('cms_version'):
                changes['version_changes'].append({
                    'port': port,
                    'old_version': old_port.get('cms_version'),
                    'new_version': new_port.get('cms_version')
                })
            
            # Vulnerability changes
            old_vulns = {v.get('description', ''): v for v in old_port.get('vulnerabilities', [])}
            new_vulns = {v.get('description', ''): v for v in new_port.get('vulnerabilities', [])}
            
            for vuln_desc in new_vulns:
                if vuln_desc not in old_vulns:
                    changes['new_vulnerabilities'].append(new_vulns[vuln_desc])
            
            for vuln_desc in old_vulns:
                if vuln_desc not in new_vulns:
                    changes['fixed_vulnerabilities'].append(old_vulns[vuln_desc])
    
    return changes

def analyze_cms_findings(components: Dict, vulnerabilities: List, security_issues: List = None, 
                        sensitive_files: List = None) -> Dict[str, Any]:
    """Enhanced analysis of CMS findings with comprehensive risk assessment"""
    if security_issues is None:
        security_issues = []
    if sensitive_files is None:
        sensitive_files = []
    
    # Calculate detailed risk score
    risk_score = 0
    risk_factors = []
    recommendations = []
    attack_vectors = []
    
    # Vulnerability scoring with advanced CVSS calculation
    vuln_categories = {
        'rce': {'weight': 30, 'priority': 'Critical'},
        'sqli': {'weight': 25, 'priority': 'Critical'},
        'xss': {'weight': 15, 'priority': 'High'},
        'csrf': {'weight': 10, 'priority': 'Medium'},
        'info_disclosure': {'weight': 8, 'priority': 'Medium'},
        'auth_bypass': {'weight': 20, 'priority': 'Critical'},
        'privilege_escalation': {'weight': 22, 'priority': 'Critical'},
        'file_upload': {'weight': 18, 'priority': 'High'},
        'path_traversal': {'weight': 12, 'priority': 'High'},
        'xxe': {'weight': 16, 'priority': 'High'},
        'ssrf': {'weight': 14, 'priority': 'High'},
        'deserialization': {'weight': 24, 'priority': 'Critical'}
    }
    
    for vuln in vulnerabilities:
        cvss_score = vuln.get('cvss_score', 0)
        vuln_type = vuln.get('type', 'unknown').lower()
        description = vuln.get('description', 'Unknown vulnerability')
        
        # Categorize vulnerability type
        category_weight = 10  # default
        for category, info in vuln_categories.items():
            if category in description.lower() or category in vuln_type:
                category_weight = info['weight']
                break
        
        if cvss_score >= 9.0:
            risk_score += category_weight + 20
            risk_factors.append(f"Critical vulnerability: {description} (CVSS: {cvss_score})")
            attack_vectors.append(f"Critical exploit path via {description}")
            recommendations.append(f"URGENT: Patch {description} immediately")
        elif cvss_score >= 7.0:
            risk_score += category_weight + 15
            risk_factors.append(f"High vulnerability: {description} (CVSS: {cvss_score})")
            attack_vectors.append(f"High-risk exploit via {description}")
            recommendations.append(f"HIGH PRIORITY: Address {description} within 24-48 hours")
        elif cvss_score >= 4.0:
            risk_score += category_weight + 10
            risk_factors.append(f"Medium vulnerability: {description} (CVSS: {cvss_score})")
            attack_vectors.append(f"Potential exploit via {description}")
            recommendations.append(f"MEDIUM PRIORITY: Schedule fix for {description}")
        else:
            risk_score += category_weight + 5
            risk_factors.append(f"Low vulnerability: {description} (CVSS: {cvss_score})")
            recommendations.append(f"LOW PRIORITY: Consider addressing {description}")
    
    # Advanced user enumeration analysis
    user_count = len(components.get('users', []))
    admin_users = []
    weak_usernames = []
    
    for user in components.get('users', []):
        username = user.get('username', '').lower()
        roles = user.get('roles', [])
        
        # Identify admin users
        if any(role in ['administrator', 'admin', 'super_admin', 'root'] for role in roles):
            admin_users.append(username)
        
        # Identify weak usernames
        weak_patterns = ['admin', 'administrator', 'root', 'test', 'demo', 'user', 'guest']
        if any(pattern in username for pattern in weak_patterns):
            weak_usernames.append(username)
    
    if user_count > 0:
        user_risk = min(user_count * 3, 25)  # Cap at 25
        risk_score += user_risk
        risk_factors.append(f"User enumeration possible ({user_count} users found)")
        attack_vectors.append(f"Brute force attack against {user_count} enumerated users")
        recommendations.append("Disable user enumeration or implement rate limiting")
        
        if admin_users:
            risk_score += len(admin_users) * 5
            risk_factors.append(f"Admin users exposed: {', '.join(admin_users)}")
            attack_vectors.append(f"Targeted attacks against admin users: {', '.join(admin_users)}")
            recommendations.append("Rename default admin accounts and use strong passwords")
        
        if weak_usernames:
            risk_score += len(weak_usernames) * 8
            risk_factors.append(f"Weak usernames detected: {', '.join(weak_usernames)}")
            attack_vectors.append(f"Dictionary attacks against weak usernames")
            recommendations.append("Change default/weak usernames to non-predictable values")
    
    # Advanced sensitive file analysis with pattern matching
    sensitive_patterns = {
        'config': {
            'patterns': ['config', 'settings', '.env', 'database'],
            'risk_multiplier': 3.0,
            'description': 'Configuration files containing credentials'
        },
        'backup': {
            'patterns': ['backup', '.bak', '.old', '.sql', '.dump'],
            'risk_multiplier': 2.5,
            'description': 'Backup files with sensitive data'
        },
        'log': {
            'patterns': ['log', 'error', 'debug', 'access'],
            'risk_multiplier': 1.5,
            'description': 'Log files with system information'
        },
        'source': {
            'patterns': ['.php', '.asp', '.jsp', '.py', '.rb'],
            'risk_multiplier': 2.0,
            'description': 'Source code files'
        },
        'admin': {
            'patterns': ['admin', 'administrator', 'management'],
            'risk_multiplier': 2.8,
            'description': 'Administrative interfaces'
        }
    }
    
    exposed_files_by_category = defaultdict(list)
    
    for file_info in sensitive_files:
        if file_info.get('status_code') == 200:
            path = file_info.get('path', '').lower()
            sensitivity = file_info.get('sensitivity_score', 0)
            size = file_info.get('size', 0)
            
            # Categorize file
            file_category = 'unknown'
            risk_multiplier = 1.0
            
            for category, info in sensitive_patterns.items():
                if any(pattern in path for pattern in info['patterns']):
                    file_category = category
                    risk_multiplier = info['risk_multiplier']
                    exposed_files_by_category[category].append(path)
                    break
            
            # Calculate file-specific risk
            base_risk = 5
            if sensitivity > 0.8:
                base_risk = 30
            elif sensitivity > 0.6:
                base_risk = 20
            elif sensitivity > 0.4:
                base_risk = 15
            elif sensitivity > 0.2:
                base_risk = 10
            
            # Size-based risk adjustment
            if size > 1024 * 1024:  # > 1MB
                base_risk *= 1.2
            elif size > 10 * 1024:  # > 10KB
                base_risk *= 1.1
            
            file_risk = int(base_risk * risk_multiplier)
            risk_score += file_risk
            
            if sensitivity > 0.7:
                risk_factors.append(f"Highly sensitive file exposed: {path} (size: {size} bytes)")
                attack_vectors.append(f"Direct access to sensitive data via {path}")
                recommendations.append(f"CRITICAL: Secure or remove {path} immediately")
            elif sensitivity > 0.4:
                risk_factors.append(f"Sensitive file exposed: {path}")
                attack_vectors.append(f"Information disclosure via {path}")
                recommendations.append(f"Secure access to {path}")
            else:
                risk_factors.append(f"File accessible: {path}")
                recommendations.append(f"Review access permissions for {path}")
    
    # Advanced security issues analysis
    security_categories = {
        'missing_security_headers': {
            'base_risk': 15,
            'description': 'Missing security headers increase attack surface'
        },
        'directory_indexing': {
            'base_risk': 12,
            'description': 'Directory indexing exposes file structure'
        },
        'ssl_issues': {
            'base_risk': 20,
            'description': 'SSL/TLS configuration problems'
        },
        'cors_misconfiguration': {
            'base_risk': 18,
            'description': 'CORS policy allows unauthorized access'
        },
        'clickjacking': {
            'base_risk': 10,
            'description': 'Clickjacking protection missing'
        },
        'csp_issues': {
            'base_risk': 14,
            'description': 'Content Security Policy weaknesses'
        }
    }
    
    for issue in security_issues:
        issue_type = issue.get('type', 'unknown')
        severity = issue.get('severity', 'Low')
        description = issue.get('description', 'Unknown security issue')
        
        base_risk = security_categories.get(issue_type, {}).get('base_risk', 5)
        
        if severity == 'Critical':
            issue_risk = base_risk * 2
        elif severity == 'High':
            issue_risk = int(base_risk * 1.5)
        elif severity == 'Medium':
            issue_risk = base_risk
        else:
            issue_risk = int(base_risk * 0.5)
        
        risk_score += issue_risk
        risk_factors.append(f"{severity} security issue: {description}")
        
        if issue_type == 'missing_security_headers':
            attack_vectors.append("XSS, clickjacking, and MITM attacks due to missing headers")
            recommendations.append("Implement comprehensive security headers")
        elif issue_type == 'directory_indexing':
            attack_vectors.append("Information disclosure via directory browsing")
            recommendations.append("Disable directory indexing in web server configuration")
    
    # Component analysis (plugins, themes, modules)
    plugin_count = len(components.get('plugins', []))
    theme_count = len(components.get('themes', []))
    outdated_components = []
    vulnerable_components = []
    
    # Analyze plugins
    for plugin in components.get('plugins', []):
        slug = plugin.get('slug', '')
        version = plugin.get('version', 'unknown')
        vulns = plugin.get('vulnerabilities', [])
        
        if vulns:
            vulnerable_components.append(f"Plugin: {slug} v{version}")
            for vuln in vulns:
                risk_score += 12
                risk_factors.append(f"Vulnerable plugin: {slug} - {vuln.get('vulnerability', 'Unknown')}")
                attack_vectors.append(f"Plugin exploitation via {slug}")
                recommendations.append(f"Update or remove vulnerable plugin: {slug}")
        
        # Check for outdated versions (simplified check)
        if version != 'unknown' and '.' in version:
            try:
                major_version = int(version.split('.')[0])
                if major_version < 2:  # Simplified outdated check
                    outdated_components.append(f"Plugin: {slug}")
                    risk_score += 5
            except (ValueError, IndexError):
                pass
    
    # Analyze themes
    for theme in components.get('themes', []):
        slug = theme.get('slug', '')
        version = theme.get('version', 'unknown')
        
        if version != 'unknown' and '.' in version:
            try:
                major_version = int(version.split('.')[0])
                if major_version < 2:  # Simplified outdated check
                    outdated_components.append(f"Theme: {slug}")
                    risk_score += 3
            except (ValueError, IndexError):
                pass
    
    # Calculate overall risk level
    if risk_score >= 100:
        risk_level = "Critical"
        risk_color = "red"
    elif risk_score >= 70:
        risk_level = "High"
        risk_color = "orange"
    elif risk_score >= 40:
        risk_level = "Medium"
        risk_color = "yellow"
    elif risk_score >= 15:
        risk_level = "Low"
        risk_color = "green"
    else:
        risk_level = "Minimal"
        risk_color = "blue"
    
    # Advanced attack scenario modeling
    attack_scenarios = []
    
    # Scenario 1: Admin account compromise
    if admin_users and vulnerabilities:
        attack_scenarios.append({
            'name': 'Administrative Account Compromise',
            'likelihood': 'High' if weak_usernames else 'Medium',
            'impact': 'Critical',
            'steps': [
                f"1. Enumerate admin users: {', '.join(admin_users[:3])}",
                "2. Exploit authentication vulnerabilities or brute force",
                "3. Gain administrative access to CMS",
                "4. Install malicious plugins/themes or modify content",
                "5. Establish persistence and lateral movement"
            ],
            'mitigations': [
                "Implement strong password policies",
                "Enable two-factor authentication",
                "Use non-default admin usernames",
                "Implement account lockout policies",
                "Monitor admin login attempts"
            ]
        })
    
    # Scenario 2: Plugin exploitation chain
    if vulnerable_components:
        attack_scenarios.append({
            'name': 'Plugin Exploitation Chain',
            'likelihood': 'High',
            'impact': 'High',
            'steps': [
                f"1. Identify vulnerable plugins: {', '.join(vulnerable_components[:2])}",
                "2. Exploit plugin vulnerabilities for code execution",
                "3. Upload malicious files or create backdoors",
                "4. Escalate privileges within the application",
                "5. Access sensitive data or deface website"
            ],
            'mitigations': [
                "Keep all plugins updated to latest versions",
                "Remove unused plugins",
                "Use security scanners to identify vulnerabilities",
                "Implement web application firewall (WAF)",
                "Regular security audits of installed components"
            ]
        })
    
    # Scenario 3: Information disclosure exploitation
    if exposed_files_by_category:
        attack_scenarios.append({
            'name': 'Sensitive Information Disclosure',
            'likelihood': 'Medium',
            'impact': 'Medium',
            'steps': [
                "1. Discover exposed sensitive files through enumeration",
                "2. Extract database credentials or API keys",
                "3. Use credentials for database access or API abuse",
                "4. Escalate access or pivot to other systems",
                "5. Data exfiltration or service disruption"
            ],
            'mitigations': [
                "Secure file permissions and access controls",
                "Move sensitive files outside web root",
                "Implement proper .htaccess rules",
                "Regular cleanup of temporary and backup files",
                "Use environment variables for sensitive configuration"
            ]
        })
    
    # Generate compliance and security framework mappings
    compliance_mapping = {
        'OWASP_Top_10': [],
        'NIST_CSF': [],
        'ISO_27001': [],
        'GDPR': []
    }
    
    # Map findings to OWASP Top 10
    owasp_mappings = {
        'injection': 'A03:2021 – Injection',
        'broken_auth': 'A07:2021 – Identification and Authentication Failures',
        'sensitive_data': 'A02:2021 – Cryptographic Failures',
        'xxe': 'A05:2021 – Security Misconfiguration',
        'broken_access': 'A01:2021 – Broken Access Control',
        'security_misconfig': 'A05:2021 – Security Misconfiguration',
        'xss': 'A03:2021 – Injection',
        'insecure_deser': 'A08:2021 – Software and Data Integrity Failures',
        'known_vulns': 'A06:2021 – Vulnerable and Outdated Components',
        'insufficient_logging': 'A09:2021 – Security Logging and Monitoring Failures'
    }
    
    for vuln in vulnerabilities:
        vuln_type = vuln.get('type', '').lower()
        for owasp_key, owasp_item in owasp_mappings.items():
            if owasp_key in vuln_type or owasp_key in vuln.get('description', '').lower():
                if owasp_item not in compliance_mapping['OWASP_Top_10']:
                    compliance_mapping['OWASP_Top_10'].append(owasp_item)
    
    # Advanced metrics and statistics
    metrics = {
        'total_components': plugin_count + theme_count,
        'vulnerable_components': len(vulnerable_components),
        'vulnerability_density': len(vulnerabilities) / max(plugin_count + theme_count, 1),
        'security_score': max(0, 100 - risk_score),
        'remediation_priority': {
            'critical': len([v for v in vulnerabilities if v.get('cvss_score', 0) >= 9.0]),
            'high': len([v for v in vulnerabilities if 7.0 <= v.get('cvss_score', 0) < 9.0]),
            'medium': len([v for v in vulnerabilities if 4.0 <= v.get('cvss_score', 0) < 7.0]),
            'low': len([v for v in vulnerabilities if v.get('cvss_score', 0) < 4.0])
        },
        'exposed_surface': {
            'files': len([f for f in sensitive_files if f.get('status_code') == 200]),
            'users': user_count,
            'admin_users': len(admin_users),
            'plugins': plugin_count,
            'themes': theme_count
        }
    }
    
    # Time-based analysis and trends
    current_time = datetime.now()
    analysis_metadata = {
        'analysis_timestamp': current_time.isoformat(),
        'analysis_version': '2.0',
        'risk_calculation_method': 'advanced_weighted_scoring',
        'confidence_level': calculate_confidence_level(components, vulnerabilities, security_issues),
        'data_freshness': 'current',
        'next_recommended_scan': (current_time + timedelta(days=7)).isoformat()
    }
    
    return {
        'risk_assessment': {
            'overall_risk_score': min(risk_score, 200),  # Cap at 200
            'risk_level': risk_level,
            'risk_color': risk_color,
            'risk_factors': risk_factors[:20],  # Limit to top 20
            'confidence_score': analysis_metadata['confidence_level']
        },
        'attack_surface': {
            'total_attack_vectors': len(attack_vectors),
            'attack_vectors': attack_vectors[:15],  # Top 15 attack vectors
            'attack_scenarios': attack_scenarios,
            'exploitation_difficulty': calculate_exploitation_difficulty(vulnerabilities, components)
        },
        'recommendations': {
            'immediate_actions': [r for r in recommendations if 'URGENT' in r or 'CRITICAL' in r],
            'short_term_actions': [r for r in recommendations if 'HIGH PRIORITY' in r],
            'long_term_actions': [r for r in recommendations if 'MEDIUM' in r or 'LOW' in r],
            'all_recommendations': recommendations[:25]  # Top 25 recommendations
        },
        'component_analysis': {
            'total_plugins': plugin_count,
            'total_themes': theme_count,
            'vulnerable_components': len(vulnerable_components),
            'outdated_components': len(outdated_components),
            'component_health_score': calculate_component_health(components),
            'update_recommendations': generate_update_recommendations(components)
        },
        'security_posture': {
            'security_issues_count': len(security_issues),
            'exposed_files_count': len([f for f in sensitive_files if f.get('status_code') == 200]),
            'user_exposure_risk': calculate_user_exposure_risk(components.get('users', [])),
            'hardening_score': calculate_hardening_score(security_issues, sensitive_files)
        },
        'compliance_status': compliance_mapping,
        'metrics': metrics,
        'metadata': analysis_metadata,
        'exposed_files_summary': {
            'by_category': dict(exposed_files_by_category),
            'high_risk_files': [f for f in sensitive_files if f.get('sensitivity_score', 0) > 0.7]
        }
    }

def calculate_confidence_level(components: Dict, vulnerabilities: List, security_issues: List) -> float:
    """Calculate confidence level of the analysis based on data completeness"""
    confidence_factors = []
    
    # Component discovery confidence
    plugin_count = len(components.get('plugins', []))
    theme_count = len(components.get('themes', []))
    user_count = len(components.get('users', []))
    
    if plugin_count > 0:
        confidence_factors.append(0.3)
    if theme_count > 0:
        confidence_factors.append(0.2)
    if user_count > 0:
        confidence_factors.append(0.15)
    
    # Version detection confidence
    versioned_components = sum([
        1 for p in components.get('plugins', []) if p.get('version')
    ] + [
        1 for t in components.get('themes', []) if t.get('version')
    ])
    
    if versioned_components > 0:
        confidence_factors.append(min(0.2, versioned_components * 0.05))
    
    # Vulnerability detection confidence
    if vulnerabilities:
        confidence_factors.append(min(0.15, len(vulnerabilities) * 0.02))
    
    return min(sum(confidence_factors), 1.0)

def calculate_exploitation_difficulty(vulnerabilities: List, components: Dict) -> str:
    """Calculate overall exploitation difficulty"""
    if not vulnerabilities:
        return "N/A"
    
    difficulty_scores = []
    
    for vuln in vulnerabilities:
        cvss_score = vuln.get('cvss_score', 0)
        exploit_available = vuln.get('exploit_available', False)
        
        if exploit_available and cvss_score >= 9.0:
            difficulty_scores.append(1)  # Very Easy
        elif exploit_available and cvss_score >= 7.0:
            difficulty_scores.append(2)  # Easy
        elif cvss_score >= 7.0:
            difficulty_scores.append(3)  # Medium
        elif cvss_score >= 4.0:
            difficulty_scores.append(4)  # Hard
        else:
            difficulty_scores.append(5)  # Very Hard
    
    avg_difficulty = sum(difficulty_scores) / len(difficulty_scores)
    
    if avg_difficulty <= 1.5:
        return "Very Easy"
    elif avg_difficulty <= 2.5:
        return "Easy"
    elif avg_difficulty <= 3.5:
        return "Medium"
    elif avg_difficulty <= 4.5:
        return "Hard"
    else:
        return "Very Hard"

def calculate_component_health(components: Dict) -> float:
    """Calculate overall component health score"""
    total_components = len(components.get('plugins', [])) + len(components.get('themes', []))
    
    if total_components == 0:
        return 1.0
    
    # Count components with versions (indicates active maintenance)
    versioned_components = sum([
        1 for p in components.get('plugins', []) if p.get('version')
    ] + [
        1 for t in components.get('themes', []) if t.get('version')
    ])
    
    # Count vulnerable components
    vulnerable_components = sum([
        1 for p in components.get('plugins', []) if p.get('vulnerabilities')
    ])
    
    # Calculate health score
    version_score = versioned_components / total_components
    vulnerability_penalty = vulnerable_components / total_components
    
    health_score = max(0, version_score - vulnerability_penalty)
    return health_score

def generate_update_recommendations(components: Dict) -> List[Dict]:
    """Generate specific update recommendations for components"""
    recommendations = []
    
    for plugin in components.get('plugins', []):
        if plugin.get('vulnerabilities'):
            recommendations.append({
                'component': plugin.get('slug'),
                'type': 'plugin',
                'current_version': plugin.get('version', 'unknown'),
                'priority': 'High',
                'reason': 'Security vulnerabilities detected',
                'action': 'Update immediately or remove if unused'
            })
    
    for theme in components.get('themes', []):
        if not theme.get('version'):
            recommendations.append({
                'component': theme.get('slug'),
                'type': 'theme',
                'current_version': 'unknown',
                'priority': 'Medium',
                'reason': 'Version unknown - potentially outdated',
                'action': 'Check for updates and verify current version'
            })
    
    return recommendations

def calculate_user_exposure_risk(users: List) -> Dict[str, Any]:
    """Calculate user exposure risk metrics"""
    if not users:
        return {'risk_level': 'None', 'exposed_users': 0, 'risk_factors': []}
    
    risk_factors = []
    exposed_count = len(users)
    admin_count = sum(1 for u in users if 'admin' in u.get('roles', []))
    
    if exposed_count > 10:
        risk_factors.append("Large number of users exposed")
    if admin_count > 0:
        risk_factors.append(f"{admin_count} admin users exposed")
    
    # Detect common/weak usernames
    weak_usernames = [
        u.get('username', '') for u in users 
        if any(weak in u.get('username', '').lower() 
               for weak in ['admin', 'administrator', 'root', 'test', 'demo'])
    ]
    
    if weak_usernames:
        risk_factors.append(f"Weak usernames detected: {', '.join(weak_usernames[:3])}")
    
    # Calculate risk level
    risk_score = exposed_count + (admin_count * 3) + len(weak_usernames)
    
    if risk_score >= 15:
        risk_level = "High"
    elif risk_score >= 8:
        risk_level = "Medium"
    elif risk_score >= 3:
        risk_level = "Low"
    else:
        risk_level = "Minimal"
    
    return {
        'risk_level': risk_level,
        'exposed_users': exposed_count,
        'admin_users': admin_count,
        'weak_usernames': len(weak_usernames),
        'risk_factors': risk_factors
    }

def calculate_hardening_score(security_issues: List, sensitive_files: List) -> float:
    """Calculate security hardening score (0-100)"""
    base_score = 100
    
    # Deduct points for security issues
    for issue in security_issues:
        severity = issue.get('severity', 'Low')
        if severity == 'Critical':
            base_score -= 25
        elif severity == 'High':
            base_score -= 15
        elif severity == 'Medium':
            base_score -= 10
        else:
            base_score -= 5
    
    # Deduct points for exposed sensitive files
    for file_info in sensitive_files:
        if file_info.get('status_code') == 200:
            sensitivity = file_info.get('sensitivity_score', 0)
            base_score -= int(sensitivity * 15)
    
    return max(0, base_score)
    
def generate_executive_summary(analysis_results: Dict) -> Dict[str, Any]:
    """Generate executive summary for management reporting with advanced analytics"""
    risk_assessment = analysis_results.get('risk_assessment', {})
    metrics = analysis_results.get('metrics', {})
    
    # Key findings summary
    key_findings = []
    
    if risk_assessment.get('risk_level') in ['Critical', 'High']:
        key_findings.append(f"HIGH RISK: Overall security risk level is {risk_assessment.get('risk_level')}")
    
    critical_vulns = metrics.get('remediation_priority', {}).get('critical', 0)
    if critical_vulns > 0:
        key_findings.append(f"CRITICAL: {critical_vulns} critical vulnerabilities require immediate attention")
    
    vulnerable_components = metrics.get('vulnerable_components', 0)
    if vulnerable_components > 0:
        key_findings.append(f"SECURITY RISK: {vulnerable_components} vulnerable components detected")
    
    exposed_files = metrics.get('exposed_surface', {}).get('files', 0)
    if exposed_files > 0:
        key_findings.append(f"EXPOSURE: {exposed_files} sensitive files publicly accessible")
    
    user_count = metrics.get('exposed_surface', {}).get('users', 0)
    if user_count > 5:
        key_findings.append(f"USER RISK: {user_count} users enumerated, potential brute-force target")
    
    # Business impact assessment with detailed metrics
    business_impact = {
        'data_breach_risk': 'High' if risk_assessment.get('overall_risk_score', 0) > 100 else 'Medium' if risk_assessment.get('overall_risk_score', 0) > 50 else 'Low',
        'service_disruption_risk': 'High' if critical_vulns > 0 or vulnerable_components > 3 else 'Medium' if vulnerable_components > 0 else 'Low',
        'reputation_risk': 'High' if critical_vulns > 0 or exposed_files > 5 else 'Medium' if user_count > 0 else 'Low',
        'compliance_risk': 'High' if len(analysis_results.get('compliance_status', {}).get('OWASP_Top_10', [])) > 3 else 'Medium' if analysis_results.get('compliance_status', {}).get('OWASP_Top_10') else 'Low',
        'financial_impact': estimate_financial_impact(risk_assessment, metrics)
    }
    
    # Investment recommendations with prioritized actions
    investment_recommendations = []
    if critical_vulns > 0:
        investment_recommendations.append("Immediate security patching and updates (Priority: Critical)")
    if vulnerable_components > 3:
        investment_recommendations.append("Comprehensive component audit and secure lifecycle management")
    if risk_assessment.get('overall_risk_score', 0) > 80:
        investment_recommendations.append("Implement Web Application Firewall (WAF) with real-time monitoring")
        investment_recommendations.append("Enhance incident response with 24/7 SOC capabilities")
    if exposed_files > 0:
        investment_recommendations.append("Implement file access controls and secure backup policies")
    if user_count > 5:
        investment_recommendations.append("Deploy user enumeration protections and MFA")
    
    # Remediation timeline with dynamic prioritization
    remediation_timeline = {
        'critical': {
            'description': 'Critical vulnerabilities requiring immediate action',
            'count': critical_vulns,
            'deadline': (datetime.now() + timedelta(days=1)).isoformat(),
            'actions': ['Apply critical patches', 'Disable vulnerable components', 'Restrict exposed admin interfaces']
        },
        'high': {
            'description': 'High-priority issues affecting system security',
            'count': metrics.get('remediation_priority', {}).get('high', 0),
            'deadline': (datetime.now() + timedelta(days=7)).isoformat(),
            'actions': ['Update outdated components', 'Implement missing security headers', 'Secure sensitive files']
        },
        'medium': {
            'description': 'Medium-priority issues for scheduled maintenance',
            'count': metrics.get('remediation_priority', {}).get('medium', 0),
            'deadline': (datetime.now() + timedelta(days=30)).isoformat(),
            'actions': ['Review user permissions', 'Optimize configurations', 'Conduct security training']
        },
        'low': {
            'description': 'Low-priority issues for long-term improvement',
            'count': metrics.get('remediation_priority', {}).get('low', 0),
            'deadline': (datetime.now() + timedelta(days=90)).isoformat(),
            'actions': ['Document configurations', 'Plan for system upgrades', 'Monitor for future risks']
        }
    }
    
    # Compliance metrics with detailed mappings
    compliance_metrics = {
        'owasp_compliance_rate': len(analysis_results.get('compliance_status', {}).get('OWASP_Top_10', [])) / 10,
        'nist_compliance_rate': len(analysis_results.get('compliance_status', {}).get('NIST_CSF', [])) / 5,
        'iso_27001_compliance_rate': len(analysis_results.get('compliance_status', {}).get('ISO_27001', [])) / 8,
        'gdpr_compliance_rate': len(analysis_results.get('compliance_status', {}).get('GDPR', [])) / 4,
        'non_compliant_controls': generate_non_compliant_controls(analysis_results)
    }
    
    # Risk trend analysis
    risk_trend = analyze_risk_trend(analysis_results)
    
    # Generate executive summary
    return {
        'executive_summary': {
            'overall_risk_level': risk_assessment.get('risk_level', 'Unknown'),
            'security_score': metrics.get('security_score', 0),
            'key_findings': key_findings[:10],  # Limit to top 10 findings
            'business_impact': business_impact,
            'investment_recommendations': investment_recommendations,
            'next_review_date': analysis_results.get('metadata', {}).get('next_recommended_scan'),
            'compliance_gaps': compliance_metrics,
            'remediation_timeline': remediation_timeline,
            'risk_trend': risk_trend,
            'executive_recommendations': generate_executive_recommendations(analysis_results),
            'attack_surface_summary': summarize_attack_surface(analysis_results),
            'roi_estimates': estimate_security_roi(investment_recommendations, business_impact)
        }
    }

def estimate_financial_impact(risk_assessment: Dict, metrics: Dict) -> Dict[str, Any]:
    """Estimate financial impact of identified risks"""
    risk_score = risk_assessment.get('overall_risk_score', 0)
    critical_vulns = metrics.get('remediation_priority', {}).get('critical', 0)
    exposed_files = metrics.get('exposed_surface', {}).get('files', 0)
    
    # Base financial impact model
    base_impact = 10000  # Base cost in USD
    critical_multiplier = 5.0 if critical_vulns > 0 else 1.0
    exposure_multiplier = 2.0 if exposed_files > 0 else 1.0
    risk_multiplier = risk_score / 100
    
    estimated_cost = base_impact * critical_multiplier * exposure_multiplier * risk_multiplier
    
    return {
        'estimated_cost': round(estimated_cost, 2),
        'cost_breakdown': {
            'data_breach': round(estimated_cost * 0.4, 2),
            'downtime': round(estimated_cost * 0.3, 2),
            'remediation': round(estimated_cost * 0.2, 2),
            'reputation': round(estimated_cost * 0.1, 2)
        },
        'confidence': min(0.9, risk_assessment.get('confidence_score', 0.5) + 0.2)
    }

def generate_non_compliant_controls(analysis_results: Dict) -> List[Dict]:
    """Generate list of non-compliant controls for compliance frameworks"""
    non_compliant = []
    compliance_status = analysis_results.get('compliance_status', {})
    
    # OWASP Top 10 controls
    owasp_controls = {
        'A01:2021': 'Implement proper access controls',
        'A02:2021': 'Use strong encryption for sensitive data',
        'A03:2021': 'Validate and sanitize all inputs',
        'A05:2021': 'Configure secure defaults',
        'A06:2021': 'Update components regularly'
    }
    
    for control in owasp_controls:
        if control in compliance_status.get('OWASP_Top_10', []):
            non_compliant.append({
                'framework': 'OWASP Top 10',
                'control': control,
                'description': owasp_controls[control],
                'severity': 'High'
            })
    
    # NIST CSF controls
    nist_controls = {
        'ID.AM-1': 'Inventory software assets',
        'PR.AC-1': 'Manage user identities',
        'PR.DS-1': 'Protect data at rest',
        'DE.AE-1': 'Establish baseline network operations',
        'RS.MI-1': 'Mitigate security incidents'
    }
    
    for control in nist_controls:
        if control in compliance_status.get('NIST_CSF', []):
            non_compliant.append({
                'framework': 'NIST CSF',
                'control': control,
                'description': nist_controls[control],
                'severity': 'Medium'
            })
    
    return non_compliant

def analyze_risk_trend(analysis_results: Dict) -> Dict[str, Any]:
    """Analyze risk trends based on historical data"""
    # Placeholder for historical comparison (requires external data)
    current_risk_score = analysis_results.get('risk_assessment', {}).get('overall_risk_score', 0)
    vuln_count = sum(analysis_results.get('metrics', {}).get('remediation_priority', {}).values())
    
    # Simulate trend based on current findings
    trend = {
        'current_risk_score': current_risk_score,
        'vulnerability_count': vuln_count,
        'trend_direction': 'Stable',  # Default, as no historical data provided
        'trend_confidence': 0.5,
        'change_indicators': []
    }
    
    if current_risk_score > 100:
        trend['change_indicators'].append('Elevated risk due to critical vulnerabilities')
    if vuln_count > 5:
        trend['change_indicators'].append('High number of vulnerabilities detected')
    
    return trend

def generate_executive_recommendations(analysis_results: Dict) -> List[str]:
    """Generate prioritized executive recommendations"""
    recommendations = []
    risk_level = analysis_results.get('risk_assessment', {}).get('risk_level', 'Unknown')
    critical_vulns = analysis_results.get('metrics', {}).get('remediation_priority', {}).get('critical', 0)
    
    if risk_level in ['Critical', 'High']:
        recommendations.append("Convene emergency security meeting to address critical risks")
    if critical_vulns > 0:
        recommendations.append("Allocate budget for immediate vulnerability remediation")
    recommendations.append("Schedule regular security assessments (weekly for high-risk systems)")
    recommendations.append("Implement automated monitoring for new vulnerabilities")
    recommendations.append("Develop comprehensive incident response plan")
    
    return recommendations

def summarize_attack_surface(analysis_results: Dict) -> Dict[str, Any]:
    """Summarize attack surface for executive reporting"""
    metrics = analysis_results.get('metrics', {})
    attack_surface = {
        'exposed_components': metrics.get('total_components', 0),
        'vulnerable_components': metrics.get('vulnerable_components', 0),
        'exposed_files': metrics.get('exposed_surface', {}).get('files', 0),
        'exposed_users': metrics.get('exposed_surface', {}).get('users', 0),
        'attack_vectors': len(analysis_results.get('attack_surface', {}).get('attack_vectors', [])),
        'critical_vectors': len([v for v in analysis_results.get('attack_surface', {}).get('attack_vectors', []) if 'Critical' in str(v)])
    }
    
    return attack_surface

def estimate_security_roi(investment_recommendations: List[str], business_impact: Dict) -> Dict[str, Any]:
    """Estimate return on investment for security measures"""
    roi_estimates = {
        'investment_areas': [],
        'estimated_savings': 0.0,
        'roi_ratio': 0.0
    }
    
    base_cost_per_measure = 5000  # USD
    total_investment = len(investment_recommendations) * base_cost_per_measure
    potential_loss = sum(business_impact.get('cost_breakdown', {}).values())
    
    for recommendation in investment_recommendations:
        roi_estimates['investment_areas'].append({
            'measure': recommendation,
            'cost': base_cost_per_measure,
            'risk_reduction': 0.3  # Assume 30% risk reduction per measure
        })
    
    roi_estimates['estimated_savings'] = potential_loss * 0.7  # Assume 70% loss prevention
    roi_estimates['roi_ratio'] = roi_estimates['estimated_savings'] / max(total_investment, 1)
    
    return roi_estimates

def export_results_to_formats(results: Dict, formats: List[str], output_dir: str) -> List[str]:
    """Export scan results to multiple formats (JSON, YAML, XML, LaTeX)"""
    output_files = []
    output_path = Path(output_dir).resolve()
    output_path.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    target = results.get('target', 'unknown')
    
    for fmt in formats:
        file_name = f"{target}_cms_recon_{timestamp}.{fmt}"
        file_path = output_path / file_name
        
        try:
            if fmt == 'json':
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2)
            elif fmt == 'yaml':
                with open(file_path, 'w', encoding='utf-8') as f:
                    yaml.dump(results, f, default_flow_style=False)
            elif fmt == 'xml':
                root = ET.Element('CMSRecon')
                dict_to_xml(results, root)
                tree = ET.ElementTree(root)
                with open(file_path, 'wb') as f:
                    tree.write(f, encoding='utf-8', xml_declaration=True)
            elif fmt == 'latex':
                latex_content = generate_latex_report(results)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(latex_content)
            output_files.append(str(file_path))
            logger.info(f"Exported results to {file_path}")
        except Exception as e:
            logger.error(f"Failed to export to {fmt}: {e}")
    
    return output_files

def dict_to_xml(data: Any, parent: ET.Element) -> None:
    """Convert dictionary to XML structure"""
    if isinstance(data, dict):
        for key, value in data.items():
            child = ET.SubElement(parent, key.replace(' ', '_').replace(':', '_'))
            dict_to_xml(value, child)
    elif isinstance(data, list):
        for item in data:
            child = ET.SubElement(parent, 'item')
            dict_to_xml(item, child)
    else:
        parent.text = str(data)

def generate_latex_report(results: Dict) -> str:
    """Generate LaTeX report for CMS reconnaissance results"""
    preamble = r"""
\documentclass[a4paper,12pt]{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{geometry}
\geometry{margin=1in}
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{xcolor}
\usepackage{enumitem}
\usepackage{noto}
\title{CMS Reconnaissance Report}
\author{Security Team}
\date{\today}
\begin{document}
\maketitle
\section{Executive Summary}
"""

    content = []
    executive_summary = results.get('executive_summary', {})
    
    content.append(f"\\textbf{{Risk Level:}} {executive_summary.get('overall_risk_level', 'Unknown')}\n")
    content.append(f"\\textbf{{Security Score:}} {executive_summary.get('security_score', 0)}/100\n")
    
    content.append("\\subsection{Key Findings}\n\\begin{itemize}\n")
    for finding in executive_summary.get('key_findings', []):
        content.append(f"\\item {finding}\n")
    content.append("\\end{itemize}\n")
    
    content.append("\\subsection{Business Impact}\n\\begin{description}\n")
    for impact, level in executive_summary.get('business_impact', {}).items():
        content.append(f"\\item[{impact.replace('_', ' ').title()}] {level}\n")
    content.append("\\end{description}\n")
    
    content.append("\\subsection{Recommendations}\n\\begin{itemize}\n")
    for rec in executive_summary.get('investment_recommendations', []):
        content.append(f"\\item {rec}\n")
    content.append("\\end{itemize}\n")
    
    content.append("\\section{Remediation Timeline}\n\\begin{longtable}{p{3cm}p{5cm}p{3cm}}\n")
    content.append("\\toprule\nPriority & Description & Deadline \\\\\n\\midrule\n")
    for priority, details in executive_summary.get('remediation_timeline', {}).items():
        content.append(f"{priority.title()} & {details['description']} & {details['deadline']} \\\\\n")
    content.append("\\bottomrule\n\\end{longtable}\n")
    
    content.append("\\end{document}")
    
    return preamble + ''.join(content)

def store_results_in_db(results: Dict, db_path: str) -> None:
    """Store scan results in SQLite database"""
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                timestamp TEXT,
                results TEXT,
                risk_level TEXT,
                security_score INTEGER
            )
        """)
        
        cursor.execute("""
            INSERT INTO scans (target, timestamp, results, risk_level, security_score)
            VALUES (?, ?, ?, ?, ?)
        """, (
            results.get('target'),
            results.get('timestamp'),
            json.dumps(results),
            results.get('executive_summary', {}).get('overall_risk_level', 'Unknown'),
            results.get('executive_summary', {}).get('security_score', 0)
        ))
        
        conn.commit()
        logger.info(f"Stored scan results in database: {db_path}")
    except sqlite3.Error as e:
        logger.error(f"Failed to store results in database: {e}")
    finally:
        if conn:
            conn.close()

def compare_with_previous_scans(db_path: str, current_results: Dict) -> Dict[str, Any]:
    """Compare current scan with previous scans in database"""
    comparison = {
        'new_findings': [],
        'resolved_findings': [],
        'persistent_findings': [],
        'trend_summary': 'No previous scans available'
    }
    
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT results FROM scans 
            WHERE target = ? 
            ORDER BY timestamp DESC LIMIT 1
        """, (current_results.get('target'),))
        
        previous_scan = cursor.fetchone()
        if previous_scan:
            previous_results = json.loads(previous_scan[0])
            changes = detect_changes(previous_results, current_results)
            
            comparison['new_findings'] = changes.get('new_vulnerabilities', []) + changes.get('new_plugins', [])
            comparison['resolved_findings'] = changes.get('fixed_vulnerabilities', []) + changes.get('removed_plugins', [])
            comparison['persistent_findings'] = [
                v for v in previous_results.get('ports', [])[0].get('vulnerabilities', [])
                if v in current_results.get('ports', [])[0].get('vulnerabilities', [])
            ]
            
            old_score = previous_results.get('executive_summary', {}).get('security_score', 0)
            new_score = current_results.get('executive_summary', {}).get('security_score', 0)
            
            if new_score > old_score:
                comparison['trend_summary'] = 'Security posture improved'
            elif new_score < old_score:
                comparison['trend_summary'] = 'Security posture degraded'
            else:
                comparison['trend_summary'] = 'Security posture stable'
        
    except sqlite3.Error as e:
        logger.error(f"Failed to compare with previous scans: {e}")
    finally:
        if conn:
            conn.close()
    
    return comparison

def generate_visualizations(results: Dict, output_dir: str) -> List[str]:
    """Generate visualizations for scan results using HTML/JS"""
    output_path = Path(output_dir).resolve()
    output_path.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    target = results.get('target', 'unknown')
    html_file = output_path / f"{target}_visualizations_{timestamp}.html"
    
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CMS Recon Visualizations - {target}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{{{ font-family: Arial, sans-serif; margin: 20px; }}}}
        canvas {{{{ max-width: 800px; margin: 20px auto; }}}}
    </style>
</head>
<body>
    <h1>CMS Reconnaissance Visualizations - {target}</h1>
    <h2>Risk Distribution</h2>
    <canvas id="riskChart"></canvas>
    <h2>Component Breakdown</h2>
    <canvas id="componentChart"></canvas>
    <script>
        const riskCtx = document.getElementById('riskChart').getContext('2d');
        new Chart(riskCtx, {{{{
            type: 'pie',
            data: {{{{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{{{ 
                    data: [
                        {results.get('metrics', {}).get('remediation_priority', {}).get('critical', 0)},
                        {results.get('metrics', {}).get('remediation_priority', {}).get('high', 0)},
                        {results.get('metrics', {}).get('remediation_priority', {}).get('medium', 0)},
                        {results.get('metrics', {}).get('remediation_priority', {}).get('low', 0)}
                    ],
                    backgroundColor: ['#FF0000', '#FFA500', '#FFFF00', '#008000']
                }}}}]
            }}}},
            options: {{{{ responsive: true }}}}
        }}}}));

        const componentCtx = document.getElementById('componentChart').getContext('2d');
        new Chart(componentCtx, {{{{
            type: 'bar',
            data: {{{{
                labels: ['Plugins', 'Themes', 'Users', 'Sensitive Files'],
                datasets: [{{{{ 
                    label: 'Count',
                    data: [
                        {results.get('metrics', {}).get('exposed_surface', {}).get('plugins', 0)},
                        {results.get('metrics', {}).get('exposed_surface', {}).get('themes', 0)},
                        {results.get('metrics', {}).get('exposed_surface', {}).get('users', 0)},
                        {results.get('metrics', {}).get('exposed_surface', {}).get('files', 0)}
                    ],
                    backgroundColor: '#4CAF50'
                }}}}]
            }}}},
            options: {{{{ responsive: true }}}}
        }}}}));
    </script>
</body>
</html>
"""
    
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    logger.info(f"Generated visualizations: {html_file}")
    return [str(html_file)]

def enhanced_cms_recon(target: str, ports: List[int], prior_findings: Dict[str, Any] = None, 
                     stealth: bool = False, proxies: Optional[Dict[str, str]] = None, 
                     cache_file: Optional[str] = None, plugin_list: Optional[str] = None,
                     output_formats: List[str] = None, db_path: Optional[str] = None,
                     output_dir: str = './recon_results') -> Dict[str, Any]:
    """Enhanced CMS recon with advanced reporting and storage"""
    results = cms_recon(target, ports, prior_findings, stealth, proxies, cache_file, plugin_list)
    
    # Generate visualizations
    visualization_files = generate_visualizations(results, output_dir)
    results['visualizations'] = visualization_files
    
    # Store in database
    if db_path:
        store_results_in_db(results, db_path)
    
    # Export to specified formats
    output_formats = output_formats or ['json']
    output_files = export_results_to_formats(results, output_formats, output_dir)
    results['output_files'] = output_files
    
    # Compare with previous scans
    if db_path:
        comparison = compare_with_previous_scans(db_path, results)
        results['historical_comparison'] = comparison
    
    return results
def main():
    """Main function to test all functionalities of CMS reconnaissance tool"""
    parser = argparse.ArgumentParser(description="Enhanced CMS Reconnaissance Tool")
    parser.add_argument('--target', type=str, default='example.com', help='Target domain or IP')
    parser.add_argument('--ports', type=int, nargs='*', default=[80, 443], help='Ports to scan')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    parser.add_argument('--proxy', type=str, help='Proxy URL (e.g., http://proxy:8080)')
    parser.add_argument('--cache', type=str, default='cache.json', help='Cache file path')
    parser.add_argument('--plugins', type=str, help='Plugin list file path')
    parser.add_argument('--formats', type=str, nargs='*', default=['json', 'yaml'], choices=['json', 'yaml', 'xml', 'latex'], help='Output formats')
    parser.add_argument('--db', type=str, default='recon.db', help='Database path')
    parser.add_argument('--output-dir', type=str, default='./recon_results', help='Output directory')
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Prepare inputs
    target = args.target
    ports = args.ports
    proxies = {'http': args.proxy, 'https': args.proxy} if args.proxy else None
    prior_findings = {}  # Mock prior findings for testing
    
    try:
        # Run enhanced CMS reconnaissance
        results = enhanced_cms_recon(
            target=target,
            ports=ports,
            prior_findings=prior_findings,
            stealth=args.stealth,
            proxies=proxies,
            cache_file=args.cache,
            plugin_list=args.plugins,
            output_formats=args.formats,
            db_path=args.db,
            output_dir=args.output_dir
        )
        
        logger.info(f"Recon completed for {target}. Results saved to: {results.get('output_files', [])}")
        logger.info(f"Visualizations generated: {results.get('visualizations', [])}")
        if 'historical_comparison' in results:
            logger.info(f"Historical comparison: {results['historical_comparison']['trend_summary']}")
        
    except Exception as e:
        logger.error(f"Recon failed: {e}")
        return

if __name__ == "__main__":
    main()
