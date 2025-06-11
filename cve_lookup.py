import logging
import re
import hashlib
import sqlite3
import threading
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any, Tuple, Union, Set
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from collections import defaultdict, deque
import json
import requests
import random
import time
from urllib.parse import quote
import xml.etree.ElementTree as ET
from packaging import version as pkg_version
import statistics

logger = logging.getLogger('recon_tool')

# Configuration constants
CVE_CACHE_TTL = 86400  # 24 hours
MAX_RETRIES = 3
RETRY_BACKOFF = 2
CONNECTION_TIMEOUT = 30
READ_TIMEOUT = 60
MAX_CONCURRENT_REQUESTS = 10
RATE_LIMIT_DELAY = 0.1

# CVSS scoring thresholds
CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0
CVSS_MEDIUM = 4.0
CVSS_LOW = 0.1

# User agents for stealth mode
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
]

@dataclass
class CVEMetrics:
    """Enhanced CVE metrics with multiple scoring systems"""
    cvss_v2_score: float = 0.0
    cvss_v3_score: float = 0.0
    cvss_v4_score: float = 0.0
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    exploit_maturity: str = "unknown"
    attack_vector: str = "unknown"
    attack_complexity: str = "unknown"
    privileges_required: str = "unknown"
    user_interaction: str = "unknown"
    scope: str = "unknown"
    confidentiality_impact: str = "unknown"
    integrity_impact: str = "unknown"
    availability_impact: str = "unknown"

@dataclass
class CVEInfo:
    """Comprehensive CVE information structure"""
    cve_id: str
    description: str
    published_date: str = ""
    modified_date: str = ""
    metrics: CVEMetrics = field(default_factory=CVEMetrics)
    references: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cpe_configs: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_sources: List[str] = field(default_factory=list)
    patch_available: bool = False
    patch_sources: List[str] = field(default_factory=list)
    vendor_advisories: List[str] = field(default_factory=list)
    threat_intelligence: Dict[str, Any] = field(default_factory=dict)

class CircuitBreaker:
    """Circuit breaker pattern for API reliability"""
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "closed"  # closed, open, half-open
        self.lock = threading.Lock()

    def call(self, func, *args, **kwargs):
        with self.lock:
            if self.state == "open":
                if time.time() - self.last_failure_time < self.recovery_timeout:
                    raise Exception("Circuit breaker is open")
                else:
                    self.state = "half-open"
            
            try:
                result = func(*args, **kwargs)
                if self.state == "half-open":
                    self.state = "closed"
                    self.failure_count = 0
                return result
            except Exception as e:
                self.failure_count += 1
                self.last_failure_time = time.time()
                if self.failure_count >= self.failure_threshold:
                    self.state = "open"
                raise e

class CacheManager:
    """Advanced caching with SQLite backend and TTL support"""
    def __init__(self, cache_file: Optional[str] = None):
        self.cache_file = cache_file or ":memory:"
        self.memory_cache = {}
        self.cache_lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        """Initialize SQLite database for persistent caching"""
        if self.cache_file != ":memory:":
            Path(self.cache_file).parent.mkdir(parents=True, exist_ok=True)
        
        self.conn = sqlite3.connect(self.cache_file, check_same_thread=False)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS cve_cache (
                key TEXT PRIMARY KEY,
                data TEXT,
                timestamp REAL,
                ttl INTEGER
            )
        ''')
        self.conn.commit()

    def get(self, key: str, default=None):
        """Get cached data with TTL check"""
        with self.cache_lock:
            # Check memory cache first
            if key in self.memory_cache:
                data, timestamp, ttl = self.memory_cache[key]
                if time.time() - timestamp < ttl:
                    return json.loads(data)
                else:
                    del self.memory_cache[key]

            # Check persistent cache
            cursor = self.conn.execute(
                'SELECT data, timestamp, ttl FROM cve_cache WHERE key = ?',
                (key,)
            )
            row = cursor.fetchone()
            if row:
                data, timestamp, ttl = row
                if time.time() - timestamp < ttl:
                    # Store in memory cache for faster access
                    self.memory_cache[key] = (data, timestamp, ttl)
                    return json.loads(data)
                else:
                    # Remove expired entry
                    self.conn.execute('DELETE FROM cve_cache WHERE key = ?', (key,))
                    self.conn.commit()
            
            return default

    def set(self, key: str, data: Any, ttl: int = CVE_CACHE_TTL):
        """Set cached data with TTL"""
        with self.cache_lock:
            json_data = json.dumps(data)
            timestamp = time.time()
            
            # Store in memory cache
            self.memory_cache[key] = (json_data, timestamp, ttl)
            
            # Store in persistent cache
            self.conn.execute(
                'INSERT OR REPLACE INTO cve_cache (key, data, timestamp, ttl) VALUES (?, ?, ?, ?)',
                (key, json_data, timestamp, ttl)
            )
            self.conn.commit()

    def clear_expired(self):
        """Clear expired cache entries"""
        with self.cache_lock:
            current_time = time.time()
            
            # Clear memory cache
            expired_keys = [
                key for key, (_, timestamp, ttl) in self.memory_cache.items()
                if current_time - timestamp >= ttl
            ]
            for key in expired_keys:
                del self.memory_cache[key]
            
            # Clear persistent cache
            self.conn.execute(
                'DELETE FROM cve_cache WHERE timestamp + ttl < ?',
                (current_time,)
            )
            self.conn.commit()

class StealthManager:
    """Manage stealth features for evasion"""
    def __init__(self, stealth: bool = False):
        self.stealth = stealth
        self.last_request_time = 0
        self.request_delays = deque(maxlen=10)
        
    def get_headers(self) -> Dict[str, str]:
        """Get randomized headers for stealth"""
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        if self.stealth:
            # Add random headers to appear more human-like
            if random.random() < 0.3:
                headers['DNT'] = '1'
            if random.random() < 0.2:
                headers['Pragma'] = 'no-cache'
            if random.random() < 0.4:
                headers['Cache-Control'] = 'no-cache'
                
        return headers

    def wait_if_needed(self):
        """Implement intelligent delay for stealth"""
        if not self.stealth:
            return
            
        current_time = time.time()
        
        # Calculate adaptive delay based on recent request patterns
        if self.request_delays:
            avg_delay = statistics.mean(self.request_delays)
            base_delay = max(0.5, avg_delay * 0.8)
        else:
            base_delay = 1.0
            
        # Add jitter to avoid detection
        delay = base_delay + random.uniform(0.1, 2.0)
        
        if current_time - self.last_request_time < delay:
            sleep_time = delay - (current_time - self.last_request_time)
            time.sleep(sleep_time)
            
        self.request_delays.append(delay)
        self.last_request_time = time.time()

class CVEDataSource(ABC):
    """Abstract base class for CVE data sources"""
    
    @abstractmethod
    def fetch_cves(self, product: str, version: str, **kwargs) -> List[CVEInfo]:
        pass
    
    @abstractmethod
    def get_source_name(self) -> str:
        pass

class NVDSource(CVEDataSource):
    """NIST National Vulnerability Database source"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.circuit_breaker = CircuitBreaker()
        
    def get_source_name(self) -> str:
        return "NVD"
    
    def _build_cpe_string(self, product: str, version: str) -> str:
        """Build CPE string with better formatting"""
        # Normalize product name
        product = re.sub(r'[^a-zA-Z0-9_.-]', '_', product.lower())
        version = re.sub(r'[^a-zA-Z0-9_.-]', '_', version.lower())
        
        return f"cpe:2.3:a:*:{product}:{version}:*:*:*:*:*:*:*"
    
    def _parse_cvss_metrics(self, cve_data: Dict) -> CVEMetrics:
        """Parse CVSS metrics from NVD data"""
        metrics = CVEMetrics()
        
        # CVSS v3.1
        cvss_v3 = cve_data.get('metrics', {}).get('cvssMetricV31', [])
        if cvss_v3:
            cvss_data = cvss_v3[0].get('cvssData', {})
            metrics.cvss_v3_score = cvss_data.get('baseScore', 0.0)
            metrics.attack_vector = cvss_data.get('attackVector', 'unknown')
            metrics.attack_complexity = cvss_data.get('attackComplexity', 'unknown')
            metrics.privileges_required = cvss_data.get('privilegesRequired', 'unknown')
            metrics.user_interaction = cvss_data.get('userInteraction', 'unknown')
            metrics.scope = cvss_data.get('scope', 'unknown')
            metrics.confidentiality_impact = cvss_data.get('confidentialityImpact', 'unknown')
            metrics.integrity_impact = cvss_data.get('integrityImpact', 'unknown')
            metrics.availability_impact = cvss_data.get('availabilityImpact', 'unknown')
        
        # CVSS v3.0 fallback
        if not cvss_v3:
            cvss_v30 = cve_data.get('metrics', {}).get('cvssMetricV30', [])
            if cvss_v30:
                metrics.cvss_v3_score = cvss_v30[0].get('cvssData', {}).get('baseScore', 0.0)
        
        # CVSS v2
        cvss_v2 = cve_data.get('metrics', {}).get('cvssMetricV2', [])
        if cvss_v2:
            metrics.cvss_v2_score = cvss_v2[0].get('cvssData', {}).get('baseScore', 0.0)
            
        return metrics
    
    def fetch_cves(self, product: str, version: str, **kwargs) -> List[CVEInfo]:
        """Fetch CVEs from NVD API with enhanced error handling"""
        try:
            cpe_string = self._build_cpe_string(product, version)
            
            params = {
                'cpeMatchString': cpe_string,
                'resultsPerPage': 2000
            }
            
            headers = kwargs.get('headers', {})
            if self.api_key:
                headers['apiKey'] = self.api_key
                
            def make_request():
                response = requests.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    proxies=kwargs.get('proxies'),
                    timeout=(CONNECTION_TIMEOUT, READ_TIMEOUT)
                )
                response.raise_for_status()
                return response.json()
            
            data = self.circuit_breaker.call(make_request)
            cves = []
            
            for vuln in data.get('vulnerabilities', []):
                cve_data = vuln.get('cve', {})
                
                # Extract basic info
                cve_info = CVEInfo(
                    cve_id=cve_data.get('id', ''),
                    description=cve_data.get('descriptions', [{}])[0].get('value', ''),
                    published_date=cve_data.get('published', ''),
                    modified_date=cve_data.get('lastModified', ''),
                    metrics=self._parse_cvss_metrics(cve_data)
                )
                
                # Extract references
                cve_info.references = [
                    ref.get('url', '') for ref in cve_data.get('references', [])
                ]
                
                # Extract CWE IDs
                weaknesses = cve_data.get('weaknesses', [])
                for weakness in weaknesses:
                    for desc in weakness.get('description', []):
                        if desc.get('lang') == 'en':
                            cve_info.cwe_ids.append(desc.get('value', ''))
                
                # Extract CPE configurations
                configurations = cve_data.get('configurations', [])
                for config in configurations:
                    for node in config.get('nodes', []):
                        for cpe_match in node.get('cpeMatch', []):
                            if cpe_match.get('vulnerable', False):
                                cve_info.cpe_configs.append(cpe_match.get('criteria', ''))
                
                cves.append(cve_info)
                
            return cves
            
        except Exception as e:
            logger.error(f"Failed to fetch CVEs from NVD for {product} {version}: {e}")
            return []

class CVEDetailsSource(CVEDataSource):
    """CVE Details alternative source"""
    
    def get_source_name(self) -> str:
        return "CVEDetails"
    
    def fetch_cves(self, product: str, version: str, **kwargs) -> List[CVEInfo]:
        """Fetch CVEs from CVE Details (implementation would depend on their API)"""
        # This would implement CVE Details API integration
        # For now, return empty list as placeholder
        return []

class EPSSSource:
    """EPSS (Exploit Prediction Scoring System) data source"""
    
    def __init__(self):
        self.base_url = "https://api.first.org/data/v1/epss"
        
    def get_epss_scores(self, cve_ids: List[str]) -> Dict[str, Tuple[float, float]]:
        """Get EPSS scores for CVE IDs"""
        try:
            # EPSS API allows bulk queries
            cve_param = ','.join(cve_ids[:100])  # Limit to 100 CVEs per request
            
            response = requests.get(
                self.base_url,
                params={'cve': cve_param},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                scores = {}
                
                for item in data.get('data', []):
                    cve_id = item.get('cve', '')
                    epss_score = float(item.get('epss', 0))
                    percentile = float(item.get('percentile', 0))
                    scores[cve_id] = (epss_score, percentile)
                
                return scores
            
        except Exception as e:
            logger.error(f"Failed to fetch EPSS scores: {e}")
            
        return {}

class ExploitDetector:
    """Detect available exploits from multiple sources"""
    
    def __init__(self):
        self.exploit_sources = [
            'https://www.exploit-db.com',
            'https://packetstormsecurity.com',
            'https://cxsecurity.com'
        ]
    
    def check_exploits(self, cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """Check for available exploits"""
        exploit_data = {}
        
        for cve_id in cve_ids:
            exploits = self._search_exploits(cve_id)
            if exploits:
                exploit_data[cve_id] = {
                    'available': True,
                    'sources': exploits,
                    'count': len(exploits)
                }
            else:
                exploit_data[cve_id] = {
                    'available': False,
                    'sources': [],
                    'count': 0
                }
        
        return exploit_data
    
    def _search_exploits(self, cve_id: str) -> List[str]:
        """Search for exploits for a specific CVE"""
        exploits = []
        
        # This would implement actual exploit database searches
        # For now, we'll use a simple heuristic based on CVE age and severity
        try:
            # Extract year from CVE ID
            cve_year = int(cve_id.split('-')[1])
            current_year = datetime.now().year
            
            # Older CVEs are more likely to have exploits
            if current_year - cve_year > 2:
                exploits.append("Potential exploit available - check Metasploit")
            
            # Add placeholder for common exploit sources
            exploits.append("Check Exploit-DB for modules")
            
        except (ValueError, IndexError):
            pass
            
        return exploits

class ProductNormalizer:
    """Normalize product names and versions for better matching"""
    
    def __init__(self):
        self.product_aliases = {
            'apache': ['httpd', 'apache2', 'apache-httpd'],
            'nginx': ['nginx-core', 'nginx-full'],
            'mysql': ['mysql-server', 'mariadb', 'percona'],
            'postgresql': ['postgres', 'pgsql'],
            'openssh': ['ssh', 'sshd', 'openssh-server'],
            'bind': ['named', 'bind9'],
            'postfix': ['postfix-main'],
            'dovecot': ['dovecot-core'],
            'proftpd': ['proftpd-basic'],
            'vsftpd': ['vsftpd-server']
        }
        
        self.version_patterns = [
            r'(\d+\.\d+\.\d+)',  # x.y.z
            r'(\d+\.\d+)',       # x.y
            r'(\d+)',            # x
        ]
    
    def normalize_product(self, product: str) -> List[str]:
        """Normalize product name and return possible variations"""
        if not product:
            return []
            
        product = product.lower().strip()
        products = [product]
        
        # Check for known aliases
        for main_product, aliases in self.product_aliases.items():
            if product in aliases:
                products.append(main_product)
            elif product == main_product:
                products.extend(aliases)
        
        # Remove common suffixes/prefixes
        cleaned = re.sub(r'(server|client|core|full|basic|main)$', '', product)
        if cleaned != product and cleaned:
            products.append(cleaned)
        
        return list(set(products))
    
    def normalize_version(self, version: str) -> List[str]:
        """Normalize version string and return possible variations"""
        if not version:
            return []
            
        versions = [version]
        
        # Extract version numbers using patterns
        for pattern in self.version_patterns:
            match = re.search(pattern, version)
            if match:
                extracted_version = match.group(1)
                if extracted_version not in versions:
                    versions.append(extracted_version)
        
        # Remove common prefixes
        cleaned = re.sub(r'^(v|version|rel|release)', '', version, flags=re.IGNORECASE)
        if cleaned != version and cleaned:
            versions.append(cleaned)
        
        return list(set(versions))

class MultiSourceCVEManager:
    """Manage multiple CVE data sources with fallback"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.sources = [
            NVDSource(api_key),
            CVEDetailsSource(),
        ]
        self.epss_source = EPSSSource()
        self.exploit_detector = ExploitDetector()
        self.product_normalizer = ProductNormalizer()
        
    def fetch_comprehensive_cves(self, product: str, version: str, **kwargs) -> List[CVEInfo]:
        """Fetch CVEs from multiple sources with comprehensive data"""
        all_cves = []
        cve_map = {}
        
        # Normalize product and version
        products = self.product_normalizer.normalize_product(product)
        versions = self.product_normalizer.normalize_version(version)
        
        # Try each product/version combination
        for norm_product in products:
            for norm_version in versions:
                # Try each source
                for source in self.sources:
                    try:
                        cves = source.fetch_cves(norm_product, norm_version, **kwargs)
                        for cve in cves:
                            if cve.cve_id not in cve_map:
                                cve_map[cve.cve_id] = cve
                                all_cves.append(cve)
                            else:
                                # Merge data from multiple sources
                                existing_cve = cve_map[cve.cve_id]
                                self._merge_cve_data(existing_cve, cve)
                                
                    except Exception as e:
                        logger.warning(f"Source {source.get_source_name()} failed for {norm_product} {norm_version}: {e}")
                        continue
        
        # Enrich with EPSS scores
        if all_cves:
            cve_ids = [cve.cve_id for cve in all_cves]
            epss_scores = self.epss_source.get_epss_scores(cve_ids)
            
            for cve in all_cves:
                if cve.cve_id in epss_scores:
                    epss_score, percentile = epss_scores[cve.cve_id]
                    cve.metrics.epss_score = epss_score
                    cve.metrics.epss_percentile = percentile
        
        # Check for exploits
        if all_cves:
            cve_ids = [cve.cve_id for cve in all_cves]
            exploit_data = self.exploit_detector.check_exploits(cve_ids)
            
            for cve in all_cves:
                if cve.cve_id in exploit_data:
                    exploit_info = exploit_data[cve.cve_id]
                    cve.exploit_available = exploit_info['available']
                    cve.exploit_sources = exploit_info['sources']
        
        return all_cves
    
    def _merge_cve_data(self, existing: CVEInfo, new: CVEInfo):
        """Merge CVE data from multiple sources"""
        # Merge references
        existing.references.extend([ref for ref in new.references if ref not in existing.references])
        
        # Merge CWE IDs
        existing.cwe_ids.extend([cwe for cwe in new.cwe_ids if cwe not in existing.cwe_ids])
        
        # Merge CPE configurations
        existing.cpe_configs.extend([cpe for cpe in new.cpe_configs if cpe not in existing.cpe_configs])
        
        # Update metrics if new source has better data
        if new.metrics.cvss_v3_score > existing.metrics.cvss_v3_score:
            existing.metrics.cvss_v3_score = new.metrics.cvss_v3_score
            existing.metrics.attack_vector = new.metrics.attack_vector
            existing.metrics.attack_complexity = new.metrics.attack_complexity

class RiskAnalyzer:
    """Advanced risk analysis for CVE findings"""
    
    def __init__(self):
        self.risk_weights = {
            'cvss_score': 0.4,
            'epss_score': 0.25,
            'exploit_available': 0.2,
            'service_exposure': 0.1,
            'patch_age': 0.05
        }
    
    def calculate_comprehensive_risk(self, services: List[Dict], target_info: Dict = None) -> Dict[str, Any]:
        """Calculate comprehensive risk assessment"""
        if not services:
            return {
                'risk_score': 0,
                'risk_level': 'Low',
                'findings': [],
                'recommendations': [],
                'priority_cves': [],
                'attack_vectors': [],
                'affected_services': []
            }
        
        all_cves = []
        service_risks = []
        
        for service in services:
            service_risk = self._analyze_service_risk(service, target_info)
            service_risks.append(service_risk)
            all_cves.extend(service.get('cves', []))
        
        # Calculate overall risk metrics
        overall_risk = self._calculate_overall_risk(service_risks, all_cves)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(services, overall_risk)
        
        # Identify priority CVEs
        priority_cves = self._identify_priority_cves(all_cves)
        
        # Analyze attack vectors
        attack_vectors = self._analyze_attack_vectors(all_cves)
        
        return {
            'risk_score': overall_risk['score'],
            'risk_level': overall_risk['level'],
            'confidence': overall_risk['confidence'],
            'findings': all_cves,
            'recommendations': recommendations,
            'priority_cves': priority_cves,
            'attack_vectors': attack_vectors,
            'affected_services': service_risks,
            'timeline_analysis': self._analyze_cve_timeline(all_cves),
            'compliance_impact': self._assess_compliance_impact(all_cves),
            'business_impact': self._assess_business_impact(service_risks)
        }
    
    def _analyze_service_risk(self, service: Dict, target_info: Dict = None) -> Dict[str, Any]:
        """Analyze risk for individual service"""
        port = service.get('port', 0)
        product = service.get('product', '')
        version = service.get('version', '')
        cves = service.get('cves', [])
        
        if not cves:
            return {
                'port': port,
                'product': product,
                'version': version,
                'risk_score': 0,
                'risk_level': 'Low',
                'cve_count': 0,
                'critical_count': 0,
                'high_count': 0,
                'exploitable_count': 0
            }
        
        # Count CVEs by severity
        critical_count = sum(1 for cve in cves if getattr(cve.metrics, 'cvss_v3_score', 0) >= CVSS_CRITICAL)
        high_count = sum(1 for cve in cves if CVSS_HIGH <= getattr(cve.metrics, 'cvss_v3_score', 0) < CVSS_CRITICAL)
        exploitable_count = sum(1 for cve in cves if getattr(cve, 'exploit_available', False))
        
        # Calculate weighted risk score
        total_score = 0
        for cve in cves:
            cvss_score = getattr(cve.metrics, 'cvss_v3_score', 0)
            epss_score = getattr(cve.metrics, 'epss_score', 0)
            exploit_multiplier = 1.5 if getattr(cve, 'exploit_available', False) else 1.0
            
            cve_risk = (cvss_score * 0.7 + epss_score * 10 * 0.3) * exploit_multiplier
            total_score += cve_risk
        
        # Adjust for service exposure
        exposure_multiplier = self._get_exposure_multiplier(port)
        service_risk_score = (total_score / len(cves)) * exposure_multiplier
        
        # Determine risk level
        if service_risk_score >= 8.0:
            risk_level = 'Critical'
        elif service_risk_score >= 6.0:
            risk_level = 'High'
        elif service_risk_score >= 4.0:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        return {
            'port': port,
            'product': product,
            'version': version,
            'risk_score': round(service_risk_score, 2),
            'risk_level': risk_level,
            'cve_count': len(cves),
            'critical_count': critical_count,
            'high_count': high_count,
            'exploitable_count': exploitable_count,
            'exposure_factor': exposure_multiplier
        }
    
    def _get_exposure_multiplier(self, port: int) -> float:
        """Get exposure multiplier based on port"""
        # High-risk ports that are commonly targeted
        high_risk_ports = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900}
        # Medium-risk ports
        medium_risk_ports = {20, 69, 111, 161, 389, 636, 873, 1080, 1521, 2049, 8080, 8443}
        
        if port in high_risk_ports:
            return 1.3
        elif port in medium_risk_ports:
            return 1.1
        else:
            return 1.0
    
    def _calculate_overall_risk(self, service_risks: List[Dict], all_cves: List[CVEInfo]) -> Dict[str, Any]:
        """Calculate overall risk assessment"""
        if not service_risks:
            return {'score': 0, 'level': 'Low', 'confidence': 1.0}
        
        # Calculate weighted average of service risks
        total_weighted_score = sum(risk['risk_score'] * risk['cve_count'] for risk in service_risks)
        total_cves = sum(risk['cve_count'] for risk in service_risks)
        
        if total_cves == 0:
            return {'score': 0, 'level': 'Low', 'confidence': 1.0}
        
        average_risk = total_weighted_score / total_cves
        
        # Apply additional factors
        critical_services = sum(1 for risk in service_risks if risk['risk_level'] == 'Critical')
        high_services = sum(1 for risk in service_risks if risk['risk_level'] == 'High')
        
        # Boost score if multiple critical services
        if critical_services > 1:
            average_risk *= 1.2
        elif critical_services == 1 and high_services > 0:
            average_risk *= 1.1
        
        # Determine overall risk level
        if average_risk >= 8.0:
            risk_level = 'Critical'
        elif average_risk >= 6.0:
            risk_level = 'High'
        elif average_risk >= 4.0:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        # Calculate confidence based on data completeness
        confidence = self._calculate_confidence(all_cves)
        
        return {
            'score': round(average_risk, 2),
            'level': risk_level,
            'confidence': confidence
        }
    
    def _calculate_confidence(self, cves: List[CVEInfo]) -> float:
        """Calculate confidence score based on data completeness"""
        if not cves:
            return 1.0
        
        confidence_factors = []
        
        for cve in cves:
            # Check data completeness
            has_cvss = getattr(cve.metrics, 'cvss_v3_score', 0) > 0
            has_epss = getattr(cve.metrics, 'epss_score', 0) > 0
            has_description = bool(getattr(cve, 'description', ''))
            has_references = bool(getattr(cve, 'references', []))
            
            cve_confidence = sum([has_cvss, has_epss, has_description, has_references]) / 4.0
            confidence_factors.append(cve_confidence)
        
        return round(statistics.mean(confidence_factors), 2)
    
    def _generate_recommendations(self, services: List[Dict], overall_risk: Dict) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Critical recommendations
        critical_services = [s for s in services if any(
            getattr(cve.metrics, 'cvss_v3_score', 0) >= CVSS_CRITICAL 
            for cve in s.get('cves', [])
        )]
        
        if critical_services:
            recommendations.append("URGENT: Address critical vulnerabilities immediately - consider taking affected services offline if patches are not available")
            
        # High-risk recommendations
        high_risk_services = [s for s in services if any(
            CVSS_HIGH <= getattr(cve.metrics, 'cvss_v3_score', 0) < CVSS_CRITICAL 
            for cve in s.get('cves', [])
        )]
        
        if high_risk_services:
            recommendations.append("HIGH PRIORITY: Apply security patches for high-severity vulnerabilities within 48-72 hours")
        
        # Exploitable vulnerabilities
        exploitable_services = [s for s in services if any(
            getattr(cve, 'exploit_available', False) 
            for cve in s.get('cves', [])
        )]
        
        if exploitable_services:
            recommendations.append("IMMEDIATE ACTION: Known exploits exist - implement additional monitoring and consider WAF/IPS rules")
        
        # Network segmentation
        if len(services) > 3:
            recommendations.append("Consider network segmentation to limit blast radius of potential compromises")
        
        # Monitoring recommendations
        recommendations.append("Implement continuous vulnerability monitoring and automated patch management")
        
        # Service-specific recommendations
        for service in services:
            product = service.get('product', '').lower()
            if 'apache' in product or 'nginx' in product:
                recommendations.append(f"Web server detected on port {service.get('port')}: Enable security headers and consider web application firewall")
            elif 'ssh' in product:
                recommendations.append(f"SSH service detected: Disable password authentication, use key-based auth, and implement fail2ban")
            elif 'mysql' in product or 'postgresql' in product:
                recommendations.append(f"Database service detected: Ensure it's not exposed to internet and use encrypted connections")
        
        return list(set(recommendations))  # Remove duplicates
    
    def _identify_priority_cves(self, cves: List[CVEInfo]) -> List[Dict[str, Any]]:
        """Identify highest priority CVEs for immediate attention"""
        priority_cves = []
        
        for cve in cves:
            cvss_score = getattr(cve.metrics, 'cvss_v3_score', 0)
            epss_score = getattr(cve.metrics, 'epss_score', 0)
            exploit_available = getattr(cve, 'exploit_available', False)
            
            # Calculate priority score
            priority_score = cvss_score
            
            if exploit_available:
                priority_score += 2.0
            
            if epss_score > 0.1:  # High EPSS score
                priority_score += 1.0
            
            # Check for recent publication
            pub_date = getattr(cve, 'published_date', '')
            if pub_date:
                try:
                    pub_datetime = datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
                    days_old = (datetime.now().replace(tzinfo=pub_datetime.tzinfo) - pub_datetime).days
                    if days_old < 30:  # Recently published
                        priority_score += 0.5
                except:
                    pass
            
            if priority_score >= 7.0:  # Only include high-priority CVEs
                priority_cves.append({
                    'cve_id': cve.cve_id,
                    'priority_score': round(priority_score, 2),
                    'cvss_score': cvss_score,
                    'epss_score': epss_score,
                    'exploit_available': exploit_available,
                    'description': getattr(cve, 'description', '')[:200] + '...' if len(getattr(cve, 'description', '')) > 200 else getattr(cve, 'description', ''),
                    'attack_vector': getattr(cve.metrics, 'attack_vector', 'unknown')
                })
        
        # Sort by priority score
        priority_cves.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return priority_cves[:10]  # Return top 10
    
    def _analyze_attack_vectors(self, cves: List[CVEInfo]) -> Dict[str, Any]:
        """Analyze common attack vectors"""
        attack_vectors = defaultdict(int)
        attack_complexity = defaultdict(int)
        
        for cve in cves:
            vector = getattr(cve.metrics, 'attack_vector', 'unknown').lower()
            complexity = getattr(cve.metrics, 'attack_complexity', 'unknown').lower()
            
            attack_vectors[vector] += 1
            attack_complexity[complexity] += 1
        
        return {
            'vectors': dict(attack_vectors),
            'complexity': dict(attack_complexity),
            'network_exploitable': attack_vectors.get('network', 0),
            'local_exploitable': attack_vectors.get('local', 0),
            'adjacent_exploitable': attack_vectors.get('adjacent_network', 0),
            'physical_exploitable': attack_vectors.get('physical', 0)
        }
    
    def _analyze_cve_timeline(self, cves: List[CVEInfo]) -> Dict[str, Any]:
        """Analyze CVE publication timeline"""
        timeline = defaultdict(int)
        recent_cves = 0
        old_cves = 0
        
        current_date = datetime.now()
        
        for cve in cves:
            pub_date = getattr(cve, 'published_date', '')
            if pub_date:
                try:
                    pub_datetime = datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
                    year = pub_datetime.year
                    timeline[year] += 1
                    
                    days_old = (current_date.replace(tzinfo=pub_datetime.tzinfo) - pub_datetime).days
                    if days_old < 90:
                        recent_cves += 1
                    elif days_old > 365:
                        old_cves += 1
                        
                except:
                    pass
        
        return {
            'by_year': dict(timeline),
            'recent_cves': recent_cves,
            'old_cves': old_cves,
            'total_cves': len(cves)
        }
    
    def _assess_compliance_impact(self, cves: List[CVEInfo]) -> Dict[str, Any]:
        """Assess compliance framework impact"""
        high_severity_count = sum(1 for cve in cves if getattr(cve.metrics, 'cvss_v3_score', 0) >= CVSS_HIGH)
        critical_count = sum(1 for cve in cves if getattr(cve.metrics, 'cvss_v3_score', 0) >= CVSS_CRITICAL)
        
        compliance_risks = []
        
        if critical_count > 0:
            compliance_risks.extend([
                "PCI DSS: Critical vulnerabilities may impact payment card data security",
                "SOX: System integrity concerns for financial reporting systems",
                "HIPAA: Patient data protection may be compromised"
            ])
        
        if high_severity_count > 0:
            compliance_risks.extend([
                "ISO 27001: Information security management system requirements",
                "NIST: Cybersecurity framework compliance concerns"
            ])
        
        return {
            'risk_level': 'Critical' if critical_count > 0 else 'High' if high_severity_count > 0 else 'Medium',
            'affected_frameworks': compliance_risks,
            'remediation_timeline': '24-48 hours' if critical_count > 0 else '1-2 weeks' if high_severity_count > 0 else '30 days'
        }
    
    def _assess_business_impact(self, service_risks: List[Dict]) -> Dict[str, Any]:
        """Assess business impact of vulnerabilities"""
        critical_services = sum(1 for s in service_risks if s['risk_level'] == 'Critical')
        high_services = sum(1 for s in service_risks if s['risk_level'] == 'High')
        
        # Assess based on service types
        web_services = sum(1 for s in service_risks if s['port'] in [80, 443, 8080, 8443])
        database_services = sum(1 for s in service_risks if s['port'] in [1433, 3306, 5432])
        remote_access = sum(1 for s in service_risks if s['port'] in [22, 3389, 5900])
        
        impact_factors = []
        
        if critical_services > 0:
            impact_factors.append("Service availability at risk")
            impact_factors.append("Data confidentiality compromised")
            impact_factors.append("Potential for lateral movement")
        
        if web_services > 0 and any(s['risk_level'] in ['Critical', 'High'] for s in service_risks if s['port'] in [80, 443]):
            impact_factors.append("Customer-facing services vulnerable")
            impact_factors.append("Reputation damage risk")
        
        if database_services > 0:
            impact_factors.append("Data breach potential")
            impact_factors.append("Regulatory compliance violation risk")
        
        if remote_access > 0:
            impact_factors.append("Unauthorized access risk")
            impact_factors.append("Privilege escalation potential")
        
        # Calculate overall business impact
        if critical_services > 2:
            business_impact = 'Severe'
        elif critical_services > 0 or high_services > 3:
            business_impact = 'High'
        elif high_services > 0:
            business_impact = 'Medium'
        else:
            business_impact = 'Low'
        
        return {
            'impact_level': business_impact,
            'impact_factors': impact_factors,
            'affected_service_types': {
                'web_services': web_services,
                'database_services': database_services,
                'remote_access': remote_access
            }
        }

# Global instances
_cache_manager = None
_multi_source_manager = None
_risk_analyzer = None
_stealth_manager = None

def get_cache_manager(cache_file: Optional[str] = None) -> CacheManager:
    """Get or create cache manager instance"""
    global _cache_manager
    if _cache_manager is None or (cache_file and cache_file != _cache_manager.cache_file):
        _cache_manager = CacheManager(cache_file)
    return _cache_manager

def get_multi_source_manager(api_key: Optional[str] = None) -> MultiSourceCVEManager:
    """Get or create multi-source CVE manager"""
    global _multi_source_manager
    if _multi_source_manager is None:
        _multi_source_manager = MultiSourceCVEManager(api_key)
    return _multi_source_manager

def get_risk_analyzer() -> RiskAnalyzer:
    """Get or create risk analyzer instance"""
    global _risk_analyzer
    if _risk_analyzer is None:
        _risk_analyzer = RiskAnalyzer()
    return _risk_analyzer

def get_stealth_manager(stealth: bool = False) -> StealthManager:
    """Get or create stealth manager instance"""
    global _stealth_manager
    if _stealth_manager is None or _stealth_manager.stealth != stealth:
        _stealth_manager = StealthManager(stealth)
    return _stealth_manager

def sanitize_target(target: str) -> str:
    """Sanitize and validate target input with enhanced security checks"""
    if not target or not isinstance(target, str):
        logger.error("Invalid target: empty or not a string")
        raise ValueError("Target must be a non-empty string")
    
    target = target.strip()
    
    # Enhanced validation patterns
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$'
    
    # Additional security checks
    if len(target) > 253:  # Maximum domain name length
        logger.error(f"Target too long: {len(target)} characters")
        raise ValueError("Target exceeds maximum length")
    
    # Check for suspicious patterns
    suspicious_patterns = [
        r'[<>"\']',  # HTML/SQL injection attempts
        r'\.\./',    # Directory traversal
        r'[;&|]',    # Command injection
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, target):
            logger.error(f"Suspicious pattern detected in target: {target}")
            raise ValueError("Target contains invalid characters")
    
    if not (re.match(ip_pattern, target) or re.match(domain_pattern, target)):
        logger.error(f"Invalid IP or domain format: {target}")
        raise ValueError("Invalid IP or domain format")
    
    return target

def fetch_cves(product: str, version: str, proxies: Optional[Dict], api_key: Optional[str] = None) -> List[Dict]:
    """Enhanced CVE fetching with multiple sources and comprehensive data
    
    Note: This function maintains backward compatibility while using enhanced backend
    """
    try:
        manager = get_multi_source_manager(api_key)
        stealth_mgr = get_stealth_manager(proxies is not None)
        
        # Apply stealth timing if using proxies
        stealth_mgr.wait_if_needed()
        
        # Get headers for request
        headers = stealth_mgr.get_headers()
        
        # Fetch comprehensive CVE data
        cve_infos = manager.fetch_comprehensive_cves(
            product, version, 
            proxies=proxies, 
            headers=headers
        )
        
        # Convert to backward-compatible format
        compatible_cves = []
        for cve_info in cve_infos:
            compatible_cve = {
                'cve_id': cve_info.cve_id,
                'cvss_score': max(
                    cve_info.metrics.cvss_v3_score,
                    cve_info.metrics.cvss_v2_score
                ),
                'description': cve_info.description,
                'exploit': 'Available exploits found' if cve_info.exploit_available else 'Check Metasploit or Exploit-DB for modules',
                # Enhanced fields (backward compatible)
                'published_date': cve_info.published_date,
                'epss_score': cve_info.metrics.epss_score,
                'attack_vector': cve_info.metrics.attack_vector,
                'exploit_available': cve_info.exploit_available,
                'references': cve_info.references[:5],  # Limit for compatibility
                'cwe_ids': cve_info.cwe_ids[:3]  # Limit for compatibility
            }
            compatible_cves.append(compatible_cve)
        
        return compatible_cves
        
    except Exception as e:
        logger.error(f"Enhanced CVE fetch failed for {product} {version}: {e}")
        # Fallback to basic functionality
        return []

def cve_lookup(target: str, prior_findings: Dict[str, Any] = None, stealth: bool = False, 
               proxies: Optional[Dict[str, str]] = None, cache_file: Optional[str] = None, 
               api_key: Optional[str] = None) -> Dict[str, Any]:
    """Enhanced CVE lookup with comprehensive analysis and multi-source data"""
    try:
        target = sanitize_target(target)
        prior_findings = prior_findings or {}
        
        logger.info(f"Starting enhanced CVE lookup for {target}")
        
        # Initialize managers
        cache_mgr = get_cache_manager(cache_file)
        stealth_mgr = get_stealth_manager(stealth)
        risk_analyzer = get_risk_analyzer()
        
        # Check cache first
        cache_key = hashlib.md5(f"{target}:{json.dumps(prior_findings, sort_keys=True)}".encode()).hexdigest()
        cached_result = cache_mgr.get(cache_key)
        if cached_result:
            logger.debug(f"Using cached CVE lookup results for {target}")
            return cached_result
        
        # Clean expired cache entries
        cache_mgr.clear_expired()
        
        results = {
            'target': target,
            'services': [],
            'scan_metadata': {
                'timestamp': datetime.now().isoformat(),
                'stealth_mode': stealth,
                'data_sources': ['NVD', 'CVEDetails', 'EPSS'],
                'cache_used': False
            }
        }
        
        # Extract services from prior findings
        all_ports = []
        
        # From nmap scan
        nmap_ports = prior_findings.get('nmap_scan', {}).get('ports', [])
        all_ports.extend(nmap_ports)
        
        # From HTTP fingerprinting
        http_ports = prior_findings.get('http_fingerprint', {}).get('ports', [])
        all_ports.extend(http_ports)
        
        # From other potential sources
        for key, value in prior_findings.items():
            if isinstance(value, dict) and 'ports' in value:
                all_ports.extend(value.get('ports', []))
        
        # Process each service
        processed_services = set()  # Avoid duplicates
        
        for port_data in all_ports:
            # Extract service information with multiple fallbacks
            port = port_data.get('port', 0)
            
            # Try multiple ways to get product name
            product = (
                port_data.get('product') or 
                port_data.get('service') or
                (port_data.get('technologies', [{}])[0].get('name') if port_data.get('technologies') else None) or
                port_data.get('name', '')
            )
            
            # Try multiple ways to get version
            version = (
                port_data.get('version') or
                (port_data.get('technologies', [{}])[0].get('version') if port_data.get('technologies') else None) or
                port_data.get('ver', '')
            )
            
            # Create service identifier to avoid duplicates
            service_id = f"{port}:{product}:{version}"
            if service_id in processed_services:
                continue
            processed_services.add(service_id)
            
            if product and version and product.lower() not in ['unknown', 'none', '']:
                logger.debug(f"Processing {product} {version} on port {port}")
                
                # Apply stealth timing
                if stealth:
                    stealth_mgr.wait_if_needed()
                
                # Get enhanced headers
                headers = stealth_mgr.get_headers()
                
                # Fetch CVEs using enhanced backend
                cves = fetch_cves(product, version, proxies, api_key)
                
                if cves:
                    service_result = {
                        'port': port,
                        'product': product,
                        'version': version,
                        'cves': cves,
                        'service_info': {
                            'state': port_data.get('state', 'unknown'),
                            'protocol': port_data.get('protocol', 'tcp'),
                            'banner': port_data.get('banner', ''),
                            'extrainfo': port_data.get('extrainfo', '')
                        }
                    }
                    results['services'].append(service_result)
                    logger.debug(f"Found {len(cves)} CVEs for {product} {version} on port {port}")
                else:
                    logger.debug(f"No CVEs found for {product} {version} on port {port}")
        
        # Perform comprehensive risk analysis
        results['analysis'] = analyze_cve_findings(results['services'])
        
        # Add enhanced analysis
        enhanced_analysis = risk_analyzer.calculate_comprehensive_risk(
            results['services'], 
            {'target': target, 'prior_findings': prior_findings}
        )
        results['enhanced_analysis'] = enhanced_analysis
        
        # Add summary statistics
        total_cves = sum(len(s['cves']) for s in results['services'])
        results['summary'] = {
            'total_services_analyzed': len(results['services']),
            'total_cves_found': total_cves,
            'services_with_vulnerabilities': len([s for s in results['services'] if s['cves']]),
            'critical_cves': sum(1 for s in results['services'] for cve in s['cves'] if cve.get('cvss_score', 0) >= CVSS_CRITICAL),
            'high_cves': sum(1 for s in results['services'] for cve in s['cves'] if CVSS_HIGH <= cve.get('cvss_score', 0) < CVSS_CRITICAL),
            'exploitable_cves': sum(1 for s in results['services'] for cve in s['cves'] if cve.get('exploit_available', False)),
            'scan_duration': 'N/A'  # Could be calculated if timing is tracked
        }
        
        # Cache the results
        cache_mgr.set(cache_key, results, CVE_CACHE_TTL)
        
        logger.info(f"Enhanced CVE lookup completed for {target}: {total_cves} CVEs found across {len(results['services'])} services")
        return results
        
    except ValueError as e:
        logger.error(f"Input validation failed for {target}: {e}")
        raise
    except Exception as e:
        logger.error(f"Enhanced CVE lookup failed for {target}: {e}")
        raise RuntimeError(f"CVE lookup failed: {e}")

def analyze_cve_findings(services: List[Dict]) -> Dict[str, Any]:
    """Enhanced CVE findings analysis with backward compatibility"""
    if not services:
        return {
            'risk_score': 0,
            'risk_level': 'Low',
            'findings': []
        }
    
    # Calculate enhanced risk score
    risk_scores = []
    all_findings = []
    
    for service in services:
        cves = service.get('cves', [])
        if not cves:
            continue
            
        # Calculate service risk
        service_scores = []
        for cve in cves:
            cvss_score = cve.get('cvss_score', 0)
            epss_score = cve.get('epss_score', 0)
            exploit_multiplier = 1.5 if cve.get('exploit_available', False) else 1.0
            
            # Enhanced scoring with EPSS integration
            enhanced_score = (cvss_score * 0.8 + epss_score * 10 * 0.2) * exploit_multiplier
            service_scores.append(enhanced_score)
            
            # Convert to finding format
            finding = {
                'cve_id': cve['cve_id'],
                'cvss_score': cvss_score,
                'description': cve['description'],
                'service': f"{service['product']} {service['version']} (port {service['port']})",
                'exploit_available': cve.get('exploit_available', False),
                'attack_vector': cve.get('attack_vector', 'unknown'),
                'published_date': cve.get('published_date', ''),
                'references': cve.get('references', [])
            }
            all_findings.append(finding)
        
        if service_scores:
            # Calculate weighted average for service
            avg_service_score = statistics.mean(service_scores)
            risk_scores.append(avg_service_score)
    
    # Calculate overall risk score
    if risk_scores:
        overall_score = statistics.mean(risk_scores)
        
        # Apply severity multipliers
        critical_count = sum(1 for f in all_findings if f['cvss_score'] >= CVSS_CRITICAL)
        high_count = sum(1 for f in all_findings if f['cvss_score'] >= CVSS_HIGH)
        exploitable_count = sum(1 for f in all_findings if f['exploit_available'])
        
        # Boost score for multiple critical vulnerabilities
        if critical_count > 1:
            overall_score *= 1.3
        elif critical_count == 1:
            overall_score *= 1.2
        
        # Boost for exploitable vulnerabilities
        if exploitable_count > 0:
            overall_score *= (1.0 + min(exploitable_count * 0.1, 0.5))
        
    else:
        overall_score = 0
    
    # Determine risk level with enhanced thresholds
    if overall_score >= 9.0:
        risk_level = 'Critical'
    elif overall_score >= 7.0:
        risk_level = 'High'
    elif overall_score >= 4.0:
        risk_level = 'Medium'
    elif overall_score > 0:
        risk_level = 'Low'
    else:
        risk_level = 'Info'
    
    return {
        'risk_score': round(overall_score, 2),
        'risk_level': risk_level,
        'findings': all_findings,
        'statistics': {
            'total_cves': len(all_findings),
            'critical_cves': critical_count,
            'high_cves': high_count,
            'exploitable_cves': exploitable_count,
            'services_affected': len([s for s in services if s.get('cves')])
        }
    }

# Enhanced utility functions for advanced operations

def batch_cve_lookup(targets: List[str], **kwargs) -> Dict[str, Dict[str, Any]]:
    """Perform CVE lookup on multiple targets with optimized caching and rate limiting"""
    results = {}
    
    # Initialize stealth manager for batch operations
    stealth_mgr = get_stealth_manager(kwargs.get('stealth', False))
    
    logger.info(f"Starting batch CVE lookup for {len(targets)} targets")
    
    for i, target in enumerate(targets):
        try:
            logger.info(f"Processing target {i+1}/{len(targets)}: {target}")
            
            # Apply rate limiting for batch operations
            if i > 0:  # Don't delay for first target
                stealth_mgr.wait_if_needed()
            
            result = cve_lookup(target, **kwargs)
            results[target] = result
            
        except Exception as e:
            logger.error(f"Failed to process target {target}: {e}")
            results[target] = {
                'error': str(e),
                'target': target,
                'services': [],
                'analysis': {'risk_score': 0, 'risk_level': 'Unknown', 'findings': []}
            }
    
    # Generate batch summary
    batch_summary = generate_batch_summary(results)
    
    return {
        'targets': results,
        'batch_summary': batch_summary,
        'metadata': {
            'total_targets': len(targets),
            'successful_scans': len([r for r in results.values() if 'error' not in r]),
            'failed_scans': len([r for r in results.values() if 'error' in r]),
            'timestamp': datetime.now().isoformat()
        }
    }

def generate_batch_summary(results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Generate comprehensive summary for batch CVE lookup results"""
    successful_results = [r for r in results.values() if 'error' not in r]
    
    if not successful_results:
        return {
            'total_cves': 0,
            'highest_risk_target': None,
            'risk_distribution': {},
            'most_common_vulnerabilities': [],
            'recommendations': []
        }
    
    # Aggregate statistics
    total_cves = sum(r.get('summary', {}).get('total_cves_found', 0) for r in successful_results)
    total_critical = sum(r.get('summary', {}).get('critical_cves', 0) for r in successful_results)
    total_high = sum(r.get('summary', {}).get('high_cves', 0) for r in successful_results)
    total_exploitable = sum(r.get('summary', {}).get('exploitable_cves', 0) for r in successful_results)
    
    # Find highest risk target
    highest_risk_target = None
    highest_risk_score = 0
    
    for target, result in results.items():
        if 'error' not in result:
            risk_score = result.get('analysis', {}).get('risk_score', 0)
            if risk_score > highest_risk_score:
                highest_risk_score = risk_score
                highest_risk_target = target
    
    # Risk distribution
    risk_distribution = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    for result in successful_results:
        risk_level = result.get('analysis', {}).get('risk_level', 'Info')
        risk_distribution[risk_level] += 1
    
    # Most common vulnerabilities
    cve_counts = defaultdict(int)
    for result in successful_results:
        for finding in result.get('analysis', {}).get('findings', []):
            cve_counts[finding.get('cve_id', '')] += 1
    
    most_common_cves = sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Generate batch recommendations
    batch_recommendations = generate_batch_recommendations(successful_results, risk_distribution)
    
    return {
        'total_cves': total_cves,
        'total_critical': total_critical,
        'total_high': total_high,
        'total_exploitable': total_exploitable,
        'highest_risk_target': highest_risk_target,
        'highest_risk_score': highest_risk_score,
        'risk_distribution': risk_distribution,
        'most_common_vulnerabilities': [{'cve_id': cve, 'count': count} for cve, count in most_common_cves],
        'recommendations': batch_recommendations
    }

def generate_batch_recommendations(results: List[Dict[str, Any]], risk_distribution: Dict[str, int]) -> List[str]:
    """Generate recommendations for batch scan results"""
    recommendations = []
    
    # Critical recommendations
    if risk_distribution.get('Critical', 0) > 0:
        recommendations.append("EMERGENCY: Multiple systems have critical vulnerabilities - implement incident response procedures")
        recommendations.append("Isolate critical systems from network until patches can be applied")
    
    # High-risk recommendations
    if risk_distribution.get('High', 0) > 0:
        recommendations.append("HIGH PRIORITY: Coordinate patch management across all high-risk systems")
        recommendations.append("Implement network segmentation to limit lateral movement")
    
    # Infrastructure recommendations
    total_targets = len(results)
    if total_targets > 10:
        recommendations.append("Consider implementing centralized vulnerability management solution")
        recommendations.append("Establish automated patch deployment pipeline")
    
    # Monitoring recommendations
    recommendations.append("Deploy continuous monitoring across all scanned systems")
    recommendations.append("Establish vulnerability disclosure and incident response procedures")
    
    return recommendations

def export_cve_report(results: Dict[str, Any], format: str = 'json', output_file: Optional[str] = None) -> str:
    """Export CVE lookup results in various formats"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if format.lower() == 'json':
        content = json.dumps(results, indent=2, default=str)
        extension = 'json'
    elif format.lower() == 'csv':
        content = convert_to_csv(results)
        extension = 'csv'
    elif format.lower() == 'html':
        content = generate_html_report(results)
        extension = 'html'
    else:
        raise ValueError(f"Unsupported format: {format}")
    
    if output_file:
        output_path = Path(output_file)
    else:
        target = results.get('target', 'unknown')
        safe_target = re.sub(r'[^a-zA-Z0-9.-]', '_', target)
        output_path = Path(f"cve_report_{safe_target}_{timestamp}.{extension}")
    
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logger.info(f"CVE report exported to {output_path}")
        return str(output_path)
        
    except OSError as e:
        logger.error(f"Failed to export CVE report: {e}")
        raise RuntimeError(f"Export failed: {e}")

def convert_to_csv(results: Dict[str, Any]) -> str:
    """Convert CVE results to CSV format"""
    import csv
    from io import StringIO
    
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    header = [
        'Target', 'Service', 'Port', 'Product', 'Version', 'CVE_ID', 
        'CVSS_Score', 'Risk_Level', 'Exploit_Available', 'Attack_Vector',
        'Description', 'Published_Date'
    ]
    writer.writerow(header)
    
    # Write data
    target = results.get('target', '')
    for service in results.get('services', []):
        port = service.get('port', '')
        product = service.get('product', '')
        version = service.get('version', '')
        
        for cve in service.get('cves', []):
            row = [
                target,
                f"{product} {version}",
                port,
                product,
                version,
                cve.get('cve_id', ''),
                cve.get('cvss_score', ''),
                get_risk_level_from_score(cve.get('cvss_score', 0)),
                'Yes' if cve.get('exploit_available', False) else 'No',
                cve.get('attack_vector', ''),
                cve.get('description', '')[:100] + '...' if len(cve.get('description', '')) > 100 else cve.get('description', ''),
                cve.get('published_date', '')
            ]
            writer.writerow(row)
    
    return output.getvalue()

def get_risk_level_from_score(score: float) -> str:
    """Convert CVSS score to risk level"""
    if score >= CVSS_CRITICAL:
        return 'Critical'
    elif score >= CVSS_HIGH:
        return 'High'
    elif score >= CVSS_MEDIUM:
        return 'Medium'
    elif score > 0:
        return 'Low'
    else:
        return 'Info'

def generate_html_report(results: Dict[str, Any]) -> str:
    """Generate HTML report for CVE results"""
    target = results.get('target', 'Unknown')
    analysis = results.get('analysis', {})
    enhanced_analysis = results.get('enhanced_analysis', {})
    services = results.get('services', [])
    summary = results.get('summary', {})
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CVE Report - {target}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
            .risk-critical {{ background-color: #e74c3c; color: white; }}
            .risk-high {{ background-color: #f39c12; color: white; }}
            .risk-medium {{ background-color: #f1c40f; color: black; }}
            .risk-low {{ background-color: #27ae60; color: white; }}
            .risk-info {{ background-color: #3498db; color: white; }}
            .service-card {{ border: 1px solid #ddd; border-radius: 8px; margin: 10px 0; padding: 15px; }}
            .cve-item {{ border-left: 3px solid #3498db; padding: 10px; margin: 5px 0; background-color: #f8f9fa; }}
            .cve-critical {{ border-left-color: #e74c3c; }}
            .cve-high {{ border-left-color: #f39c12; }}
            .cve-medium {{ border-left-color: #f1c40f; }}
            .stat-box {{ display: inline-block; background-color: #ecf0f1; padding: 15px; margin: 10px; border-radius: 8px; text-align: center; }}
            .recommendations {{ background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 15px; margin: 20px 0; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>CVE Vulnerability Report</h1>
                <h2>Target: {target}</h2>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="risk-summary">
                <h3>Risk Assessment</h3>
                <div class="stat-box">
                    <h4>Overall Risk Level</h4>
                    <div class="risk-{analysis.get('risk_level', 'info').lower()}">
                        {analysis.get('risk_level', 'Unknown')}
                    </div>
                </div>
                <div class="stat-box">
                    <h4>Risk Score</h4>
                    <strong>{analysis.get('risk_score', 0)}/10</strong>
                </div>
                <div class="stat-box">
                    <h4>Total CVEs</h4>
                    <strong>{summary.get('total_cves_found', 0)}</strong>
                </div>
                <div class="stat-box">
                    <h4>Critical CVEs</h4>
                    <strong>{summary.get('critical_cves', 0)}</strong>
                </div>
                <div class="stat-box">
                    <h4>Exploitable CVEs</h4>
                    <strong>{summary.get('exploitable_cves', 0)}</strong>
                </div>
            </div>
    """
    
    # Add recommendations
    recommendations = enhanced_analysis.get('recommendations', [])
    if recommendations:
        html_content += """
            <div class="recommendations">
                <h3>🚨 Priority Recommendations</h3>
                <ul>
        """
        for rec in recommendations:
            html_content += f"<li>{rec}</li>"
        html_content += """
                </ul>
            </div>
        """
    
    # Add services and CVEs
    html_content += "<h3>Vulnerable Services</h3>"
    
    for service in services:
        cves = service.get('cves', [])
        if cves:
            html_content += f"""
            <div class="service-card">
                <h4>{service.get('product', 'Unknown')} {service.get('version', '')} (Port {service.get('port', 'Unknown')})</h4>
                <p><strong>CVEs Found:</strong> {len(cves)}</p>
            """
            
            for cve in cves:
                risk_class = get_risk_level_from_score(cve.get('cvss_score', 0)).lower()
                exploit_badge = "🔥 EXPLOIT AVAILABLE" if cve.get('exploit_available', False) else ""
                
                html_content += f"""
                <div class="cve-item cve-{risk_class}">
                    <h5>{cve.get('cve_id', 'Unknown')} - CVSS: {cve.get('cvss_score', 'N/A')} {exploit_badge}</h5>
                    <p>{cve.get('description', 'No description available')[:200]}...</p>
                    <small>Attack Vector: {cve.get('attack_vector', 'Unknown')} | Published: {cve.get('published_date', 'Unknown')}</small>
                </div>
                """
            
            html_content += "</div>"
    
    # Add priority CVEs table
    priority_cves = enhanced_analysis.get('priority_cves', [])
    if priority_cves:
        html_content += """
        <h3>🎯 Priority CVEs (Immediate Action Required)</h3>
        <table>
            <tr>
                <th>CVE ID</th>
                <th>Priority Score</th>
                <th>CVSS Score</th>
                <th>Exploit Available</th>
                <th>Attack Vector</th>
                <th>Description</th>
            </tr>
        """
        
        for cve in priority_cves[:10]:  # Show top 10
            html_content += f"""
            <tr>
                <td>{cve.get('cve_id', 'N/A')}</td>
                <td>{cve.get('priority_score', 'N/A')}</td>
                <td>{cve.get('cvss_score', 'N/A')}</td>
                <td>{'Yes' if cve.get('exploit_available', False) else 'No'}</td>
                <td>{cve.get('attack_vector', 'N/A')}</td>
                <td>{cve.get('description', 'N/A')}</td>
            </tr>
            """
        
        html_content += "</table>"
    
    html_content += """
        </div>
    </body>
    </html>
    """
    
    return html_content

def get_cve_statistics(results: Dict[str, Any]) -> Dict[str, Any]:
    """Extract comprehensive statistics from CVE results"""
    services = results.get('services', [])
    analysis = results.get('analysis', {})
    enhanced_analysis = results.get('enhanced_analysis', {})
    
    if not services:
        return {
            'total_services': 0,
            'vulnerable_services': 0,
            'total_cves': 0,
            'severity_breakdown': {},
            'attack_vector_breakdown': {},
            'exploit_availability': {},
            'timeline_stats': {},
            'compliance_risk': 'Low'
        }
    
    # Basic statistics
    total_services = len(services)
    vulnerable_services = len([s for s in services if s.get('cves')])
    
    all_cves = []
    for service in services:
        all_cves.extend(service.get('cves', []))
    
    total_cves = len(all_cves)
    
    # Severity breakdown
    severity_breakdown = {
        'Critical': len([c for c in all_cves if c.get('cvss_score', 0) >= CVSS_CRITICAL]),
        'High': len([c for c in all_cves if CVSS_HIGH <= c.get('cvss_score', 0) < CVSS_CRITICAL]),
        'Medium': len([c for c in all_cves if CVSS_MEDIUM <= c.get('cvss_score', 0) < CVSS_HIGH]),
        'Low': len([c for c in all_cves if 0 < c.get('cvss_score', 0) < CVSS_MEDIUM]),
        'Info': len([c for c in all_cves if c.get('cvss_score', 0) == 0])
    }
    
    # Attack vector breakdown
    attack_vectors = defaultdict(int)
    for cve in all_cves:
        vector = cve.get('attack_vector', 'unknown').lower()
        attack_vectors[vector] += 1
    
    # Exploit availability
    exploitable_cves = len([c for c in all_cves if c.get('exploit_available', False)])
    
    # Timeline statistics
    timeline_stats = enhanced_analysis.get('timeline_analysis', {})
    
    return {
        'total_services': total_services,
        'vulnerable_services': vulnerable_services,
        'vulnerability_percentage': round((vulnerable_services / total_services) * 100, 2) if total_services > 0 else 0,
        'total_cves': total_cves,
        'severity_breakdown': severity_breakdown,
        'attack_vector_breakdown': dict(attack_vectors),
        'exploit_availability': {
            'exploitable_count': exploitable_cves,
            'exploitable_percentage': round((exploitable_cves / total_cves) * 100, 2) if total_cves > 0 else 0
        },
        'timeline_stats': timeline_stats,
        'compliance_risk': enhanced_analysis.get('compliance_impact', {}).get('risk_level', 'Low'),
        'business_impact': enhanced_analysis.get('business_impact', {}).get('impact_level', 'Low')
    }

# Cleanup function for proper resource management
def cleanup_resources():
    """Clean up global resources and connections"""
    global _cache_manager, _multi_source_manager, _risk_analyzer, _stealth_manager
    
    if _cache_manager and hasattr(_cache_manager, 'conn'):
        try:
            _cache_manager.conn.close()
        except:
            pass
    
    _cache_manager = None
    _multi_source_manager = None
    _risk_analyzer = None
    _stealth_manager = None
    
    logger.info("CVE lookup resources cleaned up")

# Register cleanup function for proper shutdown
import atexit
atexit.register(cleanup_resources)
