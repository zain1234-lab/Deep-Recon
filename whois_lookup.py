import asyncio
import logging
import re
import time
import random
import requests
from typing import Dict, Optional, Any, List, Union, Tuple
from pathlib import Path
import json
import hashlib
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import ssl
import subprocess
import sys
import whois
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import dns.resolver
import dns.reversename
import tldextract

try:
    import whois
    import python_whois
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import dns.resolver
    import dns.reversename
    import tldextract
    HAS_DEPENDENCIES = True
except ImportError as e:
    HAS_DEPENDENCIES = False
    MISSING_DEPS = str(e)

# Initialize logger
logger = logging.getLogger('enhanced_whois_tool')

@dataclass
class WhoisResult:
    """Structured WHOIS result data class."""
    domain: str
    registrar: str
    creation_date: Optional[str]
    expiration_date: Optional[str]
    updated_date: Optional[str]
    name_servers: List[str]
    emails: List[str]
    registrant: Optional[str]
    registrant_country: Optional[str]
    registrant_org: Optional[str]
    admin_contact: Optional[str]
    tech_contact: Optional[str]
    status: List[str]
    dnssec: Optional[str]
    whois_server: Optional[str]
    raw_data: Optional[str]
    lookup_timestamp: str
    lookup_method: str
    response_time_ms: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

class EnhancedWhoisLookup:
    """Enhanced WHOIS lookup class with multiple fallback methods."""
    
    def __init__(self, 
                 max_retries: int = 3,
                 timeout: int = 30,
                 rate_limit_delay: float = 1.0,
                 cache_ttl_hours: int = 24,
                 enable_async: bool = True):
        """
        Initialize the enhanced WHOIS lookup tool.
        
        Args:
            max_retries: Maximum number of retry attempts
            timeout: Timeout in seconds for each request
            rate_limit_delay: Delay between requests to avoid rate limiting
            cache_ttl_hours: Cache time-to-live in hours
            enable_async: Enable asynchronous operations
        """
        self.max_retries = max_retries
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self.cache_ttl_hours = cache_ttl_hours
        self.enable_async = enable_async
        self.session = self._create_session()
        self.last_request_time = 0
        
        # Fallback WHOIS servers for different TLDs
        self.whois_servers = {
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'info': 'whois.afilias.net',
            'biz': 'whois.neulevel.biz',
            'us': 'whois.nic.us',
            'uk': 'whois.nic.uk',
            'de': 'whois.denic.de',
            'fr': 'whois.afnic.fr',
            'it': 'whois.nic.it',
            'jp': 'whois.jprs.jp',
            'cn': 'whois.cnnic.cn',
            'ru': 'whois.tcinet.ru',
            'au': 'whois.auda.org.au',
            'ca': 'whois.cira.ca',
            'default': 'whois.iana.org'
        }
        
        if not HAS_DEPENDENCIES:
            logger.warning(f"Some dependencies are missing: {MISSING_DEPS}")
            logger.warning("Installing required packages...")
            self._install_dependencies()
    
    def _install_dependencies(self):
        """Attempt to install missing dependencies."""
        packages = [
            'python-whois',
            'whois',
            'requests',
            'dnspython',
            'tldextract'
        ]
        
        for package in packages:
            try:
                subprocess.check_call([
                    sys.executable, '-m', 'pip', 'install', package
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info(f"Successfully installed {package}")
            except subprocess.CalledProcessError:
                logger.error(f"Failed to install {package}")
    
    def _create_session(self) -> requests.Session:
        """Create a robust HTTP session with retry strategy."""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set user agents to avoid blocking
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        session.headers.update({
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        return session
    
    def sanitize_domain(self, domain: str) -> str:
        """
        Enhanced domain sanitization and validation.
        
        Args:
            domain: Domain name to validate
            
        Returns:
            Sanitized domain string
            
        Raises:
            ValueError: If domain is invalid
        """
        if not domain or not isinstance(domain, str):
            raise ValueError("Domain must be a non-empty string")
        
        # Remove protocol, www, and trailing slashes
        domain = re.sub(r'^https?://', '', domain.strip())
        domain = re.sub(r'^www\.', '', domain)
        domain = domain.rstrip('/')
        domain = domain.lower()
        
        # Extract domain using tldextract for better parsing
        try:
            extracted = tldextract.extract(domain)
            if not extracted.domain or not extracted.suffix:
                raise ValueError("Invalid domain format")
            domain = f"{extracted.domain}.{extracted.suffix}"
        except:
            # Fallback to regex validation
            if not re.match(r'^[a-z0-9][a-z0-9\-]{0,61}[a-z0-9](?:\.[a-z]{2,})+$', domain):
                raise ValueError("Invalid domain format")
        
        return domain
    
    def _rate_limit(self):
        """Implement rate limiting to avoid being blocked."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _get_cache_path(self, domain: str, cache_dir: Optional[str] = None) -> Path:
        """Generate cache file path."""
        if cache_dir is None:
            cache_dir = Path.home() / '.whois_cache'
        
        cache_path = Path(cache_dir)
        cache_path.mkdir(parents=True, exist_ok=True)
        
        # Create filename hash to avoid filesystem issues
        domain_hash = hashlib.md5(domain.encode()).hexdigest()
        return cache_path / f"{domain}_{domain_hash}.json"
    
    def _is_cache_valid(self, cache_file: Path) -> bool:
        """Check if cache file is still valid."""
        try:
            if not cache_file.exists():
                return False
            
            stat = cache_file.stat()
            age = datetime.now() - datetime.fromtimestamp(stat.st_mtime)
            return age < timedelta(hours=self.cache_ttl_hours)
        except:
            return False
    
    def _load_from_cache(self, domain: str, cache_dir: Optional[str] = None) -> Optional[WhoisResult]:
        """Load WHOIS data from cache."""
        try:
            cache_file = self._get_cache_path(domain, cache_dir)
            
            if not self._is_cache_valid(cache_file):
                return None
            
            with open(cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                logger.debug(f"Loaded cached WHOIS data for {domain}")
                return WhoisResult(**data)
        except Exception as e:
            logger.warning(f"Failed to load cache for {domain}: {e}")
            return None
    
    def _save_to_cache(self, result: WhoisResult, cache_dir: Optional[str] = None):
        """Save WHOIS data to cache."""
        try:
            cache_file = self._get_cache_path(result.domain, cache_dir)
            
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(result.to_dict(), f, indent=2, default=str)
            
            logger.debug(f"Cached WHOIS data for {result.domain}")
        except Exception as e:
            logger.warning(f"Failed to cache data for {result.domain}: {e}")
    
    def _whois_socket_query(self, domain: str, server: str) -> Optional[str]:
        """Perform raw WHOIS query using socket connection."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((server, 43))
                sock.send(f"{domain}\r\n".encode())
                
                response = b""
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                
                return response.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.warning(f"Socket WHOIS query failed for {domain} on {server}: {e}")
            return None
    
    def _get_tld_whois_server(self, domain: str) -> str:
        """Get the appropriate WHOIS server for the domain's TLD."""
        try:
            tld = domain.split('.')[-1].lower()
            return self.whois_servers.get(tld, self.whois_servers['default'])
        except:
            return self.whois_servers['default']
    
    def _parse_raw_whois(self, raw_data: str, domain: str) -> Dict[str, Any]:
        """Parse raw WHOIS data into structured format."""
        result = {
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'name_servers': [],
            'emails': [],
            'registrant': None,
            'registrant_country': None,
            'registrant_org': None,
            'admin_contact': None,
            'tech_contact': None,
            'status': [],
            'dnssec': None,
            'whois_server': None
        }
        
        lines = raw_data.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('%') or line.startswith('#'):
                continue
            
            # Parse various fields using regex patterns
            patterns = {
                'registrar': r'(?:registrar|sponsor):\s*(.+)',
                'creation_date': r'(?:creation|created|registered).*?:\s*(.+)',
                'expiration_date': r'(?:expir|expire).*?:\s*(.+)',
                'updated_date': r'(?:updated|last.modified|changed).*?:\s*(.+)',
                'name_servers': r'(?:name.?server|nserver).*?:\s*(.+)',
                'emails': r'[\w\.-]+@[\w\.-]+\.\w+',
                'registrant': r'(?:registrant|holder).*?:\s*(.+)',
                'status': r'(?:status|state):\s*(.+)',
                'dnssec': r'dnssec:\s*(.+)',
                'whois_server': r'whois.*?server:\s*(.+)'
            }
            
            for field, pattern in patterns.items():
                if field == 'emails':
                    emails = re.findall(pattern, line, re.IGNORECASE)
                    result['emails'].extend(emails)
                elif field in ['name_servers', 'status']:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match and match.group(1).strip():
                        result[field].append(match.group(1).strip())
                else:
                    if not result[field]:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            result[field] = match.group(1).strip()
        
        # Clean up lists
        result['emails'] = list(set(result['emails']))
        result['name_servers'] = list(set(result['name_servers']))
        result['status'] = list(set(result['status']))
        
        return result
    
    def _method_python_whois(self, domain: str, proxies: Optional[Dict] = None) -> Optional[WhoisResult]:
        """Use python-whois library."""
        try:
            import python_whois
            start_time = time.time()
            
            w = python_whois.get_whois(domain)
            response_time = (time.time() - start_time) * 1000
            
            return WhoisResult(
                domain=domain,
                registrar=w.get('registrar', ['N/A'])[0] if w.get('registrar') else 'N/A',
                creation_date=str(w.get('creation_date', [None])[0]) if w.get('creation_date') else None,
                expiration_date=str(w.get('expiration_date', [None])[0]) if w.get('expiration_date') else None,
                updated_date=str(w.get('updated_date', [None])[0]) if w.get('updated_date') else None,
                name_servers=w.get('name_servers', []),
                emails=w.get('emails', []),
                registrant=w.get('registrant', 'N/A'),
                registrant_country=w.get('country', 'N/A'),
                registrant_org=w.get('org', 'N/A'),
                admin_contact=w.get('admin', 'N/A'),
                tech_contact=w.get('tech', 'N/A'),
                status=w.get('status', []),
                dnssec=w.get('dnssec', 'N/A'),
                whois_server=w.get('whois_server', 'N/A'),
                raw_data=None,
                lookup_timestamp=datetime.now().isoformat(),
                lookup_method='python-whois',
                response_time_ms=response_time
            )
        except Exception as e:
            logger.warning(f"python-whois method failed for {domain}: {e}")
            return None
    
    def _method_whois_library(self, domain: str, proxies: Optional[Dict] = None) -> Optional[WhoisResult]:
        """Use whois library."""
        try:
            start_time = time.time()
            
            if proxies:
                w = whois.whois(domain, proxies=proxies)
            else:
                w = whois.whois(domain)
            
            response_time = (time.time() - start_time) * 1000
            
            # Handle both single values and lists
            def safe_get(data, key, default='N/A'):
                value = data.get(key, default)
                if isinstance(value, list) and value:
                    return value[0] if value[0] is not None else default
                return value if value is not None else default
            
            return WhoisResult(
                domain=domain,
                registrar=safe_get(w, 'registrar'),
                creation_date=str(safe_get(w, 'creation_date')),
                expiration_date=str(safe_get(w, 'expiration_date')),
                updated_date=str(safe_get(w, 'updated_date')),
                name_servers=w.get('name_servers', []) or [],
                emails=w.get('emails', []) or [],
                registrant=safe_get(w, 'registrant'),
                registrant_country=safe_get(w, 'country'),
                registrant_org=safe_get(w, 'org'),
                admin_contact=safe_get(w, 'admin'),
                tech_contact=safe_get(w, 'tech'),
                status=w.get('status', []) or [],
                dnssec=safe_get(w, 'dnssec'),
                whois_server=safe_get(w, 'whois_server'),
                raw_data=w.text if hasattr(w, 'text') else None,
                lookup_timestamp=datetime.now().isoformat(),
                lookup_method='whois-library',
                response_time_ms=response_time
            )
        except Exception as e:
            logger.warning(f"whois library method failed for {domain}: {e}")
            return None
    
    def _method_socket_whois(self, domain: str) -> Optional[WhoisResult]:
        """Use raw socket WHOIS query."""
        try:
            start_time = time.time()
            whois_server = self._get_tld_whois_server(domain)
            
            raw_data = self._whois_socket_query(domain, whois_server)
            if not raw_data:
                return None
            
            response_time = (time.time() - start_time) * 1000
            parsed_data = self._parse_raw_whois(raw_data, domain)
            
            return WhoisResult(
                domain=domain,
                registrar=parsed_data['registrar'],
                creation_date=parsed_data['creation_date'],
                expiration_date=parsed_data['expiration_date'],
                updated_date=parsed_data['updated_date'],
                name_servers=parsed_data['name_servers'],
                emails=parsed_data['emails'],
                registrant=parsed_data['registrant'],
                registrant_country=parsed_data['registrant_country'],
                registrant_org=parsed_data['registrant_org'],
                admin_contact=parsed_data['admin_contact'],
                tech_contact=parsed_data['tech_contact'],
                status=parsed_data['status'],
                dnssec=parsed_data['dnssec'],
                whois_server=parsed_data['whois_server'] or whois_server,
                raw_data=raw_data,
                lookup_timestamp=datetime.now().isoformat(),
                lookup_method='socket-whois',
                response_time_ms=response_time
            )
        except Exception as e:
            logger.warning(f"Socket WHOIS method failed for {domain}: {e}")
            return None
    
    def lookup(self, 
               domain: str, 
               proxies: Optional[Dict[str, str]] = None,
               cache_dir: Optional[str] = None,
               use_cache: bool = True,
               methods: Optional[List[str]] = None) -> WhoisResult:
        """
        Perform enhanced WHOIS lookup with multiple fallback methods.
        
        Args:
            domain: Target domain
            proxies: Optional proxy configuration
            cache_dir: Optional cache directory
            use_cache: Whether to use caching
            methods: List of methods to try ['python-whois', 'whois-library', 'socket']
            
        Returns:
            WhoisResult object
            
        Raises:
            ValueError: If domain is invalid
            RuntimeError: If all lookup methods fail
        """
        domain = self.sanitize_domain(domain)
        logger.info(f"Starting enhanced WHOIS lookup for {domain}")
        
        # Check cache first
        if use_cache:
            cached_result = self._load_from_cache(domain, cache_dir)
            if cached_result:
                logger.info(f"Returning cached WHOIS data for {domain}")
                return cached_result
        
        # Rate limiting
        self._rate_limit()
        
        # Define lookup methods in priority order
        if methods is None:
            methods = ['python-whois', 'whois-library', 'socket']
        
        method_map = {
            'python-whois': self._method_python_whois,
            'whois-library': self._method_whois_library,
            'socket': self._method_socket_whois
        }
        
        last_error = None
        
        for method in methods:
            if method not in method_map:
                logger.warning(f"Unknown method: {method}")
                continue
            
            try:
                logger.debug(f"Trying {method} method for {domain}")
                
                if method == 'socket':
                    result = method_map[method](domain)
                else:
                    result = method_map[method](domain, proxies)
                
                if result:
                    logger.info(f"Successfully retrieved WHOIS data for {domain} using {method}")
                    
                    # Cache the result
                    if use_cache:
                        self._save_to_cache(result, cache_dir)
                    
                    return result
                    
            except Exception as e:
                last_error = e
                logger.warning(f"Method {method} failed for {domain}: {e}")
                continue
        
        # If all methods failed
        error_msg = f"All WHOIS lookup methods failed for {domain}"
        if last_error:
            error_msg += f". Last error: {last_error}"
        
        logger.error(error_msg)
        raise RuntimeError(error_msg)
    
    async def lookup_async(self, 
                          domain: str, 
                          proxies: Optional[Dict[str, str]] = None,
                          cache_dir: Optional[str] = None,
                          use_cache: bool = True) -> WhoisResult:
        """Asynchronous WHOIS lookup."""
        loop = asyncio.get_event_loop()
        
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self.lookup, domain, proxies, cache_dir, use_cache)
            return await loop.run_in_executor(None, lambda: future.result())
    
    def batch_lookup(self, 
                    domains: List[str],
                    proxies: Optional[Dict[str, str]] = None,
                    cache_dir: Optional[str] = None,
                    use_cache: bool = True,
                    max_workers: int = 5) -> Dict[str, Union[WhoisResult, Exception]]:
        """
        Perform batch WHOIS lookups with concurrent processing.
        
        Args:
            domains: List of domains to lookup
            proxies: Optional proxy configuration
            cache_dir: Optional cache directory
            use_cache: Whether to use caching
            max_workers: Maximum concurrent workers
            
        Returns:
            Dictionary mapping domains to results or exceptions
        """
        results = {}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_domain = {
                executor.submit(self.lookup, domain, proxies, cache_dir, use_cache): domain
                for domain in domains
            }
            
            # Collect results
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    results[domain] = result
                    logger.info(f"Completed WHOIS lookup for {domain}")
                except Exception as e:
                    results[domain] = e
                    logger.error(f"Failed WHOIS lookup for {domain}: {e}")
        
        return results
    
    def get_dns_info(self, domain: str) -> Dict[str, Any]:
        """Get additional DNS information for the domain."""
        try:
            dns_info = {
                'A_records': [],
                'AAAA_records': [],
                'MX_records': [],
                'NS_records': [],
                'TXT_records': [],
                'CNAME_records': []
            }
            
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_info[f'{record_type}_records'] = [str(rdata) for rdata in answers]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                except Exception as e:
                    logger.debug(f"DNS query failed for {domain} {record_type}: {e}")
            
            return dns_info
        except Exception as e:
            logger.warning(f"Failed to get DNS info for {domain}: {e}")
            return {}

# Convenience functions for backward compatibility
def sanitize_domain(domain: str) -> str:
    """Sanitize domain using the enhanced class."""
    lookup_tool = EnhancedWhoisLookup()
    return lookup_tool.sanitize_domain(domain)

def get_whois(domain: str, 
              proxies: Optional[Dict[str, str]] = None, 
              cache_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Enhanced WHOIS lookup function with backward compatibility.
    
    Args:
        domain: Target domain
        proxies: Optional proxy configuration
        cache_file: Optional cache file (deprecated, use cache_dir instead)
        
    Returns:
        Dictionary containing WHOIS data
    """
    lookup_tool = EnhancedWhoisLookup()
    
    # Handle legacy cache_file parameter
    cache_dir = None
    if cache_file:
        cache_dir = str(Path(cache_file).parent)
    
    try:
        result = lookup_tool.lookup(domain, proxies, cache_dir)
        return result.to_dict()
    except Exception as e:
        logger.error(f"WHOIS lookup failed for {domain}: {e}")
        raise RuntimeError(f"WHOIS lookup failed: {e}")

# Main execution
if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('whois_lookup.log')
        ]
    )
    
    # Create enhanced lookup tool
    lookup_tool = EnhancedWhoisLookup(
        max_retries=3,
        timeout=30,
        rate_limit_delay=1.0,
        cache_ttl_hours=24
    )
    
    try:
        # Interactive mode
        if len(sys.argv) == 1:
            test_domain = input("Enter Target Domain: ").strip()
            if not test_domain:
                print("No domain provided. Exiting.")
                sys.exit(1)
            
            # Optional proxy configuration
            use_proxy = input("Use Tor proxy? (y/n): ").strip().lower() == 'y'
            proxies = None
            if use_proxy:
                proxies = {
                    'http': 'socks5h://127.0.0.1:9050',
                    'https': 'socks5h://127.0.0.1:9050'
                }
            
            print(f"\nPerforming WHOIS lookup for: {test_domain}")
            result = lookup_tool.lookup(test_domain, proxies=proxies)
            
            print("\n" + "="*60)
            print("WHOIS LOOKUP RESULTS")
            print("="*60)
            print(result.to_json())
            
            # Get DNS info
            print("\n" + "="*60)
            print("DNS INFORMATION")
            print("="*60)
            dns_info = lookup_tool.get_dns_info(test_domain)
            print(json.dumps(dns_info, indent=2))
        
        # Batch mode
        elif len(sys.argv) > 1:
            domains = sys.argv[1:]
            print(f"Performing batch WHOIS lookup for {len(domains)} domains...")
            
            results = lookup_tool.batch_lookup(domains, max_workers=3)
            
            for domain, result in results.items():
                print(f"\n{'='*60}")
                print(f"DOMAIN: {domain}")
                print('='*60)
                
                if isinstance(result, Exception):
                    print(f"ERROR: {result}")
                else:
                    print(result.to_json())
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Application error: {e}")
        print(f"Error: {e}")
        sys.exit(1)
