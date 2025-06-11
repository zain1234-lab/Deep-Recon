import logging
import re
from typing import Dict, List, Optional
from pathlib import Path
import json
import requests
import random
import time

# Initialize logger
logger = logging.getLogger('recon_tool')

def sanitize_domain(domain: str) -> str:
    """Sanitize and validate domain input.
    
    Args:
        domain: Domain name to validate (e.g., example.com)
    
    Returns:
        Sanitized domain string
        
    Raises:
        ValueError: If domain is invalid
    """
    if not domain or not isinstance(domain, str):
        logger.error("Invalid domain: empty or not a string")
        raise ValueError("Domain must be a non-empty string")
    
    # Basic domain validation
    domain = domain.strip().lower()
    if not re.match(r'^[a-z0-9][a-z0-9\-]{0,61}[a-z0-9](?:\.[a-z]{2,})+$', domain):
        logger.error(f"Invalid domain format: {domain}")
        raise ValueError("Invalid domain format")
    
    return domain

def fetch_subdomains(domain: str, proxies: Optional[Dict[str, str]] = None, stealth: bool = False, cache_file: Optional[str] = None) -> List[str]:
    """Fetch subdomains from crt.sh API.
    
    Args:
        domain: Target domain (e.g., example.com)
        proxies: Optional proxy configuration for stealth mode
        stealth: If True, adds delays and proxy routing
        cache_file: Optional path to cache subdomain results
        
    Returns:
        List of unique subdomains
        
    Raises:
        ValueError: If domain is invalid
        RuntimeError: If API query fails
    """
    try:
        domain = sanitize_domain(domain)
        logger.info(f"Fetching subdomains for {domain}")
        
        # Check cache if provided
        if cache_file:
            cache_path = Path(cache_file).resolve()
            try:
                if cache_path.exists():
                    with open(cache_path, 'r', encoding='utf-8') as f:
                        cached_data = json.load(f)
                        if cached_data.get('domain') == domain:
                            logger.debug(f"Using cached subdomains from {cache_path}")
                            return cached_data['subdomains']
            except (OSError, json.JSONDecodeError) as e:
                logger.warning(f"Failed to read subdomain cache: {e}")
        
        # Apply stealth delay if enabled
        if stealth:
            time.sleep(random.uniform(0.5, 3.0))
        
        # Query crt.sh API
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        try:
            response = requests.get(url, headers=headers, proxies=proxies, timeout=10, verify=True)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:
                logger.warning(f"Rate limit hit for crt.sh on {domain}. Consider increasing delay.")
            raise RuntimeError(f"HTTP error fetching subdomains: {e}")
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            logger.error(f"Network error fetching subdomains for {domain}: {e}")
            raise RuntimeError(f"Network error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching subdomains for {domain}: {e}")
            raise RuntimeError(f"Unexpected error: {e}")
        
        # Parse and deduplicate subdomains
        try:
            data = response.json()
            subdomains = set()
            for entry in data:
                name = entry.get('name_value', '').strip().lower()
                # Filter wildcards and invalid entries
                if name and not name.startswith('*') and re.match(r'^[a-z0-9][a-z0-9\-]*\.' + re.escape(domain) + '$', name):
                    subdomains.add(name)
            subdomains = sorted(list(subdomains))
            logger.info(f"Found {len(subdomains)} unique subdomains for {domain}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse crt.sh response for {domain}: {e}")
            raise RuntimeError(f"JSON parsing error: {e}")
        
        # Cache results if cache_file is provided
        if cache_file:
            try:
                cache_path.parent.mkdir(exist_ok=True)
                with open(cache_path, 'w', encoding='utf-8') as f:
                    json.dump({'domain': domain, 'subdomains': subdomains}, f, indent=2)
                logger.debug(f"Cached subdomains to {cache_path}")
            except OSError as e:
                logger.warning(f"Failed to write subdomain cache: {e}")
        
        return subdomains
    
    except ValueError as e:
        raise
    except Exception as e:
        logger.error(f"Subdomain enumeration failed for {domain}: {e}")
        raise RuntimeError(f"Subdomain enumeration failed: {e}")

if __name__ == '__main__':
    # Configure logging for standalone testing
    from utils import setup_logging
    logger = setup_logging('DEBUG')
    
    # Test the module
    try:
        test_domain = input("Enter domain :")
        proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
        result = fetch_subdomains(test_domain, proxies=proxies, stealth=True, cache_file='reports/subdomain_cache/example.com.json')
        logger.info(f"Subdomains: {json.dumps(result, indent=2)}")
    except Exception as e:
        logger.error(f"Test failed: {e}")
