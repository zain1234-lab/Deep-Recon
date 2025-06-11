import logging
import re
from typing import Dict, List, Optional
from pathlib import Path
import json
import dns.resolver
import dns.exception

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

def query_dns(domain: str, proxies: Optional[Dict[str, str]] = None, cache_file: Optional[str] = None) -> Dict[str, List[str]]:
    """Query DNS records (A, NS, MX, TXT) for a domain.
    
    Args:
        domain: Target domain (e.g., example.com)
        proxies: Optional proxy configuration for stealth mode
        cache_file: Optional path to cache DNS results
        
    Returns:
        Dictionary with DNS record types and their values
        
    Raises:
        ValueError: If domain is invalid
        RuntimeError: If DNS query fails
    """
    try:
        domain = sanitize_domain(domain)
        logger.info(f"Performing DNS enumeration for {domain}")
        
        # Check cache if provided
        if cache_file:
            cache_path = Path(cache_file).resolve()
            try:
                if cache_path.exists():
                    with open(cache_path, 'r', encoding='utf-8') as f:
                        cached_data = json.load(f)
                        if cached_data.get('domain') == domain:
                            logger.debug(f"Using cached DNS data from {cache_path}")
                            return cached_data['records']
            except (OSError, json.JSONDecodeError) as e:
                logger.warning(f"Failed to read DNS cache: {e}")
        
        # Initialize resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0  # Set timeout to 5 seconds
        resolver.lifetime = 5.0
        if proxies:
            logger.debug("Proxies provided, but dnspython does not support proxies directly. Using system resolver.")
        
        # Query record types
        records = {'A': [], 'NS': [], 'MX': [], 'TXT': []}
        for rtype in records.keys():
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
                logger.debug(f"Found {len(records[rtype])} {rtype} records for {domain}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                logger.warning(f"No {rtype} records found for {domain}")
            except dns.exception.Timeout:
                logger.warning(f"Timeout querying {rtype} records for {domain}")
            except Exception as e:
                logger.error(f"Error querying {rtype} records for {domain}: {e}")
        
        # Cache results if cache_file is provided
        if cache_file:
            try:
                cache_path.parent.mkdir(exist_ok=True)
                with open(cache_path, 'w', encoding='utf-8') as f:
                    json.dump({'domain': domain, 'records': records}, f, indent=2)
                logger.debug(f"Cached DNS data to {cache_path}")
            except OSError as e:
                logger.warning(f"Failed to write DNS cache: {e}")
        
        logger.info(f"DNS enumeration completed for {domain}")
        return records
    
    except ValueError as e:
        raise
    except Exception as e:
        logger.error(f"DNS enumeration failed for {domain}: {e}")
        raise RuntimeError(f"DNS enumeration failed: {e}")

if __name__ == '__main__':
    # Configure logging for standalone testing
    from utils import setup_logging
    logger = setup_logging('DEBUG')
    domain=input("Enter domain URL: ")
    # Test the module
    try:
        test_domain = domain
        result = query_dns(test_domain, cache_file='reports/dns_cache/example.com.json')
        logger.info(f"DNS Result: {json.dumps(result, indent=2)}")
    except Exception as e:
        logger.error(f"Test failed: {e}")
