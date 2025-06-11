import logging
import re
from typing import Dict, List, Optional
from pathlib import Path
import json
import socket
import requests
import random
import ipaddress
import time

# Initialize logger
logger = logging.getLogger('recon_tool')

# Common HTTP ports for specialized banner grabbing
HTTP_PORTS = [80, 443, 8080, 8443]

def sanitize_ip(ip: str) -> str:
    """Sanitize and validate IP address input.
    
    Args:
        ip: IP address to validate (e.g., 192.168.1.1)
    
    Returns:
        Sanitized IP string
        
    Raises:
        ValueError: If IP is invalid
    """
    if not ip or not isinstance(ip, str):
        logger.error("Invalid IP: empty or not a string")
        raise ValueError("IP must be a non-empty string")
    
    # Basic IP validation
    ip = ip.strip()
    if not re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', ip):
        logger.error(f"Invalid IP format: {ip}")
        raise ValueError("Invalid IP format")
    
    return ip

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

def grab_banner_socket(ip: str, port: int) -> Optional[str]:
    """Grab service banner using raw socket connection.
    
    Args:
        ip: Target IP address
        port: Port number to connect to
    
    Returns:
        Banner string if available, None otherwise
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)  # 2-second timeout
            s.connect((ip, port))
            # Send a basic HTTP GET for HTTP-like services, otherwise just read
            if port in HTTP_PORTS:
                s.send(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % ip.encode())
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else None
    except (socket.timeout, socket.gaierror, ConnectionRefusedError):
        logger.debug(f"Connection failed for {ip}:{port}")
        return None
    except Exception as e:
        logger.debug(f"Error grabbing banner from {ip}:{port}: {e}")
        return None

def grab_banner_http(ip: str, port: int, proxies: Optional[Dict[str, str]] = None) -> Optional[str]:
    """Grab HTTP banner using requests for HTTP services.
    
    Args:
        ip: Target IP address
        port: Port number (e.g., 80, 443)
        proxies: Optional proxy configuration for stealth mode
    
    Returns:
        HTTP banner (Server header) if available, None otherwise
    """
    try:
        protocol = 'https' if port == 443 or port == 8443 else 'http'
        url = f"{protocol}://{ip}:{port}"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, proxies=proxies, timeout=10, verify=False, allow_redirects=False)
        server = response.headers.get('Server', None)
        return server if server else None
    except requests.exceptions.RequestException as e:
        logger.debug(f"HTTP banner grab failed for {ip}:{port}: {e}")
        return None

def grab_banners(ip: str, ports: List[int], stealth: bool = False, proxies: Optional[Dict[str, str]] = None, cache_file: Optional[str] = None) -> Dict[int, str]:
    """Grab banners from multiple open ports.
    
    Args:
        ip: Target IP address
        ports: List of ports to grab banners from
        stealth: If True, adds delays for stealth mode
        proxies: Optional proxy configuration for HTTP ports
        cache_file: Optional path to cache banner results
        
    Returns:
        Dictionary mapping ports to their banners
        
    Raises:
        ValueError: If IP or ports are invalid
        RuntimeError: If banner grabbing fails
    """
    try:
        ip = sanitize_ip(ip)
        logger.info(f"Starting banner grabbing on {ip}")
        
        # Validate ports
        ports = [sanitize_port(p) for p in ports]
        
        # Check cache if provided
        if cache_file:
            cache_path = Path(cache_file).resolve()
            try:
                if cache_path.exists():
                    with open(cache_path, 'r', encoding='utf-8') as f:
                        cached_data = json.load(f)
                        if cached_data.get('ip') == ip and sorted(cached_data.get('ports', [])) == sorted(ports):
                            logger.debug(f"Using cached banner results from {cache_path}")
                            return cached_data['banners']
            except (OSError, json.JSONDecodeError) as e:
                logger.warning(f"Failed to read banner cache: {e}")
        
        # Grab banners
        banners = {}
        for port in ports:
            if stealth:
                time.sleep(random.uniform(0.5, 3.0))
            
            # Try HTTP banner grabbing for HTTP ports
            if port in HTTP_PORTS:
                banner = grab_banner_http(ip, port, proxies)
                if banner:
                    banners[port] = banner
                    logger.debug(f"HTTP banner for {ip}:{port}: {banner}")
                    continue
            
            # Fall back to socket-based banner grabbing
            banner = grab_banner_socket(ip, port)
            if banner:
                banners[port] = banner
                logger.debug(f"Banner for {ip}:{port}: {banner}")
        
        logger.info(f"Grabbed banners for {len(banners)} ports on {ip}")
        
        # Cache results if cache_file is provided
        if cache_file:
            try:
                cache_path.parent.mkdir(exist_ok=True)
                with open(cache_path, 'w', encoding='utf-8') as f:
                    json.dump({'ip': ip, 'ports': ports, 'banners': banners}, f, indent=2)
                logger.debug(f"Cached banner results to {cache_path}")
            except OSError as e:
                logger.warning(f"Failed to write banner cache: {e}")
        
        return banners
    
    except ValueError as e:
        raise
    except Exception as e:
        logger.error(f"Banner grabbing failed for {ip}: {e}")
        raise RuntimeError(f"Banner grabbing failed: {e}")

if __name__ == '__main__':
    # Configure logging for standalone testing
    from utils import setup_logging
    logger = setup_logging('DEBUG')
    ip=input("Enter Ip Address:")
    
    # Test the module
    try:
        test_ip = ip#'93.184.216.34'  # example.com
        test_ports = [80, 443]
        proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
        result = grab_banners(test_ip, test_ports, stealth=True, proxies=proxies, 
                             cache_file='reports/banner_cache/example.com.json')
        logger.info(f"Banners: {json.dumps(result, indent=2)}")
    except Exception as e:
        logger.error(f"Test failed: {e}")
