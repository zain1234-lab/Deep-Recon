import logging
import re
from typing import List, Optional, Callable, Dict, Any, Tuple
from pathlib import Path
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import time
import threading
import platform
import subprocess
import sys
import os

# Check if running on Kali Linux and import Scapy accordingly
try:
    from scapy.all import IP, TCP, UDP, ICMP, sr1, RandShort, fragment, conf
    SCAPY_AVAILABLE = True
    # Configure Scapy for Kali Linux
    conf.verb = 0  # Disable verbose output
    if platform.system().lower() == 'linux':
        conf.L3socket = conf.L3socket  # Use default L3 socket
except ImportError as e:
    SCAPY_AVAILABLE = False
    print(f"Warning: Scapy not available: {e}")
    print("Installing Scapy...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
        from scapy.all import IP, TCP, UDP, ICMP, sr1, RandShort, fragment, conf
        SCAPY_AVAILABLE = True
        conf.verb = 0
    except Exception as install_error:
        print(f"Failed to install Scapy: {install_error}")
        SCAPY_AVAILABLE = False

# Initialize logger
logger = logging.getLogger('recon_tool')

# Dynamic port lists - can be modified at runtime
DEFAULT_PORTS = [22, 80, 443, 3389, 21, 25, 110, 143, 445, 3306, 8080, 8443, 53, 135, 139, 993, 995, 1433, 3389, 5432, 5900, 6379, 27017]
COMMON_UDP_PORTS = [53, 67, 68, 123, 161, 162, 514, 1900, 5353, 69, 137, 138, 500, 4500, 1701]

# Dynamic scan configurations
SCAN_CONFIGS = {
    'fast': {'timeout': 1.0, 'max_workers': 100, 'delay_range': (0.01, 0.05)},
    'normal': {'timeout': 2.0, 'max_workers': 50, 'delay_range': (0.1, 0.5)},
    'slow': {'timeout': 5.0, 'max_workers': 20, 'delay_range': (0.5, 2.0)},
    'stealth': {'timeout': 3.0, 'max_workers': 10, 'delay_range': (1.0, 5.0)}
}

class PortScannerError(Exception):
    """Custom exception for port scanner errors"""
    pass

def check_root_privileges() -> bool:
    """Check if running with root privileges (required for raw sockets)"""
    return os.geteuid() == 0

def get_network_interface() -> str:
    """Dynamically get the default network interface"""
    try:
        if platform.system().lower() == 'linux':
            result = subprocess.run(['route', '-n'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if line.startswith('0.0.0.0'):
                    return line.split()[-1]
        return 'eth0'  # fallback
    except:
        return 'eth0'

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
    
    ip = ip.strip()
    # IPv4 validation
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    # IPv6 validation (basic)
    ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'
    
    if not (re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip)):
        logger.error(f"Invalid IP format: {ip}")
        raise ValueError(f"Invalid IP format: {ip}")
    
    return ip

def get_dynamic_timeout(port: int, scan_method: str) -> float:
    """Calculate dynamic timeout based on port and scan method"""
    base_timeout = 2.0
    
    # Well-known ports typically respond faster
    if port < 1024:
        base_timeout *= 0.8
    elif port > 49152:  # Dynamic/private ports
        base_timeout *= 1.5
    
    # Different scan methods have different timing requirements
    method_multipliers = {
        'TCP': 1.0,
        'SYN': 0.8,
        'UDP': 2.0,  # UDP needs more time
        'FIN': 1.2,
        'NULL': 1.2,
        'Xmas': 1.2
    }
    
    return base_timeout * method_multipliers.get(scan_method, 1.0)

def tcp_connect_scan(ip: str, port: int, **kwargs) -> Optional[int]:
    """TCP Connect Scan: Check if a single TCP port is open using socket.connect_ex.
    
    Args:
        ip: Target IP address
        port: Port number to scan (1-65535)
    
    Returns:
        Port number if open, None otherwise
    """
    timeout = kwargs.get('timeout', get_dynamic_timeout(port, 'TCP'))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                logger.debug(f"TCP Connect: Port {port} open on {ip}")
                return port
    except Exception as e:
        logger.debug(f"TCP Connect scan error on {ip}:{port}: {e}")
    return None

def syn_scan(ip: str, port: int, sport: int = None, **kwargs) -> Optional[int]:
    """SYN Scan: Send a SYN packet and check for SYN-ACK response.
    
    Args:
        ip: Target IP address
        port: Port number to scan (1-65535)
        sport: Source port for spoofing (e.g., 53 for DNS)
    
    Returns:
        Port number if open, None otherwise
    """
    if not SCAPY_AVAILABLE:
        logger.warning("Scapy not available, falling back to TCP connect scan")
        return tcp_connect_scan(ip, port, **kwargs)
    
    if not check_root_privileges():
        logger.warning("Root privileges required for SYN scan, falling back to TCP connect")
        return tcp_connect_scan(ip, port, **kwargs)
    
    timeout = kwargs.get('timeout', get_dynamic_timeout(port, 'SYN'))
    sport = sport or random.randint(1024, 65535)
    
    try:
        # Dynamic packet construction
        packet_options = []
        if kwargs.get('stealth', False):
            packet_options = [('Timestamp', (int(time.time()), 0))]
        
        packet = IP(dst=ip, id=random.randint(1, 65535)) / TCP(
            sport=sport, 
            dport=port, 
            flags="S", 
            seq=random.randint(1, 4294967295),
            options=packet_options
        )
        
        if kwargs.get('stealth', False) and kwargs.get('fragment', False):
            packets = fragment(packet, fragsize=8)
            response = sr1(packets[0], timeout=timeout, verbose=0)
        else:
            response = sr1(packet, timeout=timeout, verbose=0)
        
        if response and response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)
            if tcp_layer.flags == 0x12:  # SYN-ACK
                logger.debug(f"SYN Scan: Port {port} open on {ip}")
                return port
    except Exception as e:
        logger.debug(f"SYN scan error on {ip}:{port}: {e}")
    return None

def udp_scan(ip: str, port: int, sport: int = None, **kwargs) -> Optional[int]:
    """UDP Scan: Send a UDP packet and check for responses.
    
    Args:
        ip: Target IP address
        port: Port number to scan (1-65535)
        sport: Source port for spoofing
    
    Returns:
        Port number if open (or potentially filtered), None otherwise
    """
    if not SCAPY_AVAILABLE:
        logger.warning("Scapy not available, skipping UDP scan")
        return None
    
    timeout = kwargs.get('timeout', get_dynamic_timeout(port, 'UDP'))
    sport = sport or random.randint(1024, 65535)
    
    try:
        # Dynamic payload based on port
        payload = b""
        if port == 53:  # DNS
            payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01"
        elif port == 161:  # SNMP
            payload = b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63"
        
        packet = IP(dst=ip, id=random.randint(1, 65535)) / UDP(sport=sport, dport=port) / payload
        
        if kwargs.get('stealth', False) and kwargs.get('fragment', False):
            packets = fragment(packet, fragsize=8)
            response = sr1(packets[0], timeout=timeout, verbose=0)
        else:
            response = sr1(packet, timeout=timeout, verbose=0)
        
        if response:
            if response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                if icmp_layer.type == 3 and icmp_layer.code == 3:  # Port unreachable
                    return None
            logger.debug(f"UDP Scan: Port {port} open/filtered on {ip}")
            return port
        else:
            # No response could mean open or filtered
            logger.debug(f"UDP Scan: Port {port} open/filtered (no response) on {ip}")
            return port
    except Exception as e:
        logger.debug(f"UDP scan error on {ip}:{port}: {e}")
    return None

def fin_scan(ip: str, port: int, sport: int = None, **kwargs) -> Optional[int]:
    """FIN Scan: Send a FIN packet and check for responses.
    
    Args:
        ip: Target IP address
        port: Port number to scan (1-65535)
        sport: Source port for spoofing
    
    Returns:
        Port number if open or filtered, None otherwise
    """
    if not SCAPY_AVAILABLE:
        logger.warning("Scapy not available, skipping FIN scan")
        return None
    
    timeout = kwargs.get('timeout', get_dynamic_timeout(port, 'FIN'))
    sport = sport or random.randint(1024, 65535)
    
    try:
        packet_options = []
        if kwargs.get('stealth', False):
            packet_options = [('Timestamp', (int(time.time()), 0))]
        
        packet = IP(dst=ip, id=random.randint(1, 65535)) / TCP(
            sport=sport, 
            dport=port, 
            flags="F", 
            seq=random.randint(1, 4294967295),
            options=packet_options
        )
        
        response = sr1(packet, timeout=timeout, verbose=0)
        
        # No response or non-RST response indicates open/filtered
        if not response or not (response.haslayer(TCP) and response.getlayer(TCP).flags & 0x04):  # RST flag
            logger.debug(f"FIN Scan: Port {port} open/filtered on {ip}")
            return port
    except Exception as e:
        logger.debug(f"FIN scan error on {ip}:{port}: {e}")
    return None

def null_scan(ip: str, port: int, sport: int = None, **kwargs) -> Optional[int]:
    """NULL Scan: Send a NULL (no flags) TCP packet and check for responses.
    
    Args:
        ip: Target IP address
        port: Port number to scan (1-65535)
        sport: Source port for spoofing
    
    Returns:
        Port number if open or filtered, None otherwise
    """
    if not SCAPY_AVAILABLE:
        logger.warning("Scapy not available, skipping NULL scan")
        return None
    
    timeout = kwargs.get('timeout', get_dynamic_timeout(port, 'NULL'))
    sport = sport or random.randint(1024, 65535)
    
    try:
        packet_options = []
        if kwargs.get('stealth', False):
            packet_options = [('Timestamp', (int(time.time()), 0))]
        
        packet = IP(dst=ip, id=random.randint(1, 65535)) / TCP(
            sport=sport, 
            dport=port, 
            flags="", 
            seq=random.randint(1, 4294967295),
            options=packet_options
        )
        
        response = sr1(packet, timeout=timeout, verbose=0)
        
        # No response or non-RST response indicates open/filtered
        if not response or not (response.haslayer(TCP) and response.getlayer(TCP).flags & 0x04):  # RST flag
            logger.debug(f"NULL Scan: Port {port} open/filtered on {ip}")
            return port
    except Exception as e:
        logger.debug(f"NULL scan error on {ip}:{port}: {e}")
    return None

def xmas_scan(ip: str, port: int, sport: int = None, **kwargs) -> Optional[int]:
    """Xmas Scan: Send a TCP packet with FIN+PSH+URG flags and check for responses.
    
    Args:
        ip: Target IP address
        port: Port number to scan (1-65535)
        sport: Source port for spoofing
    
    Returns:
        Port number if open or filtered, None otherwise
    """
    if not SCAPY_AVAILABLE:
        logger.warning("Scapy not available, skipping Xmas scan")
        return None
    
    timeout = kwargs.get('timeout', get_dynamic_timeout(port, 'Xmas'))
    sport = sport or random.randint(1024, 65535)
    
    try:
        packet_options = []
        if kwargs.get('stealth', False):
            packet_options = [('Timestamp', (int(time.time()), 0))]
        
        packet = IP(dst=ip, id=random.randint(1, 65535)) / TCP(
            sport=sport, 
            dport=port, 
            flags="FPU", 
            seq=random.randint(1, 4294967295),
            options=packet_options
        )
        
        response = sr1(packet, timeout=timeout, verbose=0)
        
        # No response or non-RST response indicates open/filtered
        if not response or not (response.haslayer(TCP) and response.getlayer(TCP).flags & 0x04):  # RST flag
            logger.debug(f"Xmas Scan: Port {port} open/filtered on {ip}")
            return port
    except Exception as e:
        logger.debug(f"Xmas scan error on {ip}:{port}: {e}")
    return None

# Dynamic mapping of scan methods to their respective functions
SCAN_METHODS = {
    'TCP': tcp_connect_scan,
    'SYN': syn_scan,
    'UDP': udp_scan,
    'FIN': fin_scan,
    'NULL': null_scan,
    'Xmas': xmas_scan,
}

def get_port_range(port_spec: str) -> List[int]:
    """Parse port specification into list of ports.
    
    Args:
        port_spec: Port specification (e.g., "80,443,8000-8080")
    
    Returns:
        List of port numbers
    """
    ports = []
    for part in port_spec.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(list(set(ports)))

def scan_ports(ip: str, ports: List[int] = None, stealth: bool = False, deep_scan: bool = False, 
              cache_file: Optional[str] = None, scan_method: str = 'TCP', randomize_order: bool = False, 
              sport: int = None, scan_config: str = 'normal', custom_timeout: float = None,
              fragment: bool = False, max_workers: int = None) -> List[int]:
    """Scan TCP/UDP ports on a target IP with various methods.
    
    Args:
        ip: Target IP address
        ports: List of ports to scan (default: common ports)
        stealth: If True, adds random delays, source port spoofing, and packet mutation
        deep_scan: If True, scans all TCP ports (1-65535)
        cache_file: Optional path to cache scan results
        scan_method: Scan method to use ('TCP', 'SYN', 'UDP', 'FIN', 'NULL', 'Xmas')
        randomize_order: If True, randomizes the order of ports
        sport: Source port for spoofing (e.g., 53 for DNS)
        scan_config: Scan speed configuration ('fast', 'normal', 'slow', 'stealth')
        custom_timeout: Custom timeout override
        fragment: Enable packet fragmentation for stealth
        max_workers: Override maximum worker threads
    
    Returns:
        List of open ports
        
    Raises:
        ValueError: If IP or ports are invalid
        PortScannerError: If port scanning fails
    """
    try:
        ip = sanitize_ip(ip)
        logger.info(f"Starting {scan_method} port scan on {ip}")
        
        if scan_method not in SCAN_METHODS:
            raise ValueError(f"Unknown scan_method: {scan_method}. Available: {list(SCAN_METHODS.keys())}")
        
        scan_func = SCAN_METHODS[scan_method]
        
        # Get scan configuration
        config = SCAN_CONFIGS.get(scan_config, SCAN_CONFIGS['normal'])
        timeout = custom_timeout or config['timeout']
        workers = max_workers or config['max_workers']
        delay_range = config['delay_range']
        
        # Determine ports to scan dynamically
        if deep_scan:
            ports = list(range(1, 65536))
            logger.warning(f"Deep scan enabled: scanning all 65535 ports on {ip}")
            workers = min(workers, 100)  # Limit for deep scans
        elif ports is None:
            ports = COMMON_UDP_PORTS if scan_method == 'UDP' else DEFAULT_PORTS
            logger.debug(f"Using default ports: {len(ports)} ports")
        else:
            logger.debug(f"Scanning {len(ports)} specified ports")
        
        if randomize_order and ports:
            ports = ports.copy()
            random.shuffle(ports)
            logger.debug("Randomized port order for stealth")
        
        # Check cache if provided
        cache_key = f"{ip}_{scan_method}_{deep_scan}_{sorted(ports) if not deep_scan else 'all'}"
        if cache_file:
            cache_path = Path(cache_file).resolve()
            try:
                if cache_path.exists():
                    with open(cache_path, 'r', encoding='utf-8') as f:
                        cached_data = json.load(f)
                        if cached_data.get('cache_key') == cache_key:
                            cache_age = time.time() - cached_data.get('timestamp', 0)
                            if cache_age < 3600:  # Cache valid for 1 hour
                                logger.info(f"Using cached results (age: {cache_age:.0f}s)")
                                return cached_data['open_ports']
            except (OSError, json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Cache read failed: {e}")
        
        # Perform the scan
        open_ports = []
        scan_start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            # Submit all scan tasks
            future_to_port = {
                executor.submit(
                    scan_func, ip, port, 
                    sport=sport, 
                    stealth=stealth, 
                    timeout=timeout,
                    fragment=fragment
                ): port for port in ports
            }
            
            # Process results as they complete
            for i, future in enumerate(as_completed(future_to_port)):
                if stealth or scan_config == 'stealth':
                    time.sleep(random.uniform(*delay_range))
                
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        logger.info(f"Found open port: {result}/{scan_method.lower()}")
                except Exception as e:
                    logger.debug(f"Scan error on port {port}: {e}")
                
                # Progress logging for large scans
                if i % 1000 == 0 and deep_scan:
                    progress = (i / len(ports)) * 100
                    logger.info(f"Scan progress: {progress:.1f}% ({i}/{len(ports)})")
        
        open_ports = sorted(open_ports)
        scan_duration = time.time() - scan_start_time
        logger.info(f"Scan completed in {scan_duration:.2f}s: {len(open_ports)} open ports found")
        
        # Cache results
        if cache_file and open_ports:
            try:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                cache_data = {
                    'cache_key': cache_key,
                    'ip': ip,
                    'scan_method': scan_method,
                    'deep_scan': deep_scan,
                    'open_ports': open_ports,
                    'timestamp': time.time(),
                    'scan_duration': scan_duration
                }
                with open(cache_path, 'w', encoding='utf-8') as f:
                    json.dump(cache_data, f, indent=2)
                logger.debug(f"Results cached to {cache_path}")
            except OSError as e:
                logger.warning(f"Cache write failed: {e}")
        
        return open_ports
    
    except ValueError as e:
        raise
    except Exception as e:
        logger.error(f"Port scan failed for {ip}: {e}")
        raise PortScannerError(f"Port scan failed: {e}")

def get_scan_recommendations(ip: str) -> Dict[str, Any]:
    """Get dynamic scan recommendations based on target IP"""
    recommendations = {
        'scan_method': 'TCP',
        'stealth': False,
        'scan_config': 'normal',
        'max_workers': 50
    }
    
    try:
        # Check if target is local network
        import ipaddress
        target_ip = ipaddress.ip_address(ip)
        if target_ip.is_private:
            recommendations.update({
                'scan_method': 'SYN',
                'stealth': False,
                'scan_config': 'fast',
                'max_workers': 100
            })
        else:
            recommendations.update({
                'scan_method': 'SYN',
                'stealth': True,
                'scan_config': 'stealth',
                'max_workers': 20
            })
    except:
        pass
    
    return recommendations

if __name__ == '__main__':
    # Configure logging for standalone testing
    try:
        from utils import setup_logging
        logger = setup_logging('DEBUG')
    except ImportError:
        logging.basicConfig(level=logging.DEBUG)
        logger = logging.getLogger('recon_tool')
    
    print("=== Dynamic Port Scanner for Kali Linux ===")
    print(f"Scapy Available: {SCAPY_AVAILABLE}")
    print(f"Root Privileges: {check_root_privileges()}")
    print(f"Network Interface: {get_network_interface()}")
    print()
    
    # Interactive scan type selection
    print("Choose scan type:")
    print("1. Smart scan (auto-detect best method)")
    print("2. Fast TCP scan")
    print("3. Stealthy SYN scan")
    print("4. Deep scan (all ports)")
    print("5. UDP scan")
    print("6. Custom scan")
    
    try:
        choice = int(input("Enter choice (1-6): "))
        if choice not in range(1, 7):
            raise ValueError("Invalid choice")
    except ValueError as e:
        logger.error(f"Invalid input: {e}")
        sys.exit(1)
    
    # Get target IP
    test_ip = input("Enter Target IP: ").strip()
    if not test_ip:
        logger.error("No IP provided")
        sys.exit(1)
    
    try:
        cache_file = f'reports/port_scan_cache/{test_ip.replace(".", "_").replace(":", "_")}.json'
        
        if choice == 1:
            # Smart scan with recommendations
            recommendations = get_scan_recommendations(test_ip)
            logger.info(f"Using recommendations: {recommendations}")
            result = scan_ports(
                test_ip,
                cache_file=cache_file,
                **recommendations
            )
        elif choice == 2:
            # Fast TCP scan
            result = scan_ports(
                test_ip,
                scan_method='TCP',
                scan_config='fast',
                cache_file=cache_file
            )
        elif choice == 3:
            # Stealthy SYN scan
            result = scan_ports(
                test_ip,
                scan_method='SYN',
                stealth=True,
                randomize_order=True,
                sport=53,
                scan_config='stealth',
                fragment=True,
                cache_file=cache_file
            )
        elif choice == 4:
            # Deep scan
            result = scan_ports(
                test_ip,
                scan_method='SYN',
                deep_scan=True,
                stealth=True,
                scan_config='normal',
                cache_file=cache_file
            )
        elif choice == 5:
            # UDP scan
            result = scan_ports(
                test_ip,
                ports=COMMON_UDP_PORTS,
                scan_method='UDP',
                stealth=True,
                scan_config='slow',
                cache_file=cache_file
            )
        else:
            # Custom scan
            method = input("Scan method (TCP/SYN/UDP/FIN/NULL/Xmas): ").upper()
            if method not in SCAN_METHODS:
                method = 'TCP'
            
            port_input = input("Ports (comma-separated or range, e.g., 80,443,8000-8080): ").strip()
            if port_input:
                custom_ports = get_port_range(port_input)
            else:
                custom_ports = None
            
            result = scan_ports(
                test_ip,
                ports=custom_ports,
                scan_method=method,
                stealth=True,
                randomize_order=True,
                cache_file=cache_file
            )
        
        # Display results
        print(f"\n=== Scan Results for {test_ip} ===")
        if result:
            print(f"Open ports found: {len(result)}")
            for port in result:
                print(f"  {port}/tcp")
        else:
            print("No open ports found")
        
        # Save results to file
        results_file = f'reports/port_scan_results_{test_ip.replace(".", "_").replace(":", "_")}_{int(time.time())}.json'
        Path(results_file).parent.mkdir(parents=True, exist_ok=True)
        with open(results_file, 'w') as f:
            json.dump({
                'target': test_ip,
                'timestamp': time.time(),
                'open_ports': result,
                'scan_method': locals().get('method', 'various')
            }, f, indent=2)
        print(f"Results saved to: {results_file}")
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)
