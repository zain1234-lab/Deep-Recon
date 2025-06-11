import logging
import re
import subprocess
import shlex
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import json
import random
import time
from prompt_toolkit import PromptSession
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.formatted_text import HTML
import requests
from itertools import chain

# Initialize logger
logger = logging.getLogger('recon_tool')

# Comprehensive Port-to-script mapping - dynamically expandable
PORT_SCRIPT_MAP = {
    21: [
        ('ftp-anon', 'Checks if FTP allows anonymous access'),
        ('ftp-bounce', 'Checks for FTP bounce attack vulnerability'),
        ('ftp-brute', 'Performs brute-force attack on FTP credentials'),
        ('ftp-vsftpd-backdoor', 'Checks for VSFTPD backdoor'),
    ],
    22: [
        ('ssh-auth-methods', 'Enumerates supported SSH authentication methods'),
        ('ssh-brute', 'Performs brute-force attack on SSH credentials'),
        ('ssh-hostkey', 'Retrieves SSH host keys'),
        ('ssh2-enum-algos', 'Enumerates SSH algorithms'),
        ('ssh-run', 'Runs commands on SSH server'),
    ],
    23: [
        ('telnet-brute', 'Performs brute-force attack on Telnet'),
        ('telnet-encryption', 'Checks Telnet encryption capabilities'),
    ],
    25: [
        ('smtp-commands', 'Enumerates SMTP commands'),
        ('smtp-enum-users', 'Enumerates SMTP users'),
        ('smtp-open-relay', 'Checks for SMTP open relay'),
        ('smtp-brute', 'Performs brute-force attack on SMTP'),
    ],
    53: [
        ('dns-zone-transfer', 'Attempts DNS zone transfer'),
        ('dns-recursion', 'Checks DNS recursion'),
        ('dns-cache-snoop', 'Performs DNS cache snooping'),
        ('dns-brute', 'Brute-forces DNS subdomains'),
    ],
    80: [
        ('http-title', 'Grabs HTTP page title'),
        ('http-enum', 'Enumerates directories and files on web server'),
        ('http-vuln-cve2017-5638', 'Checks for Struts RCE vulnerability'),
        ('http-methods', 'Enumerates HTTP methods'),
        ('http-robots.txt', 'Checks robots.txt file'),
        ('http-headers', 'Shows HTTP headers'),
        ('http-backup-finder', 'Finds backup files'),
        ('http-sql-injection', 'Tests for SQL injection'),
        ('http-shellshock', 'Tests for Shellshock vulnerability'),
    ],
    110: [
        ('pop3-brute', 'Performs brute-force attack on POP3'),
        ('pop3-capabilities', 'Enumerates POP3 capabilities'),
    ],
    111: [
        ('rpcinfo', 'Enumerates RPC services'),
        ('nfs-ls', 'Lists NFS exports'),
        ('nfs-showmount', 'Shows NFS mount information'),
    ],
    135: [
        ('msrpc-enum', 'Enumerates Microsoft RPC endpoints'),
        ('rpc-grind', 'Fingerprints RPC services'),
    ],
    139: [
        ('smb-enum-shares', 'Enumerates SMB shares'),
        ('smb-enum-users', 'Enumerates SMB users'),
        ('smb-brute', 'Performs brute-force attack on SMB credentials'),
        ('smb-os-discovery', 'Discovers SMB OS information'),
    ],
    143: [
        ('imap-brute', 'Performs brute-force attack on IMAP'),
        ('imap-capabilities', 'Enumerates IMAP capabilities'),
    ],
    161: [
        ('snmp-brute', 'Performs brute-force attack on SNMP'),
        ('snmp-info', 'Extracts SNMP information'),
        ('snmp-sysdescr', 'Gets SNMP system description'),
    ],
    389: [
        ('ldap-rootdse', 'Retrieves LDAP root DSE'),
        ('ldap-search', 'Performs LDAP searches'),
        ('ldap-brute', 'Performs brute-force attack on LDAP'),
    ],
    443: [
        ('ssl-cert', 'Retrieves SSL/TLS certificate details'),
        ('ssl-enum-ciphers', 'Enumerates SSL/TLS ciphers'),
        ('ssl-heartbleed', 'Checks for Heartbleed vulnerability'),
        ('ssl-poodle', 'Checks for POODLE vulnerability'),
        ('http-title', 'Grabs HTTPS page title'),
        ('http-enum', 'Enumerates directories and files on web server'),
        ('http-methods', 'Enumerates HTTP methods'),
        ('http-robots.txt', 'Checks robots.txt file'),
    ],
    445: [
        ('smb-vuln-ms17-010', 'Checks for EternalBlue vulnerability'),
        ('smb-vuln-ms08-067', 'Checks for MS08-067 vulnerability'),
        ('smb-vuln-cve2009-3103', 'Checks for SMBv2 vulnerability'),
        ('smb-enum-shares', 'Enumerates SMB shares'),
        ('smb-brute', 'Performs brute-force attack on SMB credentials'),
        ('smb-os-discovery', 'Discovers SMB OS information'),
        ('smb-security-mode', 'Gets SMB security mode'),
    ],
    993: [
        ('ssl-cert', 'Retrieves SSL/TLS certificate details'),
        ('imap-capabilities', 'Enumerates IMAP capabilities over SSL'),
    ],
    995: [
        ('ssl-cert', 'Retrieves SSL/TLS certificate details'),
        ('pop3-capabilities', 'Enumerates POP3 capabilities over SSL'),
    ],
    1433: [
        ('ms-sql-info', 'Gets Microsoft SQL Server information'),
        ('ms-sql-brute', 'Performs brute-force attack on MS SQL'),
        ('ms-sql-empty-password', 'Checks for empty passwords'),
    ],
    1521: [
        ('oracle-sid-brute', 'Brute-forces Oracle SIDs'),
        ('oracle-brute', 'Performs brute-force attack on Oracle'),
    ],
    2049: [
        ('nfs-ls', 'Lists NFS exports'),
        ('nfs-showmount', 'Shows NFS mount information'),
        ('nfs-statfs', 'Shows NFS filesystem statistics'),
    ],
    3306: [
        ('mysql-info', 'Gets MySQL server information'),
        ('mysql-brute', 'Performs brute-force attack on MySQL'),
        ('mysql-empty-password', 'Checks for empty passwords'),
        ('mysql-users', 'Enumerates MySQL users'),
    ],
    3389: [
        ('rdp-enum-encryption', 'Enumerates RDP encryption'),
        ('rdp-vuln-ms12-020', 'Checks for MS12-020 vulnerability'),
    ],
    5432: [
        ('pgsql-brute', 'Performs brute-force attack on PostgreSQL'),
        ('postgresql-info', 'Gets PostgreSQL server information'),
    ],
    5900: [
        ('vnc-info', 'Gets VNC server information'),
        ('vnc-brute', 'Performs brute-force attack on VNC'),
    ],
    6379: [
        ('redis-info', 'Gets Redis server information'),
        ('redis-brute', 'Performs brute-force attack on Redis'),
    ],
    8080: [
        ('http-title', 'Grabs HTTP page title'),
        ('http-enum', 'Enumerates directories and files on web server'),
        ('http-methods', 'Enumerates HTTP methods'),
        ('http-robots.txt', 'Checks robots.txt file'),
    ],
    27017: [
        ('mongodb-info', 'Gets MongoDB server information'),
        ('mongodb-brute', 'Performs brute-force attack on MongoDB'),
    ],
}

# Comprehensive Nmap flags with descriptions - dynamically expandable
NMAP_FLAGS = [
    # Scan techniques
    ('-sS', 'SYN scan (stealthy, fast)'),
    ('-sT', 'TCP connect scan (reliable)'),
    ('-sU', 'UDP scan (for UDP services)'),
    ('-sA', 'ACK scan (firewall rules)'),
    ('-sW', 'Window scan (firewall detection)'),
    ('-sM', 'Maimon scan (stealth scan)'),
    ('-sN', 'Null scan (stealth scan)'),
    ('-sF', 'FIN scan (stealth scan)'),
    ('-sX', 'Xmas scan (stealth scan)'),
    ('-sI', 'Idle scan (zombie host)'),
    ('-sY', 'SCTP INIT scan'),
    ('-sZ', 'SCTP COOKIE-ECHO scan'),
    
    # Host discovery
    ('-sn', 'Ping scan (no port scan)'),
    ('-Pn', 'No ping (assume host is up)'),
    ('-PS', 'TCP SYN ping'),
    ('-PA', 'TCP ACK ping'),
    ('-PU', 'UDP ping'),
    ('-PY', 'SCTP INIT ping'),
    ('-PE', 'ICMP echo ping'),
    ('-PP', 'ICMP timestamp ping'),
    ('-PM', 'ICMP netmask ping'),
    ('-PO', 'IP protocol ping'),
    
    # Port specification
    ('-p-', 'Scan all 65535 ports'),
    ('-F', 'Fast scan (top 100 ports)'),
    ('--top-ports', 'Scan top N ports'),
    
    # Service/version detection
    ('-sV', 'Service/version detection'),
    ('--version-intensity', 'Set version detection intensity (0-9)'),
    ('--version-light', 'Light mode (intensity 2)'),
    ('--version-all', 'All probes (intensity 9)'),
    ('--version-trace', 'Show version detection activity'),
    
    # OS detection
    ('-O', 'OS detection'),
    ('--osscan-limit', 'Limit OS detection to promising targets'),
    ('--osscan-guess', 'Guess OS more aggressively'),
    
    # Script scanning
    ('-sC', 'Default script scan'),
    ('--script', 'Run specific NSE scripts'),
    ('--script-args', 'Provide arguments to NSE scripts'),
    ('--script-trace', 'Show script execution trace'),
    ('--script-updatedb', 'Update script database'),
    
    # Aggressive options
    ('-A', 'Aggressive scan (includes -sV, -O, scripts)'),
    
    # Timing and performance
    ('-T0', 'Paranoid timing (very slow, stealthy)'),
    ('-T1', 'Sneaky timing (slow, stealthy)'),
    ('-T2', 'Polite timing (balanced stealth)'),
    ('-T3', 'Normal timing (default)'),
    ('-T4', 'Aggressive timing (fast)'),
    ('-T5', 'Insane timing (very fast, noisy)'),
    ('--host-timeout', 'Set timeout per host (e.g., 30m)'),
    ('--scan-delay', 'Delay between probes (e.g., 1s)'),
    ('--max-retries', 'Maximum retries for probes'),
    ('--min-rate', 'Minimum packet rate (packets/sec)'),
    ('--max-rate', 'Maximum packet rate (packets/sec)'),
    ('--min-parallelism', 'Minimum parallel probes'),
    ('--max-parallelism', 'Maximum parallel probes'),
    
    # Firewall/IDS evasion
    ('-f', 'Fragment packets'),
    ('--mtu', 'Set MTU size'),
    ('-D', 'Decoy scan (spoof source)'),
    ('-S', 'Spoof source address'),
    ('-g', 'Spoof source port'),
    ('--proxies', 'Use proxy chain'),
    ('--data-length', 'Append random data'),
    ('--ip-options', 'Send packets with IP options'),
    ('--ttl', 'Set IP time-to-live'),
    ('--spoof-mac', 'Spoof MAC address'),
    ('--badsum', 'Send packets with bad checksums'),
    
    # Output options (filtered for safety)
    ('-v', 'Verbose output'),
    ('-vv', 'Very verbose output'),
    ('-d', 'Debug output'),
    ('--reason', 'Show reason for port state'),
    ('--open', 'Show only open ports'),
    ('--packet-trace', 'Show packet trace'),
    ('--iflist', 'Show host interfaces'),
    ('--log-errors', 'Log errors to stderr'),
    
    # Miscellaneous
    ('-6', 'Enable IPv6 scanning'),
    ('--datadir', 'Specify custom data directory'),
    ('--send-eth', 'Send raw ethernet packets'),
    ('--send-ip', 'Send raw IP packets'),
    ('--privileged', 'Assume privileged user'),
    ('--unprivileged', 'Assume unprivileged user'),
    ('--release-memory', 'Release memory before quitting'),
]

def sanitize_target(target: str) -> str:
    """Validate and sanitize target (IP, CIDR, domain, or range).
    
    Args:
        target: IP, CIDR, domain, or range to validate
    
    Returns:
        Sanitized target
    
    Raises:
        ValueError: If target is invalid
    """
    if not target or not isinstance(target, str):
        logger.error("Invalid target: empty or not a string")
        raise ValueError("Target must be a non-empty string")
    
    target = target.strip().lower()
    if len(target) > 255:
        logger.error(f"Target too long: {target}")
        raise ValueError("Target exceeds maximum length")
    
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:3[0-2]|[12]?[0-9]))?$'
    ipv6_pattern = r'^(?:(?:[0-9a-fA-F]{1,4}:){0,7}(?::[0-9a-fA-F]{1,4}){1,7}|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}?|^::1$|^::$)'
    domain_pattern = r'^(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})$'
    ip_range_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)-(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    
    if not any(re.match(p, target) for p in [ipv4_pattern, ipv6_pattern, domain_pattern, ip_range_pattern]):
        logger.error(f"Invalid IP, CIDR, domain, or range: {target}")
        raise ValueError("Invalid target format")
    
    if re.match(ip_range_pattern, target):
        start, end = target.split('-')
        start_octet = int(start.split('.')[-1])
        end_octet = int(end)
        if end_octet < start_octet:
            raise ValueError("Invalid IP range: end must be greater than start")
    
    return target

def check_nmap() -> bool:
    """Check if Nmap is installed and accessible.
    
    Returns:
        True if Nmap is available, False otherwise
    """
    try:
        result = subprocess.run(
            ["nmap", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=10
        )
        version_info = result.stdout.strip()
        logger.debug(f"Nmap version: {version_info}")
        
        # Check if running as root/privileged for better scan capabilities
        try:
            import os
            if os.geteuid() != 0:
                logger.warning("Not running as root - some scan types may be limited")
        except AttributeError:
            pass  # Windows doesn't have geteuid
            
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.error(f"Nmap not found or not executable: {e}")
        return False

def get_nmap_scripts(port: int) -> List[Tuple[str, str]]:
    """Get relevant Nmap scripts for a given port.
    
    Args:
        port: Open port number
    
    Returns:
        List of (script_name, description) tuples
    """
    scripts = PORT_SCRIPT_MAP.get(port, [])
    
    # Add generic scripts that work on any port
    generic_scripts = [
        ('banner', 'Grabs service banner'),
        ('fingerprint-strings', 'Gets service fingerprint'),
    ]
    
    # Add vulnerability scripts for common ports
    if port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389]:
        generic_scripts.extend([
            ('vuln', 'Runs all vulnerability scripts'),
            ('exploit', 'Runs exploit scripts (use with caution)'),
        ])
    
    return scripts + generic_scripts

def build_nmap_menu(open_ports: List[int]) -> Dict[str, List[Tuple[str, str]]]:
    """Build interactive menu based on open ports.
    
    Args:
        open_ports: List of open ports from prior scans
    
    Returns:
        Dictionary with menu sections (scan_types, flags, scripts)
    """
    # Get unique scripts for all open ports
    all_scripts = []
    for port in open_ports:
        port_scripts = get_nmap_scripts(port)
        for script in port_scripts:
            if script not in all_scripts:
                all_scripts.append(script)
    
    menu = {
        'scan_types': [
            ('quick_scan', 'Quick TCP scan (top 1000 ports)'),
            ('full_tcp_scan', 'Full TCP scan (all 65535 ports)'),
            ('udp_scan', 'UDP port scan (top 1000 ports)'),
            ('stealth_scan', 'Stealth SYN scan'),
            ('connect_scan', 'TCP connect scan'),
            ('service_version', 'Service and version detection'),
            ('os_detection', 'Operating system detection'),
            ('aggressive', 'Aggressive scan (ports, services, OS, scripts)'),
            ('comprehensive', 'Comprehensive scan (TCP + UDP + scripts)'),
            ('vulnerability', 'Vulnerability assessment scan'),
            ('custom', 'Custom scan (specify your own flags)'),
        ],
        'timing': [
            ('paranoid', 'T0 - Paranoid (very slow, stealthy)'),
            ('sneaky', 'T1 - Sneaky (slow, stealthy)'),
            ('polite', 'T2 - Polite (balanced stealth)'),
            ('normal', 'T3 - Normal (default timing)'),
            ('aggressive', 'T4 - Aggressive (fast)'),
            ('insane', 'T5 - Insane (very fast, noisy)'),
        ],
        'flags': NMAP_FLAGS,
        'scripts': all_scripts,
    }
    return menu

def display_interactive_menu(menu: Dict[str, List[Tuple[str, str]]], open_ports: List[int]) -> None:
    """Display a classic interactive menu for Nmap options.
    
    Args:
        menu: Menu dictionary with options
        open_ports: List of open ports
    """
    def print_section(title: str, content: str) -> None:
        print(f"┌{'─' * (len(title) + 4)}┐")
        print(f"│  {title}  │")
        print(f"├{'─' * (len(title) + 4)}┴{'─' * 50}")
        print(content.strip())
        print(f"└{'─' * 54}\n")
    
    banner = """
    ╔══════════════════════════════════════╗
    ║       NMAP INTERACTIVE SCANNER       ║
    ╚══════════════════════════════════════╝
    """
    print(banner)
    
    if open_ports:
        ports_info = f"Open Ports: {', '.join(map(str, sorted(open_ports)))}"
        print_section("DISCOVERED PORTS", ports_info)
    
    scan_types = "\n".join(
        f"  {i:2d}. {opt:<20} - {desc}" for i, (opt, desc) in enumerate(menu['scan_types'], 1)
    )
    print_section("SCAN TYPES", scan_types)
    
    timing_options = "\n".join(
        f"  T{i-1}. {opt:<20} - {desc}" for i, (opt, desc) in enumerate(menu['timing'], 1)
    )
    print_section("TIMING OPTIONS", timing_options)
    
    if menu['scripts']:
        scripts = "\n".join(
            f"  {i:2d}. {script:<25} - {desc}" for i, (script, desc) in enumerate(menu['scripts'][:10], 1)
        )
        if len(menu['scripts']) > 10:
            scripts += f"\n  ... and {len(menu['scripts']) - 10} more scripts available"
        print_section("AVAILABLE SCRIPTS", scripts)
    
    flags = "\n".join(
        f"  {flag:<20} - {desc}" for flag, desc in NMAP_FLAGS[:8]
    )
    flags += f"\n  ... and {len(NMAP_FLAGS) - 8} more flags available"
    print_section("ADVANCED FLAGS", flags)
    
def get_user_selections(menu: Dict[str, List[Tuple[str, str]]]) -> List[str]:
    """Get user selections for Nmap scan sequentially.
    
    Args:
        menu: Menu dictionary with options
    
    Returns:
        List of selected options
    """
    import os

    def print_section(title: str, content: str) -> None:
        print(f"┌{'─' * (len(title) + 4)}┐")
        print(f"│  {title}  │")
        print(f"├{'─' * (len(title) + 4)}┴{'─' * 60}")
        print(content.strip())
        print(f"└{'─' * 64}\n")

    selections = []
    max_attempts = 3

    # Initial choice: manual flags or menu options
    os.system('clear')
    print("""
    ╔══════════════════════════════════════╗
    ║       NMAP INTERACTIVE SCANNER       ║
    ╚══════════════════════════════════════╝
    """)
    print_section("SELECT INPUT METHOD", "1. Enter manual Nmap flags\n2. Use interactive menu options")
    
    attempt = 0
    while attempt < max_attempts:
        try:
            choice = input(f"Enter choice (1 or 2, attempt {attempt + 1}/{max_attempts}): ").strip()
            if choice == '1':
                flags = input("Enter manual Nmap flags (e.g., -sV -O --script=vuln): ").strip()
                if flags:
                    return [flag.strip() for flag in flags.split()]
                else:
                    logger.info("No flags provided, using default scan")
                    return ['service_version', 'default_scripts', 'fast_scan']
            elif choice == '2':
                break
            else:
                print(f"❌ Invalid choice. {max_attempts - attempt - 1} attempts left.")
        except KeyboardInterrupt:
            print("\n🚫 Scan cancelled")
            return []
        attempt += 1
    else:
        logger.warning("Max attempts reached, defaulting to safe scan")
        return ['service_version', 'default_scripts', 'fast_scan']

    # Scan Types Menu
    os.system('clear')
    scan_types_content = "\n".join(
        f"  {i:2d}. {opt:<20} - {desc}" for i, (opt, desc) in enumerate(menu['scan_types'], 1)
    ) + "\n  0. Skip (no scan type)"
    print_section("SCAN TYPES", scan_types_content)
    
    attempt = 0
    while attempt < max_attempts:
        try:
            user_input = input(f"Enter scan type number (0-{len(menu['scan_types'])}, attempt {attempt + 1}/{max_attempts}): ").strip()
            if user_input == '0':
                break
            if user_input.isdigit():
                idx = int(user_input) - 1
                if 0 <= idx < len(menu['scan_types']):
                    selections.append(menu['scan_types'][idx][0])
                    break
                else:
                    print(f"❌ Invalid scan type. {max_attempts - attempt - 1} attempts left.")
            else:
                print(f"❌ Invalid input. {max_attempts - attempt - 1} attempts left.")
        except KeyboardInterrupt:
            print("\n🚫 Scan cancelled")
            return []
        attempt += 1
    else:
        logger.warning("No valid scan type selected, proceeding without scan type")

    # Timing Options Menu
    os.system('clear')
    timing_content = "\n".join(
        f"  T{i}. {opt:<20} - {desc}" for i, (opt, desc) in enumerate(menu['timing'])
    ) + "\n  S. Skip (default timing)"
    print_section("TIMING OPTIONS", timing_content)
    
    attempt = 0
    while attempt < max_attempts:
        try:
            user_input = input(f"Enter timing option (T0-T{len(menu['timing'])-1} or S, attempt {attempt + 1}/{max_attempts}): ").strip().upper()
            if user_input == 'S':
                break
            if user_input.startswith('T') and user_input[1:].isdigit():
                idx = int(user_input[1:])
                if 0 <= idx < len(menu['timing']):
                    selections.append(menu['timing'][idx][0])
                    break
                else:
                    print(f"❌ Invalid timing. {max_attempts - attempt - 1} attempts left.")
            else:
                print(f"❌ Invalid input. {max_attempts - attempt - 1} attempts left.")
        except KeyboardInterrupt:
            print("\n🚫 Scan cancelled")
            return []
        attempt += 1
    else:
        logger.warning("No valid timing selected, using default timing")

    # Scripts Menu
    os.system('clear')
    scripts_content = "\n".join(
        f"  {i:2d}. {script:<40} - {desc}" for i, (script, desc) in enumerate(menu['scripts'])
    ) + "\n  0. Skip (no scripts)"
    print_section("AVAILABLE SCRIPTS", scripts_content)
    
    attempt = 0
    while attempt < max_attempts:
        try:
            user_input = input(f"Enter script numbers (e.g., 1,3,5 or 0 to skip, attempt {attempt + 1}/{max_attempts}): ").strip()
            if user_input == '0':
                break
            raw_selections = [s.strip() for s in user_input.split(',')]
            valid = True
            for sel in raw_selections:
                if sel.isdigit():
                    idx = int(sel) - 1
                    if 0 <= idx < len(menu['scripts']):
                        selections.append(menu['scripts'][idx][0])
                    else:
                        print(f"❌ Invalid script: {sel}")
                        valid = False
                else:
                    print(f"❌ Invalid input: {sel}")
                    valid = False
            if valid and raw_selections:
                break
            else:
                print(f"❌ No valid scripts selected. {max_attempts - attempt - 1} attempts left.")
        except KeyboardInterrupt:
            print("\n🚫 Scan cancelled")
            return []
        attempt += 1
    else:
        logger.warning("No valid scripts selected, proceeding without scripts")

    # Flags Menu
    os.system('clear')
    flags_content = "\n".join(
        f"  {i:2d}. {flag:<20} - {desc}" for i, (flag, desc) in enumerate(NMAP_FLAGS)
    ) + "\n  0. Skip (no additional flags)"
    print_section("ADVANCED FLAGS", flags_content)
    
    attempt = 0
    while attempt < max_attempts:
        try:
            user_input = input(f"Enter flag numbers (e.g., 1,3,5 or 0 to skip, attempt {attempt + 1}/{max_attempts}): ").strip()
            if user_input == '0':
                break
            raw_selections = [s.strip() for s in user_input.split(',')]
            valid = True
            for sel in raw_selections:
                if sel.isdigit():
                    idx = int(sel) - 1
                    if 0 <= idx < len(NMAP_FLAGS):
                        selections.append(NMAP_FLAGS[idx][0])
                    else:
                        print(f"❌ Invalid flag: {sel}")
                        valid = False
                else:
                    print(f"❌ Invalid input: {sel}")
                    valid = False
            if valid and raw_selections:
                break
            else:
                print(f"❌ No valid flags selected. {max_attempts - attempt - 1} attempts left.")
        except KeyboardInterrupt:
            print("\n🚫 Scan cancelled")
            return []
        attempt += 1
    else:
        logger.warning("No valid flags selected, proceeding without flags")

    if not selections:
        logger.info("No selections made, using default scan")
        return ['service_version', 'default_scripts', 'fast_scan']
    
    return selections    
def build_nmap_command(target: str, selections: List[str], menu: Dict[str, List[Tuple[str, str]]], stealth: bool) -> List[str]:
    """Build Nmap command from user selections.
    
    Args:
        target: Target to scan
        selections: User's selections
        menu: Menu dictionary
        stealth: Whether to use stealth mode
    
    Returns:
        List of command arguments
    """
    cmd_parts = []
    scripts = []
    timing_set = False
    
    # Process selections
    for selection in selections:
        if selection in [s[0] for s in menu['scan_types']]:
            # Scan type selections
            if selection == 'quick_scan':
                cmd_parts.extend(['-sS', '-F'])
            elif selection == 'full_tcp_scan':
                cmd_parts.extend(['-sS', '-p-'])
            elif selection == 'udp_scan':
                cmd_parts.extend(['-sU', '--top-ports', '1000'])
            elif selection == 'stealth_scan':
                cmd_parts.append('-sS')
            elif selection == 'connect_scan':
                cmd_parts.append('-sT')
            elif selection == 'service_version':
                cmd_parts.append('-sV')
            elif selection == 'os_detection':
                cmd_parts.append('-O')
            elif selection == 'aggressive':
                cmd_parts.append('-A')
            elif selection == 'comprehensive':
                cmd_parts.extend(['-sS', '-sU', '-sV', '-sC', '--top-ports', '1000'])
            elif selection == 'vulnerability':
                cmd_parts.extend(['-sV', '--script=vuln'])
            elif selection == 'default_scripts':
                cmd_parts.append('-sC')
            elif selection == 'fast_scan':
                cmd_parts.append('-F')
        
        elif selection in [s[0] for s in menu['timing']]:
            # Timing selections
            timing_map = {
                'paranoid': '-T0', 'sneaky': '-T1', 'polite': '-T2',
                'normal': '-T3', 'aggressive': '-T4', 'insane': '-T5'
            }
            if selection in timing_map:
                cmd_parts.append(timing_map[selection])
                timing_set = True
        
        elif selection in [s[0] for s in menu['scripts']]:
            # Script selections
            scripts.append(selection)
        
        elif selection.startswith('-'):
            # Raw nmap flags
            cmd_parts.append(selection)
    
    # Add scripts if any were selected
    if scripts:
        cmd_parts.append(f"--script={','.join(scripts)}")
    
    # Apply stealth settings if requested and no timing was set
    if stealth and not timing_set:
        cmd_parts.extend(['-T2', '--scan-delay', '1s'])
    
    # Set default timing if none specified
    if not timing_set and not stealth:
        cmd_parts.append('-T3')
    
    # Remove duplicates while preserving order
    seen = set()
    unique_parts = []
    for part in cmd_parts:
        if part not in seen:
            seen.add(part)
            unique_parts.append(part)
    
    return unique_parts

def run_interactive_nmap(target: str, open_ports: List[int], stealth: bool = False, proxies: Optional[Dict[str, str]] = None, cache_file: Optional[str] = None) -> Dict[str, Any]:
    """Run Nmap interactively with a findings-based menu.
    
    Args:
        target: Target IP or domain
        open_ports: List of open ports from prior scans
        stealth: If True, uses stealth options and delays
        proxies: Optional proxy configuration
        cache_file: Optional path to cache results
    
    Returns:
        Dictionary with Nmap results
    
    Raises:
        ValueError: If target is invalid
        RuntimeError: If Nmap fails
    """
    try:
        target = sanitize_target(target)
        logger.info(f"Starting interactive Nmap scan on {target}")
        
        if not check_nmap():
            raise RuntimeError("Nmap is not installed or accessible")
        
        # Build menu based on open ports
        menu = build_nmap_menu(open_ports)
        
        # Display interactive menu
        display_interactive_menu(menu, open_ports)
        
        # Get user selections
        selections = get_user_selections(menu)
        
        if not selections:
            logger.warning("Scan cancelled by user")
            return {'error': 'Scan cancelled by user'}
        
        # Build Nmap command
        nmap_options = build_nmap_command(target, selections, menu, stealth)
        options_str = ' '.join(nmap_options)
        
        print(f"\n🚀 Executing: nmap {options_str} {target}")
        
        # Execute Nmap scan
        results = execute_nmap(target, options_str, stealth, proxies, cache_file)
        
        # Perform risk scoring and comparison
        results['risk_analysis'] = score_risk(results)
        
        if cache_file and Path(cache_file).exists():
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cached_data = json.load(f)
                    old_results = cached_data.get('results', {})
                    if old_results:
                        results['changes'] = compare_results(old_results, results)
            except (OSError, json.JSONDecodeError) as e:
                logger.warning(f"Could not load previous results for comparison: {e}")
        
        return results
    
    except ValueError as e:
        raise
    except Exception as e:
        logger.error(f"Interactive Nmap scan failed for {target}: {e}")
        raise RuntimeError(f"Interactive Nmap scan failed: {e}")

def execute_nmap(target: str, options: str, stealth: bool, proxies: Optional[Dict[str, str]], cache_file: Optional[str]) -> Dict[str, Any]:
    """Execute Nmap scan and parse results.
    
    Args:
        target: Target IP or domain
        options: Nmap command-line options
        stealth: If True, applies stealth settings
        proxies: Optional proxy configuration
        cache_file: Optional path to cache results
    
    Returns:
        Dictionary with parsed Nmap results
    
    Raises:
        RuntimeError: If Nmap scan fails
    """
    try:
        logger.debug(f"Executing Nmap with options: {options}")
        
        # Check cache
        if cache_file:
            cache_path = Path(cache_file).resolve()
            try:
                if cache_path.exists() and cache_path.is_file():
                    with open(cache_path, 'r', encoding='utf-8') as f:
                        cached_data = json.load(f)
                        cache_key = f"{target}_{options}"
                        if not isinstance(cached_data, dict):
                            raise ValueError("Invalid cache format")
                        if cached_data.get('cache_key') == cache_key:
                            timestamp = cached_data.get('timestamp', 0)
                            cache_age = time.time() - timestamp
                            if cache_age < 3600 and cached_data.get('results'):
                                logger.info(f"Using cached results (age: {cache_age:.0f}s)")
                                return cached_data['results']
            except (OSError, json.JSONDecodeError, ValueError) as e:
                logger.warning(f"Invalid or corrupted cache: {e}")        
        
        # Build Nmap command
        base_cmd = ["nmap", "-oX", "-", "--no-stylesheet"]
        
        # Handle proxy configuration
        if proxies:
            proxy_url = proxies.get('http') or proxies.get('https')
            if proxy_url:
                proxy_url = proxy_url.strip()
                proxy_pattern = r'^(https?|socks[45]h?)://(?:\S+@)?[\w.-]+(?::\d{1,5})?$'
                if not re.match(proxy_pattern, proxy_url):
                    logger.error(f"Invalid proxy URL: {proxy_url}")
                    raise ValueError(f"Invalid proxy URL: {proxy_url}")
                if proxy_url.startswith('socks5h://'):
                    proxy_url = proxy_url.replace('socks5h://', 'http://')
                base_cmd.extend(["--proxies", proxy_url])
                logger.debug(f"Using proxy: {proxy_url}")
        
        # Parse and validate user options
        try:
            user_options = shlex.split(options) if options else []
            if len(user_options) > 50:
                raise ValueError("Too many options provided")
        except ValueError as e:
            logger.error(f"Invalid options: {e}")
            raise ValueError(f"Invalid options: {e}")
        
        # Prevent dangerous output options
        dangerous_options = ['-oX', '-oN', '-oG', '-oA', '-oS']
        for opt in user_options:
            if any(opt.startswith(d) for d in dangerous_options):
                logger.error(f"Prohibited option: {opt}")
                raise ValueError(f"Prohibited option: {opt}")
        
        # Build command
        cmd = base_cmd + user_options + [target]
        safe_cmd = [arg if not arg.startswith('http') else '[PROXY]' for arg in cmd]
        logger.debug(f"Nmap command: {' '.join(shlex.quote(arg) for arg in safe_cmd)}")
        
        # Stealth delay
        if stealth:
            delay = random.uniform(1.0, 5.0)
            logger.debug(f"Stealth delay: {delay:.2f}s")
            time.sleep(delay)
        
        # Execute with retries
        max_retries = 3
        timeout = 1800  # 30 minutes timeout
        
        result = None
        for attempt in range(max_retries):
            try:
                logger.info(f"Starting Nmap scan (attempt {attempt + 1}/{max_retries})")
                start_time = time.time()
                
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True,
                    timeout=timeout
                )
                
                execution_time = time.time() - start_time
                logger.info(f"Nmap scan completed in {execution_time:.2f} seconds")
                break
                
            except subprocess.CalledProcessError as e:
                if attempt < max_retries - 1:
                    retry_delay = 2 ** attempt
                    logger.warning(f"Nmap attempt {attempt + 1} failed: {e.stderr}. Retrying in {retry_delay}s...")
                    time.sleep(retry_delay)
                else:
                    logger.error(f"Nmap scan failed after {max_retries} attempts: {e.stderr}")
                    raise RuntimeError(f"Nmap scan failed: {e.stderr}")
            
            except subprocess.TimeoutExpired:
                logger.error(f"Nmap scan timed out after {timeout} seconds")
                raise RuntimeError(f"Nmap scan timed out after {timeout} seconds")
            
            except FileNotFoundError:
                logger.error("Nmap binary not found")
                raise RuntimeError("Nmap binary not found")
        
        # Parse XML output
        try:
            if not result.stdout.strip():
                logger.error("Nmap returned empty output")
                raise RuntimeError("Nmap returned empty output")
            
            max_size = 100 * 1024 * 1024  # 100MB limit
            if len(result.stdout) > max_size:
                raise RuntimeError("Output too large")
            
            # Parse XML using ElementTree
            root = ET.fromstring(result.stdout)
            
            results = {
                'target': target,
                'scan_info': {},
                'hosts': [],
                'summary': {}
            }
            
            # Parse scan info
            try:
                scaninfo = root.find('scaninfo')
                if scaninfo is not None:
                    results['scan_info'] = {
                        'type': scaninfo.get('type'),
                        'protocol': scaninfo.get('protocol'),
                        'numservices': scaninfo.get('numservices'),
                        'services': scaninfo.get('services')
                    }
            except Exception as e:
                logger.error(f"Failed to parse scaninfo: {e}")

            # Parse hosts
            for host in root.findall('host'):
                host_info = {
                    'addresses': [],
                    'hostnames': [],
                    'status': {},
                    'ports': [],
                    'scripts': [],
                    'os': None,
                    'uptime': None,
                    'distance': None
                }
                
                # Parse addresses
                for address in host.findall('address'):
                    addr_info = {
                        'addr': address.get('addr'),
                        'addrtype': address.get('addrtype')
                    }
                    if address.get('vendor'):
                        addr_info['vendor'] = address.get('vendor')
                    host_info['addresses'].append(addr_info)
                
                # Parse hostnames
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    for hostname in hostnames.findall('hostname'):
                        host_info['hostnames'].append({
                            'name': hostname.get('name'),
                            'type': hostname.get('type')
                        })
                
                # Parse status
                status = host.find('status')
                if status is not None:
                    host_info['status'] = {
                        'state': status.get('state'),
                        'reason': status.get('reason'),
                        'reason_ttl': status.get('reason_ttl')
                    }
                
                # Parse ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_info = {
                            'portid': int(port.get('portid')),
                            'protocol': port.get('protocol')
                        }
                        
                        # Port state
                        state = port.find('state')
                        if state is not None:
                            port_info['state'] = {
                                'state': state.get('state'),
                                'reason': state.get('reason'),
                                'reason_ttl': state.get('reason_ttl')
                            }
                        
                        # Service info
                        service = port.find('service')
                        if service is not None:
                            service_info = {}
                            for attr in ['name', 'product', 'version', 'extrainfo', 'method', 'conf']:
                                if service.get(attr):
                                    service_info[attr] = service.get(attr)
                            if service_info:
                                port_info['service'] = service_info
                        
                        # Port scripts
                        port_scripts = []
                        for script in port.findall('script'):
                            script_info = {
                                'id': script.get('id'),
                                'output': script.get('output')
                            }
                            # Parse script elements if present
                            elements = []
                            for elem in script.findall('.//elem'):
                                elem_info = {'content': elem.text}
                                if elem.get('key'):
                                    elem_info['key'] = elem.get('key')
                                elements.append(elem_info)
                            if elements:
                                script_info['elements'] = elements
                            port_scripts.append(script_info)
                        
                        if port_scripts:
                            port_info['scripts'] = port_scripts
                        
                        host_info['ports'].append(port_info)
                
                # Parse host scripts
                hostscript = host.find('hostscript')
                if hostscript is not None:
                    for script in hostscript.findall('script'):
                        script_info = {
                            'id': script.get('id'),
                            'output': script.get('output')
                        }
                        # Parse script elements
                        elements = []
                        for elem in script.findall('.//elem'):
                            elem_info = {'content': elem.text}
                            if elem.get('key'):
                                elem_info['key'] = elem.get('key')
                            elements.append(elem_info)
                        if elements:
                            script_info['elements'] = elements
                        host_info['scripts'].append(script_info)
                
                # Parse OS detection
                os_elem = host.find('os')
                if os_elem is not None:
                    os_info = {
                        'portused': [],
                        'osmatch': [],
                        'osfingerprint': []
                    }
                    
                    for portused in os_elem.findall('portused'):
                        os_info['portused'].append({
                            'state': portused.get('state'),
                            'proto': portused.get('proto'),
                            'portid': portused.get('portid')
                        })
                    
                    for osmatch in os_elem.findall('osmatch'):
                        match_info = {
                            'name': osmatch.get('name'),
                            'accuracy': osmatch.get('accuracy'),
                            'line': osmatch.get('line')
                        }
                        
                        osclass_list = []
                        for osclass in osmatch.findall('osclass'):
                            osclass_list.append({
                                'type': osclass.get('type'),
                                'vendor': osclass.get('vendor'),
                                'osfamily': osclass.get('osfamily'),
                                'osgen': osclass.get('osgen'),
                                'accuracy': osclass.get('accuracy')
                            })
                        if osclass_list:
                            match_info['osclass'] = osclass_list
                        
                        os_info['osmatch'].append(match_info)
                    
                    if os_info['osmatch'] or os_info['portused']:
                        host_info['os'] = os_info
                
                # Parse uptime
                uptime = host.find('uptime')
                if uptime is not None:
                    host_info['uptime'] = {
                        'seconds': uptime.get('seconds'),
                        'lastboot': uptime.get('lastboot')
                    }
                
                # Parse distance
                distance = host.find('distance')
                if distance is not None:
                    host_info['distance'] = distance.get('value')
                
                results['hosts'].append(host_info)
            
            # Parse run stats
            runstats = root.find('runstats')
            if runstats is not None:
                finished = runstats.find('finished')
                hosts = runstats.find('hosts')
                
                if finished is not None or hosts is not None:
                    results['summary'] = {}
                    if finished is not None:
                        results['summary']['finished'] = {
                            'time': finished.get('time'),
                            'timestr': finished.get('timestr'),
                            'elapsed': finished.get('elapsed'),
                            'summary': finished.get('summary'),
                            'exit': finished.get('exit')
                        }
                    if hosts is not None:
                        results['summary']['hosts'] = {
                            'up': hosts.get('up'),
                            'down': hosts.get('down'),
                            'total': hosts.get('total')
                        }
            
            # Create simplified port list for backward compatibility
            all_ports = []
            for host in results['hosts']:
                for port in host['ports']:
                    if port.get('state', {}).get('state') == 'open':
                        port_simple = {
                            'port': port['portid'],
                            'protocol': port['protocol'],
                            'state': 'open'
                        }
                        if port.get('service'):
                            service = port['service']
                            port_simple.update({
                                'service': service.get('name'),
                                'product': service.get('product'),
                                'version': service.get('version')
                            })
                        all_ports.append(port_simple)
            
            results['ports'] = all_ports
            results['host'] = target
            
            # Add script results for backward compatibility
            all_scripts = []
            for host in results['hosts']:
                all_scripts.extend(host.get('scripts', []))
                for port in host['ports']:
                    all_scripts.extend(port.get('scripts', []))
            results['scripts'] = all_scripts
            
            # Add OS info for backward compatibility
            for host in results['hosts']:
                if host.get('os') and host['os'].get('osmatch'):
                    best_match = max(host['os']['osmatch'], 
                                   key=lambda x: int(x.get('accuracy', 0)))
                    results['os'] = {
                        'name': best_match.get('name'),
                        'accuracy': best_match.get('accuracy')
                    }
                    break
            
            logger.info(f"Nmap scan completed: {len(results['ports'])} open ports found on {target}")
            
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML output: {e}")
            logger.debug(f"Raw output: {result.stdout if result else 'No output'}")
            raise RuntimeError(f"XML parsing error: {e}")
        
        # Cache results
        if cache_file:
            try:
                cache_path = Path(cache_file).resolve()
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                
                cache_data = {
                    'cache_key': f"{target}_{options}",
                    'timestamp': time.time(),
                    'target': target,
                    'options': options,
                    'results': results
                }
                
                with open(cache_path, 'w', encoding='utf-8') as f:
                    json.dump(cache_data, f, indent=2)
                logger.debug(f"Cached Nmap results to {cache_path}")
                
            except OSError as e:
                logger.warning(f"Failed to write Nmap cache: {e}")
        
        return results
    
    except Exception as e:
        logger.error(f"Nmap execution failed for {target}: {e}")
        raise RuntimeError(f"Nmap execution failed: {e}")

def compare_results(old_results: Dict, new_results: Dict) -> Dict[str, Any]:
    """Compare old and new Nmap results to highlight changes.
    
    Args:
        old_results: Previous scan results
        new_results: Current scan results
    
    Returns:
        Dictionary with added/removed/changed items
    """
    changes = {
        'added_ports': [],
        'removed_ports': [],
        'changed_services': [],
        'new_scripts': [],
        'os_changes': [],
        'summary': {}
    }
    
    try:
        # Compare ports
        old_ports = {(p['port'], p['protocol']) for p in old_results.get('ports', [])}
        new_ports = {(p['port'], p['protocol']) for p in new_results.get('ports', [])}
        
        added_ports = new_ports - old_ports
        removed_ports = old_ports - new_ports
        
        changes['added_ports'] = [{'port': p[0], 'protocol': p[1]} for p in added_ports]
        changes['removed_ports'] = [{'port': p[0], 'protocol': p[1]} for p in removed_ports]
        
        # Compare services on existing ports
        old_services = {(p['port'], p['protocol']): p for p in old_results.get('ports', [])}
        new_services = {(p['port'], p['protocol']): p for p in new_results.get('ports', [])}
        
        for port_key in old_services:
            if port_key in new_services:
                old_svc = old_services[port_key]
                new_svc = new_services[port_key]
                
                service_changed = False
                changes_detail = {'port': port_key[0], 'protocol': port_key[1], 'changes': {}}
                
                for field in ['service', 'product', 'version']:
                    old_val = old_svc.get(field)
                    new_val = new_svc.get(field)
                    if old_val != new_val:
                        changes_detail['changes'][field] = {'old': old_val, 'new': new_val}
                        service_changed = True
                
                if service_changed:
                    changes['changed_services'].append(changes_detail)
        
        # Compare scripts
        old_script_ids = {s.get('id') for s in old_results.get('scripts', [])}
        new_script_ids = {s.get('id') for s in new_results.get('scripts', [])}
        
        new_scripts = new_script_ids - old_script_ids
        changes['new_scripts'] = list(new_scripts)
        
        # Compare OS detection
        old_os = old_results.get('os')
        new_os = new_results.get('os')
        
        if old_os != new_os:
            changes['os_changes'] = {
                'old': old_os,
                'new': new_os
            }
        
        # Summary statistics
        changes['summary'] = {
            'ports_added': len(changes['added_ports']),
            'ports_removed': len(changes['removed_ports']),
            'services_changed': len(changes['changed_services']),
            'new_scripts_found': len(changes['new_scripts']),
            'os_changed': bool(changes['os_changes'])
        }
        
    except Exception as e:
        logger.error(f"Error comparing results: {e}")
        changes['error'] = str(e)
    
    return changes

def score_risk(results: Dict) -> Dict[str, Any]:
    """Assign risk scores to Nmap findings.
    
    Args:
        results: Nmap scan results
    
    Returns:
        Dictionary with risk scores and level
    """
    risk_score = 0
    findings = []
    critical_findings = []
    
    try:
        # Define risk weights
        HIGH_RISK_SERVICES = {
            'telnet': 8, 'ftp': 6, 'tftp': 7, 'rsh': 9, 'rexec': 9,
            'finger': 5, 'netbios-ssn': 6, 'microsoft-ds': 7, 'snmp': 6,
            'ldap': 5, 'nfs': 7, 'rpcbind': 6, 'mysql': 5, 'postgresql': 5,
            'vnc': 7, 'rdp': 6, 'winrm': 6
        }
        
        MEDIUM_RISK_SERVICES = {
            'ssh': 3, 'http': 2, 'https': 1, 'smtp': 3, 'pop3': 3,
            'imap': 3, 'dns': 2, 'dhcp': 2
        }
        
        VULNERABLE_VERSIONS = [
            'openssl/0.', 'openssl/1.0.0', 'apache/1.', 'apache/2.0',
            'apache/2.2', 'nginx/0.', 'nginx/1.0', 'openssh/3.',
            'openssh/4.', 'openssh/5.', 'mysql/3.', 'mysql/4.',
            'postgresql/7.', 'postgresql/8.', 'proftpd/1.2',
            'vsftpd/2.0', 'bind/8.', 'bind/9.0', 'bind/9.1'
        ]
        
        # Analyze ports and services
        for port in results.get('ports', []):
            service = port.get('service', '').lower()
            product = port.get('product', '').lower()
            version = port.get('version', '').lower()
            port_num = port.get('port')
            
            # Check for high-risk services
            if service in HIGH_RISK_SERVICES:
                score_add = HIGH_RISK_SERVICES[service]
                risk_score += score_add
                findings.append(f"Port {port_num} ({service}): High-risk service exposed (+{score_add})")
                
                if service in ['telnet', 'rsh', 'rexec']:
                    critical_findings.append(f"Port {port_num}: {service.upper()} - Cleartext protocol!")
            
            elif service in MEDIUM_RISK_SERVICES:
                score_add = MEDIUM_RISK_SERVICES[service]
                risk_score += score_add
                findings.append(f"Port {port_num} ({service}): Service exposed (+{score_add})")
            
            # Check for vulnerable versions
            version_string = f"{product}/{version}".lower()
            for vuln_version in VULNERABLE_VERSIONS:
                if vuln_version in version_string:
                    risk_score += 5
                    findings.append(f"Port {port_num}: Potentially vulnerable version - {product} {version} (+5)")
                    break
            
            # Check for default/weak configurations
            if 'default' in version or 'default' in product:
                risk_score += 3
                findings.append(f"Port {port_num}: Default configuration detected (+3)")
            
            # Check for administrative interfaces on non-standard ports
            admin_services = ['http-proxy', 'http-alt', 'webcache']
            if service in admin_services and port_num not in [80, 443, 8080]:
                risk_score += 4
                findings.append(f"Port {port_num}: Administrative interface on non-standard port (+4)")
        
        # Analyze script results for vulnerabilities
        for script in results.get('scripts', []):
            script_id = script.get('id', '').lower()
            script_output = script.get('output', '').lower()
            
            # High-impact vulnerabilities
            if 'ms17-010' in script_id and 'vulnerable' in script_output:
                risk_score += 15
                critical_findings.append("EternalBlue vulnerability (MS17-010) detected!")
                findings.append("Critical: EternalBlue vulnerability found (+15)")
            
            elif 'heartbleed' in script_id and 'vulnerable' in script_output:
                risk_score += 12
                critical_findings.append("Heartbleed vulnerability detected!")
                findings.append("Critical: Heartbleed vulnerability found (+12)")
            
            elif 'shellshock' in script_id and 'vulnerable' in script_output:
                risk_score += 10
                critical_findings.append("Shellshock vulnerability detected!")
                findings.append("Critical: Shellshock vulnerability found (+10)")
            
            # Medium-impact vulnerabilities
            elif 'vuln' in script_id and 'vulnerable' in script_output:
                risk_score += 8
                findings.append(f"Vulnerability detected: {script_id} (+8)")
            
            # Information disclosure
            elif any(keyword in script_output for keyword in ['anonymous', 'guest', 'public']):
                risk_score += 4
                findings.append(f"Information disclosure: {script_id} (+4)")
            
            # Brute-force opportunities
            elif 'brute' in script_id and 'valid' in script_output:
                risk_score += 6
                findings.append(f"Weak credentials found: {script_id} (+6)")
        
        # Analyze OS fingerprinting results
        os_info = results.get('os')
        if os_info:
            os_name = os_info.get('name', '').lower()
            
            # Check for outdated operating systems
            if any(old_os in os_name for old_os in ['windows xp', 'windows 2000', 'windows 2003']):
                risk_score += 10
                critical_findings.append("Outdated operating system detected!")
                findings.append("Critical: End-of-life operating system (+10)")
            
            elif any(old_os in os_name for old_os in ['windows 7', 'windows 2008']):
                risk_score += 6
                findings.append("Potentially outdated operating system (+6)")
        
        # Calculate risk level
        if risk_score >= 25:
            risk_level = 'Critical'
        elif risk_score >= 15:
            risk_level = 'High'
        elif risk_score >= 8:
            risk_level = 'Medium'
        elif risk_score >= 3:
            risk_level = 'Low'
        else:
            risk_level = 'Minimal'
        
        # Generate recommendations
        recommendations = []
        if critical_findings:
            recommendations.append("URGENT: Address critical vulnerabilities immediately")
            recommendations.append("Consider taking affected systems offline until patched")
        
        if risk_score >= 15:
            recommendations.append("Implement network segmentation")
            recommendations.append("Enable firewall rules to limit exposure")
            recommendations.append("Conduct thorough security assessment")
        
        if any('brute' in f for f in findings):
            recommendations.append("Implement strong password policies")
            recommendations.append("Enable account lockout mechanisms")
            recommendations.append("Consider multi-factor authentication")
        
        if not recommendations:
            recommendations.append("Maintain current security posture")
            recommendations.append("Continue regular security monitoring")
        
    except Exception as e:
        logger.error(f"Error during risk scoring: {e}")
        return {
            'score': 0,
            'level': 'Unknown',
            'findings': [f"Risk analysis failed: {e}"],
            'critical_findings': [],
            'recommendations': ['Manual security review recommended']
        }
    
    return {
        'score': risk_score,
        'level': risk_level,
        'findings': findings,
        'critical_findings': critical_findings,
        'recommendations': recommendations,
        'total_ports': len(results.get('ports', [])),
        'total_scripts': len(results.get('scripts', []))
    }

if __name__ == '__main__':
    # Configure logging for standalone testing
    import sys
    import os
    
    # Add parent directory to path for utils import
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    try:
        from utils import setup_logging
        logger = setup_logging('DEBUG')
    except ImportError:
        # Fallback logging setup
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        logger = logging.getLogger('nmap_scan')
    
    # Test the module
    try:
        print("Testing Nmap Scanner Module")
        print("=" * 50)
        
        # Check if running as root
        try:
            import os
            if os.geteuid() == 0:
                print("✓ Running as root - full scan capabilities available")
            else:
                print("⚠ Not running as root - some scan types may be limited")
        except AttributeError:
            print("⚠ Cannot determine privilege level")
        
        # Test target (scanme.nmap.org is designed for testing)
        test_target = input("Enter Domain or IP: ")
        test_ports = [22, 80, 9929]  # Known open ports on scanme.nmap.org
        
        print(f"\nTesting target: {test_target}")
        print(f"Simulated open ports: {test_ports}")
        
        # Test configuration
        stealth = True
        cache_file = '/tmp/nmap_test_cache.json'
        
        # Run interactive scan
        result = run_interactive_nmap(
            test_target, 
            test_ports, 
            stealth=stealth, 
            cache_file=cache_file
        )
        
        print(f"\n🎯 Scan Results Summary:")
        print(f"Target: {result.get('host', 'Unknown')}")
        print(f"Open Ports: {len(result.get('ports', []))}")
        print(f"Scripts Run: {len(result.get('scripts', []))}")
        print(f"Risk Level: {result.get('risk_analysis', {}).get('level', 'Unknown')}")
        
        if result.get('ports'):
            print(f"\nOpen Ports Details:")
            for port in result['ports']:
                service = port.get('service', 'unknown')
                version = port.get('version', '')
                print(f"  {port['port']}/{port['protocol']} - {service} {version}")
        
        if result.get('risk_analysis', {}).get('critical_findings'):
            print(f"\n🚨 Critical Findings:")
            for finding in result['risk_analysis']['critical_findings']:
                print(f"  • {finding}")
        
        print(f"\n✓ Test completed successfully")
        
    except KeyboardInterrupt:
        print(f"\n\n🚫 Test cancelled by user")
    except Exception as e:
        logger.error(f"Test failed: {e}")
        print(f"❌ Test failed: {e}")
        sys.exit(1)
