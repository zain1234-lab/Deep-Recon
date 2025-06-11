#!/usr/bin/env python3
"""
Advanced CLI Reconnaissance Tool
A modular reconnaissance framework for offensive security operations
"""

import argparse
import os
import sys
import json
import socket
from datetime import datetime
from pathlib import Path

# Import modules
from modules import (
    whois_lookup, dns_enum, subdomains, subdomain_brute,
    port_scan, banner_grab, nmap_scan, http_fingerprint,
    header_analyzer, asn_lookup, js_parser, takeover_check,
    archive_scan, endpoint_enum, recon_compare, risk_score
)
from utils import setup_logging, generate_report, check_tor, stealth_delay, get_proxies


def check_dependencies():
    """Check if required tools and dependencies are available"""
    missing = []
    
    # Check Python packages
    required_packages = [
        'requests', 'dnspython', 'python-whois', 'beautifulsoup4'
    ]
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing.append(f"Python package: {package}")
    
    # Check external tools
    if not os.system("which nmap > /dev/null 2>&1") == 0:
        missing.append("nmap (install with: sudo apt install nmap)")
    
    if not os.system("which ffuf > /dev/null 2>&1") == 0:
        print("[!] Warning: ffuf not found. Endpoint enumeration will be limited.")
    
    if missing:
        print("[!] Missing dependencies:")
        for dep in missing:
            print(f"    - {dep}")
        sys.exit(1)


def choose_scan_mode():
    """Prompt user to choose between stealth and fast scan modes"""
    print("\n🔍 Recon Scan Mode Selection:")
    print("1. Stealthy scan (TOR proxy, delays, evasion)")
    print("2. Fast/Normal scan (direct connection, faster)")
    
    while True:
        choice = input("\nChoose scan mode [1/2]: ").strip()
        if choice == '1':
            # Check if TOR is available
            if check_tor():
                print("[+] TOR proxy detected and will be used")
                return True, get_proxies()
            else:
                print("[!] TOR not available. Install and start TOR service.")
                print("    sudo apt install tor && sudo systemctl start tor")
                fallback = input("Continue without TOR? [y/N]: ").strip().lower()
                if fallback == 'y':
                    return False, None
                else:
                    sys.exit(1)
        elif choice == '2':
            print("[+] Fast scan mode selected")
            return False, None
        else:
            print("Please enter 1 or 2")


def main():
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║              Advanced CLI Reconnaissance Tool                ║
    ║           Professional-Grade Recon Framework                 ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    parser = argparse.ArgumentParser(
        description="Advanced CLI Reconnaissance Tool for Offensive Security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com --dns --whois --subs --ports
  python main.py example.com --profile full
  python main.py example.com --compare last.json --output report.html
        """
    )
    
    # Target argument
    parser.add_argument("domain", help="Target domain to reconnaissance")
    
    # Module flags
    parser.add_argument("--whois", action="store_true", help="WHOIS lookup")
    parser.add_argument("--dns", action="store_true", help="DNS enumeration")
    parser.add_argument("--subs", action="store_true", help="Subdomain enumeration")
    parser.add_argument("--brute-subs", action="store_true", help="Subdomain bruteforcing")
    parser.add_argument("--ports", action="store_true", help="Port scanning")
    parser.add_argument("--nmap", action="store_true", help="Nmap service detection")
    parser.add_argument("--banners", action="store_true", help="Banner grabbing")
    parser.add_argument("--http-info", action="store_true", help="HTTP fingerprinting")
    parser.add_argument("--headers", action="store_true", help="Security header analysis")
    parser.add_argument("--asn", action="store_true", help="ASN and geo lookup")
    parser.add_argument("--js", action="store_true", help="JavaScript file analysis")
    parser.add_argument("--takeover", action="store_true", help="Subdomain takeover check")
    parser.add_argument("--wayback", action="store_true", help="Wayback Machine URLs")
    parser.add_argument("--endpoints", action="store_true", help="Endpoint enumeration")
    
    # Profiles
    parser.add_argument("--profile", choices=["quick", "full", "passive"], 
                       help="Predefined scan profiles")
    
    # Output options
    parser.add_argument("--output", default="report.txt", help="Output file")
    parser.add_argument("--json", action="store_true", help="JSON output format")
    parser.add_argument("--html", action="store_true", help="HTML output format")
    
    # Comparison
    parser.add_argument("--compare", help="Compare with previous scan results")
    
    # Verbosity
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    
    args = parser.parse_args()
    
    # Check dependencies
    check_dependencies()
    
    # Setup logging
    log_level = "DEBUG" if args.verbose else "WARNING" if args.quiet else "INFO"
    logger = setup_logging(log_level)
    
    # Choose scan mode
    stealth_mode, proxies = choose_scan_mode()
    
    # Handle profiles
    if args.profile:
        if args.profile == "quick":
            args.whois = args.dns = args.subs = args.ports = True
        elif args.profile == "full":
            args.whois = args.dns = args.subs = args.brute_subs = True
            args.ports = args.nmap = args.banners = args.http_info = True
            args.headers = args.asn = args.js = args.takeover = True
            args.wayback = args.endpoints = True
        elif args.profile == "passive":
            args.whois = args.dns = args.subs = args.asn = args.wayback = True
    
    # Results storage
    results = {
        "target": args.domain,
        "timestamp": datetime.now().isoformat(),
        "scan_mode": "stealth" if stealth_mode else "normal",
        "modules": {}
    }
    
    print(f"\n[+] Starting reconnaissance on: {args.domain}")
    print(f"[+] Scan mode: {'Stealth (TOR)' if stealth_mode else 'Normal'}")
    print(f"[+] Timestamp: {results['timestamp']}")
    print("=" * 60)
    
    # Module execution with stealth delays
    module_count = 0
    
    try:
        # WHOIS Lookup
        if args.whois:
            print("\n[*] Running WHOIS lookup...")
            results["modules"]["whois"] = whois_lookup.get_whois(args.domain)
            module_count += 1
            if stealth_mode:
                stealth_delay()
        
        # DNS Enumeration
        if args.dns:
            print("\n[*] Running DNS enumeration...")
            results["modules"]["dns"] = dns_enum.query_dns(args.domain)
            module_count += 1
            if stealth_mode:
                stealth_delay()
        
        # Subdomain Enumeration
        if args.subs:
            print("\n[*] Running subdomain enumeration...")
            results["modules"]["subdomains"] = subdomains.fetch_subdomains(
                args.domain, proxies=proxies, stealth=stealth_mode
            )
            module_count += 1
            if stealth_mode:
                stealth_delay()
        
        # Subdomain Bruteforcing
        if args.brute_subs:
            print("\n[*] Running subdomain bruteforcing...")
            results["modules"]["brute_subdomains"] = subdomain_brute.brute_subdomains(
                args.domain, stealth=stealth_mode
            )
            module_count += 1
            if stealth_mode:
                stealth_delay()
        
        # Get IP for active scans
        try:
            target_ip = socket.gethostbyname(args.domain)
            results["target_ip"] = target_ip
            print(f"[+] Target IP: {target_ip}")
        except socket.gaierror:
            print(f"[!] Could not resolve {args.domain}")
            target_ip = None
        
        # Port Scanning
        if args.ports and target_ip:
            print("\n[*] Running port scan...")
            results["modules"]["ports"] = port_scan.scan_ports(target_ip)
            module_count += 1
            if stealth_mode:
                stealth_delay()
        
        # Nmap Scanning
        if args.nmap:
            print("\n[*] Running Nmap service detection...")
            results["modules"]["nmap"] = nmap_scan.run_nmap(args.domain)
            module_count += 1
            if stealth_mode:
                stealth_delay()
        
        # Banner Grabbing
        if args.banners and target_ip and "ports" in results["modules"]:
            print("\n[*] Running banner grabbing...")
            open_ports = results["modules"]["ports"]
            results["modules"]["banners"] = {}
            for port in open_ports[:5]:  # Limit to first 5 ports
                banner = banner_grab.grab_banner(target_ip, port)
                if banner:
                    results["modules"]["banners"][str(port)] = banner
            module_count += 1
            if stealth_mode:
                stealth_delay()
        
        # HTTP Fingerprinting
        if args.http_info:
            print("\n[*] Running HTTP fingerprinting...")
            results["modules"]["http"] = http_fingerprint.fingerprint_http(
                f"http://{args.domain}", proxies=proxies
            )
            module_count += 1
            if stealth_mode:
                stealth_delay()
        
        # Header Analysis
        if args.headers:
            print("\n[*] Running security header analysis...")
            results["modules"]["headers"] = header_analyzer.analyze_headers(args.domain, proxies=proxies)
            module_count += 1
            if stealth_mode:
                stealth_delay()
        
        # ASN Lookup
        if args.asn and target_ip:
            print("\n[*] Running ASN and geo lookup...")
            results["modules"]["asn"] = asn_lookup.get_asn_info(target_ip, proxies=proxies)
            module_count += 1
            if stealth_mode:
                stealth_delay()
        
        # JavaScript Analysis
        if args.js:
            print("\n[*] Running JavaScript file analysis...")
            results["modules"]["js"] = js_parser.parse_js_from_domain(args.domain, proxies=proxies)
            module_count += 1
            if stealth_mode:
                stealth_delay()
        
        # Subdomain Takeover Check
        if args.takeover and "subdomains" in results["modules"]:
            print("\n[*] Running subdomain takeover check...")
            subdomains_list = results["modules"]["subdomains"]
            results["modules"]["takeover"] = takeover_check.check_takeover(subdomains_list)
            module_count += 1
            if stealth_mode:
                stealth_delay()
        
        # Wayback Machine
        if args.wayback:
            print("\n[*] Running Wayback Machine scan...")
            results["modules"]["wayback"] = archive_scan.get_wayback_urls(args.domain, proxies=proxies)
            module_count += 1
            if stealth_mode:
                stealth_delay()
        
        # Endpoint Enumeration
        if args.endpoints:
            print("\n[*] Running endpoint enumeration...")
            results["modules"]["endpoints"] = endpoint_enum.run_fuzzer(args.domain)
            module_count += 1
            if stealth_mode:
                stealth_delay()
        
        # Risk Scoring
        print("\n[*] Calculating risk scores...")
        results["risk_analysis"] = risk_score.score_findings(results)
        
        # Comparison with previous results
        if args.compare:
            print(f"\n[*] Comparing with {args.compare}...")
            try:
                results["comparison"] = recon_compare.compare_results(args.compare, results)
            except FileNotFoundError:
                print(f"[!] Comparison file {args.compare} not found")
        
        print("=" * 60)
        print(f"[+] Reconnaissance completed! Executed {module_count} modules")
        
        # Generate reports
        if args.json:
            json_file = args.output.replace('.txt', '.json').replace('.html', '.json')
            with open(json_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"[+] JSON report saved: {json_file}")
        
        if args.html:
            html_file = args.output.replace('.txt', '.html').replace('.json', '.html')
            generate_report(results, html_file, format_type="html")
            print(f"[+] HTML report saved: {html_file}")
        else:
            generate_report(results, args.output, format_type="txt")
            print(f"[+] Text report saved: {args.output}")
        
        # Save current results for future comparison
        comparison_file = f"{args.domain}_last.json"
        with open(comparison_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[+] Scan data saved for future comparison: {comparison_file}")
        print("\n🎯 Reconnaissance Summary:")
        
        # Display key findings
        if "risk_analysis" in results:
            risk_level = results["risk_analysis"].get("total_risk", "Unknown")
            print(f"   Risk Level: {risk_level}")
        
        if "subdomains" in results["modules"]:
            sub_count = len(results["modules"]["subdomains"])
            print(f"   Subdomains Found: {sub_count}")
        
        if "ports" in results["modules"]:
            port_count = len(results["modules"]["ports"])
            print(f"   Open Ports: {port_count}")
        
        if "takeover" in results["modules"]:
            takeover_count = len([x for x in results["modules"]["takeover"] if x.get("vulnerable")])
            if takeover_count > 0:
                print(f"   ⚠️  Potential Takeovers: {takeover_count}")
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during scan: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
