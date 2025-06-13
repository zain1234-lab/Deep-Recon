import argparse
import os
import json
import atexit
import sys
import asyncio
import time
import random
import ipaddress
import dns.resolver
import dns.reversename
from datetime import datetime
import logging
import threading
from contextlib import asynccontextmanager
import inspect # Added for function signature inspection

# --- Global Logger Initialization (will be fully configured in main()) ---
# Initialize logger, but configuration (handlers, level) will happen in main()
logger = logging.getLogger('recon_tool')
# Set a default level to INFO for early messages if any, before main() configures it.
# This logger should not have handlers attached yet to avoid duplicates.
logger.setLevel(logging.INFO)
logger.propagate = False # Crucial to prevent logs from propagating to the root logger

# --- Safe imports with error handling ---
def safe_import(module_name, items=None):
    """Safely import modules and return available functions/classes."""
    try:
        if items:
            module = __import__(module_name, fromlist=items)
            imported_items = {}
            found_any = False
            for item in items:
                attr = getattr(module, item, None)
                imported_items[item] = attr
                if attr is not None:
                    found_any = True
            
            if not found_any:
                logger.warning(f"⚠️ Module '{module_name}' imported, but none of the specified items ({', '.join(items)}) were found. Skipping module functionality.")
                return {} # Return empty dict to indicate failure
            logger.debug(f"Successfully imported items {', '.join(items)} from module: {module_name}")
            return imported_items
        else:
            module = __import__(module_name)
            logger.debug(f"Successfully imported module: {module_name}")
            return {module_name: module} # Return module itself if no specific items requested
    except ImportError as e:
        logger.warning(f"⚠️ Module '{module_name}' not available: {e}. Skipping module functionality.")
        return {} # Return empty dict to indicate failure
    except Exception as e:
        logger.error(f"❌ Error during safe import of '{module_name}': {e}. Skipping module functionality.")
        return {}

# --- Core imports (should always work, with a fallback for setup_logging) ---
try:
    # Attempt to import setup_logging from utils.py
    from utils import setup_logging
except ImportError:
    # Fallback setup_logging if utils is not available
    def setup_logging(level):
        """Sets up logging for the recon tool, ensuring only one handler is added."""
        tool_logger = logging.getLogger('recon_tool')
        # Check if handlers are already present to prevent duplicates
        if not tool_logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
            handler.setFormatter(formatter)
            tool_logger.addHandler(handler)
            tool_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
            tool_logger.propagate = False # Prevent logs from being passed to the root logger
        return tool_logger

# --- Proxy manager import with better error handling ---
AdvancedProxyManager_module = safe_import('proxy_manager', ['AdvancedProxyManager'])
AdvancedProxyManager = AdvancedProxyManager_module.get('AdvancedProxyManager')

if not AdvancedProxyManager:
    logger.warning("⚠️ Advanced proxy manager not available. Proxy functionality will be disabled.")

# --- Module imports with fallbacks ---
# Each module should return a dictionary of its exposed functions.
# If a module is not found or items are not found, its entry will be an empty dictionary.
modules = {
    'port_scan': safe_import('port_scan', ['scan_ports', 'check_root_privileges']),
    'banner_grab': safe_import('banner_grab', ['grab_banners']),
    'cms': safe_import('cms', ['cms_recon']),
    'http_fingerprint': safe_import('http_fingerprint', ['fingerprint_http']),
    'dir_enum': safe_import('dir_enum', ['dir_enum']),
    'vuln_scan': safe_import('vuln_scan', ['vuln_scan']),
    'dns_enum': safe_import('dns_enum', ['query_dns']),
    'subdomains': safe_import('subdomains', ['fetch_subdomains']),
    'whois_lookup': safe_import('whois_lookup', ['EnhancedWhoisLookup']), # Import the class
    'firewall_detect': safe_import('firewall_detect', ['firewall_detect']),
    'header_analyzer': safe_import('header_analyzer', ['header_analyzer', '_analyze_ports_async']),
    'cve_lookup': safe_import('cve_lookup', ['cve_lookup', 'cleanup_resources']),
    'db_integration': safe_import('db_integration', ['init_db', 'db_integration', 'cleanup_database_connections']),
    'report_generator': safe_import('report_generator', ['enhanced_report_generator'])
}

ALL_MODULES = [
    "port_scan", "banner_grab", "cms", "http_fingerprint", "dir_enum",
    "vuln_scan", "dns_enum", "subdomains", "whois_lookup",
    "firewall_detect", "header_analyzer", "cve_lookup", "db_integration",
    "report_generator"
]

# Global variables with thread safety
proxy_manager = None
_cleanup_lock = threading.Lock()
_cleanup_done = False

def validate_modules(requested_modules: list) -> list:
    """Validate requested modules and filter for availability."""
    if not requested_modules or "all" in requested_modules:
        requested_modules = ALL_MODULES
    
    available_modules = []
    for mod_name in requested_modules:
        if mod_name not in ALL_MODULES:
            logger.warning(f"[!] Unknown module: '{mod_name}'. Skipping.")
        elif not is_module_available(mod_name):
            # is_module_available already logs a warning via safe_import
            pass 
        else:
            available_modules.append(mod_name)
    
    return list(set(available_modules))

def is_module_available(module_name: str) -> bool:
    """Check if a module is actually available and functional (has at least one function)."""
    module_dict = modules.get(module_name, {})
    return any(v is not None for v in module_dict.values())

async def initialize_proxy_manager(proxy_sources: list, use_proxy: bool):
    """Initialize proxy manager if proxy usage is enabled."""
    global proxy_manager
    
    if not use_proxy:
        logger.info("🔴 Proxy usage disabled - using direct connections.")
        return None
    
    if not AdvancedProxyManager:
        logger.warning("⚠️ AdvancedProxyManager class not found. Proxy functionality disabled.")
        return None
    
    try:
        logger.info("🔧 Initializing proxy manager...")
        proxy_manager = AdvancedProxyManager()
        
        if proxy_sources:
            # Check if proxy_list.txt exists and is not empty before trying to load
            if os.path.exists(proxy_sources[0]) and os.path.getsize(proxy_sources[0]) > 0:
                await proxy_manager.initialize(proxy_sources)
            else:
                logger.warning(f"Proxy list file '{proxy_sources[0]}' not found or is empty. Initializing proxy manager without sources.")
                await proxy_manager.initialize([])
        else:
            logger.warning("No proxy sources provided, initializing with empty list.")
            await proxy_manager.initialize([])
            
        logger.info("✅ Proxy manager initialized successfully.")
        return proxy_manager
    except Exception as e:
        logger.error(f"❌ Failed to initialize proxy manager: {e}")
        logger.warning("🔄 Falling back to direct connections.")
        proxy_manager = None
        return None

async def get_proxy():
    """Get optimal proxy or None for direct connection."""
    global proxy_manager
    if proxy_manager:
        try:
            return await proxy_manager.get_optimal_proxy()
        except Exception as e:
            logger.error(f"Failed to get proxy: {e}. Using direct connection.")
    return None

def cleanup_proxy_manager():
    """Cleanup proxy manager on exit with thread safety."""
    global proxy_manager, _cleanup_done
    
    with _cleanup_lock:
        if _cleanup_done or not proxy_manager:
            return
        
        _cleanup_done = True
        logger.info("Closing proxy manager...")
        
        try:
            try:
                loop = asyncio.get_running_loop()
                task = loop.create_task(proxy_manager.close())
                # Do not await or block here in atexit, let the event loop handle it
            except RuntimeError:
                # No running loop, create a new one for cleanup if necessary
                try:
                    asyncio.run(proxy_manager.close())
                except Exception as cleanup_error:
                    logger.debug(f"Proxy cleanup error during new loop: {cleanup_error}")
        except Exception as e:
            logger.debug(f"Error during proxy cleanup: {e}")
        finally:
            proxy_manager = None

def stealth_delay():
    """Introduces a random delay for stealth."""
    delay = random.uniform(0.5, 3.0)
    logger.debug(f"Stealth delay: {delay:.2f}s")
    time.sleep(delay)

def is_ip_address(target: str) -> bool:
    """Check if target is a valid IP address."""
    try:
        ipaddress.ip_address(target.strip())
        return True
    except (ValueError, AttributeError):
        return False

def resolve_target(target: str):
    """Resolve target to IP and domain with improved error handling."""
    resolved_info = {
        'original_target': target,
        'ip_address': None,
        'domain_name': None,
        'original_type': None
    }

    target = target.strip()
    
    if is_ip_address(target):
        resolved_info['original_type'] = 'ip'
        resolved_info['ip_address'] = target
        try:
            addr = dns.reversename.from_address(target)
            answers = dns.resolver.resolve(addr, 'PTR', lifetime=10)
            resolved_info['domain_name'] = str(answers[0]).rstrip('.')
            logger.info(f"Resolved IP {target} to domain: {resolved_info['domain_name']}")
        except Exception as e:
            logger.debug(f"Reverse DNS failed for {target}: {e}")
    else:
        resolved_info['original_type'] = 'domain'
        resolved_info['domain_name'] = target
        try:
            answers = dns.resolver.resolve(target, 'A', lifetime=10)
            resolved_info['ip_address'] = str(answers[0])
            logger.info(f"Resolved domain {target} to IP: {resolved_info['ip_address']}")
        except Exception as e:
            logger.debug(f"Forward DNS failed for {target}: {e}")
    
    return resolved_info

@asynccontextmanager
async def managed_resources():
    """Context manager for proper resource cleanup."""
    try:
        yield
    finally:
        cleanup_proxy_manager()
        # atexit registered functions will run on program exit

def get_function_signature(func):
    """Get function signature to check supported parameters."""
    try:
        return inspect.signature(func)
    except (ValueError, TypeError, AttributeError):
        return None

def filter_kwargs(func, kwargs):
    """Filter kwargs to only include parameters supported by the function."""
    if func is None:
        return {}
    
    sig = get_function_signature(func)
    if sig is None:
        return {}
    
    param_names = set(sig.parameters.keys())
    
    filtered = {}
    removed = set()
    for k, v in kwargs.items():
        if k in param_names:
            filtered[k] = v
        else:
            removed.add(k)
    
    if removed:
        logger.debug(f"Filtered unsupported parameters for {func.__name__}: {removed}")
    
    return filtered

def safe_module_call(module_name, function_name, *args, **kwargs):
    """Safely call a module function with error handling and parameter filtering."""
    try:
        if not is_module_available(module_name):
            return None
            
        module_dict = modules.get(module_name, {})
        func = module_dict.get(function_name)
        
        if func is None:
            logger.warning(f"Function '{function_name}' not found in module '{module_name}'.")
            return None
        
        filtered_kwargs = filter_kwargs(func, kwargs)
        
        return func(*args, **filtered_kwargs)
    except Exception as e:
        logger.error(f"❌ Error calling {module_name}.{function_name}: {e}")
        return None

async def safe_async_module_call(module_name, function_name, *args, **kwargs):
    """Safely call an async module function with error handling and parameter filtering."""
    try:
        if not is_module_available(module_name):
            return None
            
        module_dict = modules.get(module_name, {})
        func = module_dict.get(function_name)
        
        if func is None:
            logger.warning(f"Async function '{function_name}' not found in module '{module_name}'.")
            return None
        
        filtered_kwargs = filter_kwargs(func, kwargs)
        
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **filtered_kwargs)
        else:
            logger.debug(f"Function '{function_name}' in module '{module_name}' is not a coroutine. Calling synchronously.")
            return func(*args, **filtered_kwargs)
    except Exception as e:
        logger.error(f"❌ Error calling async {module_name}.{function_name}: {e}")
        return None

async def main_async():
    """Main async function with improved error handling and resource management."""
    global logger, proxy_manager # Ensure global variables are referenced
    
    parser = argparse.ArgumentParser(description="🔍 Python Recon Automation Tool")
    parser.add_argument("--target", "-t", required=True, help="Target IP or domain")
    parser.add_argument("--ports", default="80,443", help="Comma-separated port list")
    parser.add_argument("--modules", nargs="*", default=ALL_MODULES, 
                       help="Modules to run (or 'all'). Defaults to all available modules.")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth scan delays")
    parser.add_argument("--db", default="recon.db", help="SQLite DB path")
    parser.add_argument("--output", default="recon_results", help="Report output directory")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--use-proxy", action="store_true", help="Enable proxy usage")
    parser.add_argument("--proxy-list", default="proxy_list.txt", help="Path to proxy list file")
    parser.add_argument("--deepseek-api-key", help="API key for DeepSeek AI analysis")
    parser.add_argument("--concurrency-limit", type=int, default=10,
                       help="Maximum concurrent requests/workers")
    # New argument for custom report base name
    parser.add_argument("--report-base-name", help="Base name for the generated report files (e.g., 'my_scan_results'). If not provided, target name will be used.")


    args = parser.parse_args()

    # Create output directory with error handling
    try:
        os.makedirs(args.output, exist_ok=True)
    except Exception as e:
        logger.error(f"❌ Failed to create output directory {args.output}: {e}")
        sys.exit(1)

    # Reconfigure logger level based on verbose argument
    logger.setLevel(getattr(logging, "DEBUG" if args.verbose else "INFO", logging.INFO))


    async with managed_resources():
        # Resolve target with validation
        resolved_target_info = resolve_target(args.target)
        target_ip = resolved_target_info['ip_address']
        target_domain = resolved_target_info['domain_name']
        original_target_type = resolved_target_info['original_type']
        
        if not target_ip and not target_domain:
            logger.error(f"❌ Failed to resolve target '{args.target}'. Exiting.")
            sys.exit(1)

        # Determine report base name based on user input or target
        report_base_name = args.report_base_name if args.report_base_name else \
                           (target_domain if target_domain else target_ip).replace('.', '_')
        
        # Database initialization with error handling
        if is_module_available('db_integration') and modules['db_integration'].get('init_db'):
            try:
                logger.info(f"Initializing database at {args.db}...")
                db_result = safe_module_call('db_integration', 'init_db', args.db)
                if db_result and isinstance(db_result, dict) and 'error' in db_result:
                    logger.error(f"Database initialization failed: {db_result['error']}")
                else:
                    logger.info("Database initialized successfully.")
            except Exception as e:
                logger.error(f"Database initialization error: {e}")

        # Register cleanup functions
        if is_module_available('db_integration') and modules.get('db_integration', {}).get('cleanup_database_connections'):
            atexit.register(modules['db_integration']['cleanup_database_connections'])
        if is_module_available('cve_lookup') and modules.get('cve_lookup', {}).get('cleanup_resources'):
            atexit.register(modules['cve_lookup']['cleanup_resources'])
        atexit.register(cleanup_proxy_manager)

        # Check root privileges if available
        if is_module_available('port_scan') and modules.get('port_scan', {}).get('check_root_privileges'):
            try:
                if not modules['port_scan']['check_root_privileges']():
                    logger.warning("⚠️ Root privileges not found. Some scans will be limited.")
            except Exception as e:
                logger.debug(f"Root privilege check failed: {e}")

        # Initialize proxy manager
        proxy_sources = [args.proxy_list] if os.path.exists(args.proxy_list) else []
        await initialize_proxy_manager(proxy_sources, args.use_proxy)
        proxy = await get_proxy()

        if args.use_proxy and not proxy:
            logger.warning("⚠️ Proxy requested but unavailable - using direct connection.")

        # Parse ports with validation
        try:
            ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]
            if not ports:
                logger.warning("No valid ports specified, using default 80,443")
                ports = [80, 443]
        except Exception as e:
            logger.error(f"Port parsing error: {e}. Using defaults.")
            ports = [80, 443]

        findings = {'target': args.target}
        args.modules = validate_modules(args.modules)

        # Log scan information
        logger.info("📌 Target: %s (%s)", args.target, original_target_type)
        if target_ip: 
            logger.info("   IP: %s", target_ip)
        if target_domain: 
            logger.info("   Domain: %s", target_domain)
        logger.info("📦 Modules: %s", ', '.join(args.modules) if args.modules else "None")
        
        proxy_status = "✅ Enabled" if proxy else ("❌ Unavailable" if args.use_proxy else "Disabled")
        logger.info(f"🌐 Proxy: {proxy_status}")
        logger.info(f"⚡ Concurrency: {args.concurrency_limit}")

        try:
            # Execute modules with improved error handling
            
            # Domain-based modules
            if "subdomains" in args.modules and target_domain:
                logger.info("Starting subdomain enumeration...")
                if args.stealth: stealth_delay()
                result = safe_module_call('subdomains', 'fetch_subdomains', 
                                        target_domain, 
                                        proxies=proxy, 
                                        stealth=args.stealth,
                                        timeout=30)
                if result: 
                    findings['subdomains'] = result
                    logger.info("Subdomain enumeration completed.")
                else:
                    logger.warning("Subdomain enumeration returned no results or failed.")

            if "dns_enum" in args.modules and target_domain:
                logger.info("Starting DNS enumeration...")
                if args.stealth: stealth_delay()
                result = safe_module_call('dns_enum', 'query_dns', 
                                        target_domain, 
                                        proxies=proxy, 
                                        cache_file=None)
                if result: 
                    findings['dns'] = result
                    logger.info("DNS enumeration completed.")
                else:
                    logger.warning("DNS enumeration returned no results or failed.")

            if "whois_lookup" in args.modules and target_domain:
                logger.info("Starting WHOIS lookup...")
                if args.stealth: stealth_delay()
                
                # Retrieve the EnhancedWhoisLookup class from the modules dictionary
                EnhancedWhoisLookupClass = modules['whois_lookup'].get('EnhancedWhoisLookup')
                
                if EnhancedWhoisLookupClass:
                    # Instantiate the class
                    whois_tool = EnhancedWhoisLookupClass()
                    # Call the lookup method
                    lookup_result = whois_tool.lookup(target_domain, proxies=proxy)
                    
                    if lookup_result:
                        findings['whois'] = lookup_result.to_dict()
                        logger.info("WHOIS lookup completed.")
                        
                        # Also get DNS info using the tool's method
                        dns_info_from_whois = whois_tool.get_dns_info(target_domain)
                        if dns_info_from_whois:
                            # Merge or store DNS info, possibly under a new key if it's distinct from dns_enum
                            if 'dns' not in findings:
                                findings['dns'] = dns_info_from_whois
                            else:
                                # Example: merge A records if both modules provide them
                                if 'A_records' in dns_info_from_whois and 'A_records' in findings['dns']:
                                    findings['dns']['A_records'].extend(dns_info_from_whois['A_records'])
                                    findings['dns']['A_records'] = list(set(findings['dns']['A_records'])) # Remove duplicates
                                # You can add more complex merging logic here
                                logger.debug("Merged DNS info from whois_lookup into existing DNS findings.")
                            logger.info("DNS information from WHOIS lookup integrated.")
                    else:
                        logger.warning("WHOIS lookup returned no results or failed.")
                else:
                    logger.warning("EnhancedWhoisLookup class not found in whois_lookup module. Skipping WHOIS functionality.")


            # IP-based modules
            if "port_scan" in args.modules and target_ip:
                logger.info("Starting port scan...")
                if args.stealth: stealth_delay()
                result = safe_module_call('port_scan', 'scan_ports', 
                                        target_ip, 
                                        ports=ports, 
                                        stealth=args.stealth)
                if result: 
                    findings['open_ports'] = result
                    logger.info(f"Port scan completed. Found {len(result)} open ports.")
                else:
                    logger.warning("Port scan found no open ports or failed.")

            if "banner_grab" in args.modules and target_ip and findings.get('open_ports'):
                logger.info("Starting banner grabbing...")
                if args.stealth: stealth_delay()
                result = safe_module_call('banner_grab', 'grab_banners', 
                                        target_ip, 
                                        findings['open_ports'], 
                                        args.stealth, 
                                        proxy, 
                                        None)
                if result: 
                    findings['banners'] = result
                    logger.info("Banner grabbing completed.")
                else:
                    logger.warning("Banner grabbing returned no results or failed.")

            if "vuln_scan" in args.modules and target_ip and findings.get('open_ports'):
                logger.info("Starting vulnerability scan...")
                if args.stealth: stealth_delay()
                result = safe_module_call('vuln_scan', 'vuln_scan', 
                                        target_ip, 
                                        findings['open_ports'], 
                                        proxy)
                if result: 
                    findings['vulnerabilities'] = result
                    logger.info("Vulnerability scanning completed.")
                else:
                    logger.warning("Vulnerability scan found no vulnerabilities or failed.")

            if "firewall_detect" in args.modules and target_ip:
                logger.info("Starting firewall detection...")
                if args.stealth: stealth_delay()
                result = safe_module_call('firewall_detect', 'firewall_detect', 
                                        target_ip, 
                                        findings.get('open_ports', []), 
                                        args.stealth, 
                                        proxy)
                if result: 
                    findings['firewall'] = result
                    logger.info("Firewall detection completed.")
                else:
                    logger.warning("Firewall detection returned no results or failed.")

            # Flexible modules (can use domain or IP)
            if "cms" in args.modules and (target_domain or target_ip):
                logger.info("Starting CMS reconnaissance...")
                if args.stealth: stealth_delay()
                target_for_cms = target_domain or target_ip
                result = safe_module_call('cms', 'cms_recon', 
                                        target_for_cms, 
                                        findings.get('open_ports', []), 
                                        args.stealth, 
                                        proxy,
                                        concurrency_limit=args.concurrency_limit)
                if result: 
                    findings['cms'] = result
                    logger.info("CMS reconnaissance completed.")
                else:
                    logger.warning("CMS reconnaissance returned no results or failed.")

            if "dir_enum" in args.modules and (target_domain or target_ip):
                logger.info("Starting directory enumeration...")
                if args.stealth: stealth_delay()
                target_for_dir = target_domain or target_ip
                result = safe_module_call('dir_enum', 'dir_enum', 
                                        target_for_dir, 
                                        findings.get('open_ports', []),
                                        wordlist_path=None, 
                                        stealth=args.stealth, 
                                        proxies=proxy,
                                        cache_file=None, 
                                        cms=findings.get('cms', {}).get('name'),
                                        output_dir=args.output, 
                                        formats=['json', 'html'],
                                        max_workers=args.concurrency_limit)
                if result: 
                    findings['dir_enum'] = result
                    logger.info("Directory enumeration completed.")
                else:
                    logger.warning("Directory enumeration returned no results or failed.")

            if "http_fingerprint" in args.modules and (target_domain or target_ip):
                logger.info("Starting HTTP fingerprinting...")
                if args.stealth: stealth_delay()
                target_for_http = target_domain or target_ip
                result = safe_module_call('http_fingerprint', 'fingerprint_http',
                                        target_for_http, 
                                        findings.get('open_ports', []),
                                        stealth=args.stealth, 
                                        proxies=proxy, 
                                        cache_file=None,
                                        max_workers=args.concurrency_limit)
                if result: 
                    findings['http_fingerprint'] = result
                    logger.info("HTTP fingerprinting completed.")
                else:
                    logger.warning("HTTP fingerprinting returned no results or failed.")

            if "header_analyzer" in args.modules and (target_domain or target_ip):
                logger.info("Starting header analysis...")
                if args.stealth: stealth_delay()
                target_for_headers = target_domain or target_ip
                result = await safe_async_module_call('header_analyzer', '_analyze_ports_async',
                                                    target_for_headers, 
                                                    findings.get('open_ports', []),
                                                    args.stealth, 
                                                    proxy, 
                                                    timeout=10,
                                                    concurrency_limit=args.concurrency_limit)
                if result:
                    findings['headers'] = {
                        'target': target_for_headers,
                        'ports': result,
                        'scan_metadata': {
                            'timestamp': datetime.now().isoformat(),
                            'stealth_mode': args.stealth,
                            'async_mode': True,
                            'total_ports': len(ports)
                        },
                        'changes': {}
                    }
                    logger.info("Header analysis completed.")
                else:
                    logger.warning("Header analysis returned no results or failed.")

            # General modules
            if "cve_lookup" in args.modules:
                logger.info("Starting CVE lookup...")
                if args.stealth: stealth_delay()
                # Passing deepseek_api_key to cve_lookup. This assumes cve_lookup can use
                # this API key for NVD or other services it might query.
                result = safe_module_call('cve_lookup', 'cve_lookup', 
                                        args.target, 
                                        findings, 
                                        proxy, 
                                        api_key=args.deepseek_api_key) 
                if result: 
                    findings['cves'] = result
                    logger.info("CVE lookup completed.")
                else:
                    logger.warning("CVE lookup returned no results or failed.")

            if "db_integration" in args.modules:
                logger.info("Starting database integration...")
                result = safe_module_call('db_integration', 'db_integration', 
                                        findings, 
                                        args.db)
                if result and isinstance(result, dict) and 'error' in result:
                    logger.error(f"Database integration failed: {result['error']}")
                else:
                    logger.info("Database integration completed.")

            if "report_generator" in args.modules:
                logger.info("Generating reports...")
                report_gen_func = modules['report_generator'].get('enhanced_report_generator')
                if report_gen_func:
                    # --- Interactive report type selection ---
                    available_report_options = {
                        1: "advanced",
                        2: "comprehensive"
                    }
                    selected_report_types = []
                    
                    while True:
                        print("\nSelect report types to generate (enter numbers separated by commas, or 'q' to skip):")
                        for num, r_type in available_report_options.items():
                            print(f"  {num}: {r_type.capitalize()} Report")
                        
                        user_input = input("Your choice(s): ").strip()
                        if user_input.lower() == 'q':
                            break
                        
                        try:
                            choices = [int(c.strip()) for c in user_input.split(',') if c.strip().isdigit()]
                            for choice in choices:
                                if choice in available_report_options:
                                    selected_report_types.append(available_report_options[choice])
                                else:
                                    print(f"Invalid choice: {choice}. Please select from the menu.")
                            selected_report_types = list(set(selected_report_types)) # Remove duplicates
                            if selected_report_types:
                                break
                            else:
                                print("No valid report types selected. Please try again.")
                        except ValueError:
                            print("Invalid input. Please enter numbers separated by commas.")

                    if not selected_report_types:
                        logger.info("No report types selected. Skipping report generation.")
                    else:
                        logger.info(f"Generating: {', '.join(selected_report_types)} reports.")
                        
                        # Modified to use safe_module_call for enhanced_report_generator
                        result = safe_module_call(
                                                'report_generator', 
                                                'enhanced_report_generator',
                                                findings=findings, 
                                                output_dir=args.output, 
                                                deepseek_api_key=args.deepseek_api_key,
                                                report_types=selected_report_types, 
                                                report_base_name=report_base_name) 
                        if result:
                            print(f"\n📄 Reports saved to: {json.dumps(result, indent=2)}")
                            logger.info("Report generation completed.")
                        else:
                            logger.warning("Report generation failed or returned no results.")
                else:
                    logger.warning("Report generation module 'enhanced_report_generator' is not available.")


            logger.info("✅ Scan Complete. Output: %s", os.path.abspath(args.output))

            # Display proxy stats
            if proxy_manager:
                try:
                    stats = proxy_manager.get_stats()
                    logger.info(f"📊 Proxy Stats: {stats.get('healthy_proxies', 0)}/"
                              f"{stats.get('total_proxies', 0)} healthy, "
                              f"avg response: {stats.get('average_response_time', 0):.0f}ms")
                except Exception as e:
                    logger.debug(f"Failed to get proxy stats: {e}")

        except KeyboardInterrupt:
            logger.info("🛑 Scan interrupted by user.")
            raise
        except Exception as e:
            logger.exception(f"❌ Error during scan: {e}")
            raise

def main():
    """Main entry point with proper exception handling and logging setup."""
    # Setup logging globally for the application ONCE
    try:
        global logger
        # Ensure we are configuring the 'recon_tool' logger and not adding duplicate handlers.
        # The setup_logging function itself should handle checking for existing handlers.
        logger = setup_logging("INFO")
        
        logger.info("Application starting...")
    except Exception as e:
        print(f"❌ Fatal: Logging setup failed at application start: {e}")
        sys.exit(1)

    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n🛑 Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        if logger:
            logger.critical(f"❌ Fatal error during scan execution: {e}", exc_info=True)
        else:
            print(f"❌ Fatal error during scan execution: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

