import logging
import socket
from pathlib import Path
from typing import Optional, Dict
import random
import time
import json
import os

def setup_logging(level: str) -> logging.Logger:
    """Configure logging with specified verbosity level.
    
    Args:
        level: Logging level ('DEBUG', 'INFO', 'WARNING')
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger('recon_tool')
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    )
    logger.addHandler(console_handler)
    
    # File handler
    log_dir = Path('reports')
    log_dir.mkdir(exist_ok=True)
    file_handler = logging.FileHandler(log_dir / 'recon.log')
    file_handler.setFormatter(
        logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    )
    logger.addHandler(file_handler)
    
    return logger

def check_tor() -> bool:
    """Check if TOR service is running on localhost:9050.
    
    Returns:
        True if TOR is available, False otherwise
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            return s.connect_ex(('127.0.0.1', 9050)) == 0
    except (socket.error, ConnectionError):
        return False

def get_proxies() -> Optional[Dict[str, str]]:
    """Return proxy configuration for TOR if available.
    
    Returns:
        Dictionary with proxy settings or None if TOR is unavailable
    """
    if check_tor():
        return {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
    return None

def stealth_delay() -> None:
    """Add randomized delay for stealth mode (0.5-3 seconds)."""
    time.sleep(random.uniform(0.5, 3.0))

def generate_report(data: Dict, filename: str, format_type: str) -> None:
    """Generate text or HTML report from scan results.
    
    Args:
        data: Dictionary containing scan results
        filename: Output file path (sanitized)
        format_type: 'txt' or 'html'
    """
    safe_filename = Path(filename).resolve()
    safe_filename.parent.mkdir(exist_ok=True)
    
    try:
        if format_type == 'html':
            with open(safe_filename, 'w', encoding='utf-8') as f:
                f.write('<html><head><title>Recon Report</title></head><body>')
                f.write(f'<h1>Reconnaissance Report - {data.get("target", "Unknown")}</h1>')
                f.write(f'<p>Timestamp: {data.get("timestamp", "")}</p>')
                f.write(f'<p>Scan Mode: {data.get("scan_mode", "Unknown")}</p>')
                for module, results in data.get('modules', {}).items():
                    f.write(f'<h2>{module.capitalize()}</h2><pre>{json.dumps(results, indent=2)}</pre>')
                if 'risk_analysis' in data:
                    f.write(f'<h2>Risk Analysis</h2><pre>{json.dumps(data["risk_analysis"], indent=2)}</pre>')
                f.write('</body></html>')
        else:
            with open(safe_filename, 'w', encoding='utf-8') as f:
                f.write(f'Reconnaissance Report - {data.get("target", "Unknown")}\n')
                f.write(f'Timestamp: {data.get("timestamp", "")}\n')
                f.write(f'Scan Mode: {data.get("scan_mode", "Unknown")}\n\n')
                for module, results in data.get('modules', {}).items():
                    f.write(f'{module.capitalize()}:\n{json.dumps(results, indent=2)}\n\n')
                if 'risk_analysis' in data:
                    f.write(f'Risk Analysis:\n{json.dumps(data["risk_analysis"], indent=2)}\n')
    except OSError as e:
        logger = logging.getLogger('recon_tool')
        logger.error(f"Failed to write report to {safe_filename}: {e}")

if __name__ == '__main__':
    # Test the module independently
    logger = setup_logging('DEBUG')
    logger.info("Testing utils module")
    logger.info(f"TOR available: {check_tor()}")
    logger.info(f"Proxies: {get_proxies()}")
    stealth_delay()
    logger.info("Stealth delay applied")
    test_data = {
        'target': 'example.com',
        'timestamp': '2025-06-03T05:55:00',
        'scan_mode': 'stealth',
        'modules': {'whois': {'registrar': 'Test'}}
    }
    generate_report(test_data, 'reports/test.txt', 'txt')
    generate_report(test_data, 'reports/test.html', 'html')