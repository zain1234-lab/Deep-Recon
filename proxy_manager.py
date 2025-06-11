import logging
import asyncio
import aiohttp
import threading
import time
import json
import random
import socket
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path
from urllib.parse import urlparse
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, deque
import ipaddress
import hashlib

logger = logging.getLogger('recon_tool')

@dataclass
class ProxyMetrics:
    """Comprehensive proxy performance metrics"""
    response_time: float = 0.0
    success_rate: float = 0.0
    last_used: float = 0.0
    failure_count: int = 0
    success_count: int = 0
    location: Optional[str] = None
    anonymity_level: str = "unknown"
    connection_count: int = 0
    bandwidth_score: float = 0.0
    
    def calculate_score(self) -> float:
        """Calculate overall proxy quality score"""
        if self.success_count + self.failure_count == 0:
            return 0.0
        
        success_weight = 0.4
        speed_weight = 0.3
        reliability_weight = 0.2
        freshness_weight = 0.1
        
        success_score = self.success_rate * success_weight
        speed_score = max(0, (5000 - self.response_time) / 5000) * speed_weight
        reliability_score = max(0, (10 - self.failure_count) / 10) * reliability_weight
        freshness_score = max(0, 1 - (time.time() - self.last_used) / 3600) * freshness_weight
        
        return success_score + speed_score + reliability_score + freshness_score

@dataclass
class ProxyConfig:
    """Enhanced proxy configuration"""
    scheme: str
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    proxy_type: str = "http"
    
    @property
    def url(self) -> str:
        if self.username and self.password:
            return f"{self.scheme}://{self.username}:{self.password}@{self.host}:{self.port}"
        return f"{self.scheme}://{self.host}:{self.port}"
    
    @property
    def identifier(self) -> str:
        return f"{self.host}:{self.port}"

class AdvancedProxyManager:
    """Ultra-advanced reconnaissance proxy manager with intelligent routing"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.proxies: Dict[str, ProxyConfig] = {}
        self.metrics: Dict[str, ProxyMetrics] = {}
        self.blacklist: Set[str] = set()
        self.circuit_breakers: Dict[str, float] = {}
        self.rotation_queue = deque()
        self.connection_pools: Dict[str, Any] = {}
        self.geolocation_cache = {}
        
        # Performance settings
        self.max_concurrent_checks = self.config.get('max_concurrent_checks', 50)
        self.health_check_interval = self.config.get('health_check_interval', 300)
        self.max_failures = self.config.get('max_failures', 5)
        self.timeout = self.config.get('timeout', 10)
        self.retry_blacklist_after = self.config.get('retry_blacklist_after', 1800)
        
        # Reconnaissance-specific settings
        self.stealth_mode = self.config.get('stealth_mode', True)
        self.geolocation_aware = self.config.get('geolocation_aware', True)
        self.adaptive_rotation = self.config.get('adaptive_rotation', True)
        self.fingerprint_evasion = self.config.get('fingerprint_evasion', True)
        
        self._health_monitor_task = None
        self._stats_lock = threading.RLock()
        self._direct_mode = False
        self._shutdown_flag = False
        
    async def initialize(self, proxy_sources: List[str]) -> None:
        """Initialize proxy manager with multiple sources"""
        logger.info("Initializing advanced reconnaissance proxy manager")
        
        # Load proxies from multiple sources
        all_proxies = []
        for source in proxy_sources:
            if source.startswith('http'):
                proxies = await self._fetch_remote_proxies(source)
            else:
                proxies = await self._load_local_proxies(source)
            all_proxies.extend(proxies)
        
        # Validate and test proxies concurrently
        valid_proxies = await self._batch_validate_proxies(all_proxies)
        
        # Initialize metrics and connection pools
        for proxy in valid_proxies:
            self.proxies[proxy.identifier] = proxy
            self.metrics[proxy.identifier] = ProxyMetrics()
            
        # Start health monitoring
        if self._health_monitor_task is None:
            self._health_monitor_task = asyncio.create_task(self._health_monitor())
        
        # Restore previous state if available
        await self._restore_state()
            
        logger.info(f"Initialized with {len(valid_proxies)} validated proxies")
    
    async def _fetch_remote_proxies(self, url: str) -> List[ProxyConfig]:
        """Fetch proxies from remote sources"""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        return self._parse_proxy_list(content)
        except Exception as e:
            logger.error(f"Failed to fetch remote proxies from {url}: {e}")
        return []
    
    async def _load_local_proxies(self, filepath: str) -> List[ProxyConfig]:
        """Load proxies from local file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                return self._parse_proxy_list(content)
        except Exception as e:
            logger.error(f"Failed to load local proxies from {filepath}: {e}")
        return []
    
    def _parse_proxy_list(self, content: str) -> List[ProxyConfig]:
        """Parse proxy list from various formats"""
        proxies = []
        lines = content.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            try:
                # Handle JSON format
                if line.startswith('{'):
                    data = json.loads(line)
                    proxy = ProxyConfig(**data)
                # Handle URL format
                elif '://' in line:
                    proxy = self._parse_proxy_url(line)
                # Handle IP:PORT format
                elif ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        proxy = ProxyConfig(
                            scheme='http',
                            host=parts[0],
                            port=int(parts[1])
                        )
                    else:
                        continue
                else:
                    continue
                    
                if proxy:
                    proxies.append(proxy)
                    
            except Exception as e:
                logger.debug(f"Failed to parse proxy line '{line}': {e}")
                continue
                
        return proxies
    
    def _parse_proxy_url(self, url: str) -> Optional[ProxyConfig]:
        """Parse proxy from URL format"""
        try:
            parsed = urlparse(url)
            if not parsed.hostname or not parsed.port:
                return None
                
            return ProxyConfig(
                scheme=parsed.scheme,
                host=parsed.hostname,
                port=parsed.port,
                username=parsed.username,
                password=parsed.password
            )
        except Exception:
            return None
    
    async def _batch_validate_proxies(self, proxies: List[ProxyConfig]) -> List[ProxyConfig]:
        """Validate proxies in batches for speed"""
        valid_proxies = []
        
        # Create semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(self.max_concurrent_checks)
        
        async def validate_single(proxy: ProxyConfig) -> Optional[ProxyConfig]:
            async with semaphore:
                if await self._test_proxy_advanced(proxy):
                    return proxy
                return None
        
        # Execute validation tasks
        tasks = [validate_single(proxy) for proxy in proxies]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ProxyConfig):
                valid_proxies.append(result)
                
        return valid_proxies
    
    async def _test_proxy_advanced(self, proxy: ProxyConfig) -> bool:
        """Advanced proxy testing with multiple endpoints"""
        test_urls = [
            'http://httpbin.org/ip',
            'https://api.ipify.org?format=json',
            'http://ip-api.com/json/?fields=query,country,city,isp'
        ]
        
        start_time = time.time()
        
        try:
            connector = aiohttp.ProxyConnector.from_url(proxy.url)
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=self._get_stealth_headers() if self.stealth_mode else {}
            ) as session:
                
                # Test connectivity with first available endpoint
                for url in test_urls:
                    try:
                        async with session.get(url) as response:
                            if response.status == 200:
                                response_time = (time.time() - start_time) * 1000
                                
                                # Update metrics
                                identifier = proxy.identifier
                                if identifier not in self.metrics:
                                    self.metrics[identifier] = ProxyMetrics()
                                
                                self.metrics[identifier].response_time = response_time
                                self.metrics[identifier].last_used = time.time()
                                
                                # Extract geolocation if available
                                if 'ip-api.com' in url:
                                    data = await response.json()
                                    proxy.country = data.get('country')
                                    proxy.city = data.get('city')
                                    proxy.isp = data.get('isp')
                                
                                return True
                    except:
                        continue
                        
        except Exception as e:
            logger.debug(f"Proxy {proxy.identifier} failed validation: {e}")
            
        return False
    
    def _get_stealth_headers(self) -> Dict[str, str]:
        """Generate randomized headers for stealth operations"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        
        return {
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
        }
    
    async def get_optimal_proxy(self, 
                              target_region: Optional[str] = None,
                              exclude_regions: Optional[List[str]] = None,
                              min_success_rate: float = 0.7) -> Optional[ProxyConfig]:
        """Get the optimal proxy based on multiple factors"""
        
        with self._stats_lock:
            # Filter available proxies
            candidates = []
            
            for identifier, proxy in self.proxies.items():
                if identifier in self.blacklist:
                    continue
                    
                metrics = self.metrics.get(identifier, ProxyMetrics())
                
                # Apply filters
                if metrics.success_rate < min_success_rate and metrics.success_count > 5:
                    continue
                    
                if target_region and proxy.country != target_region:
                    continue
                    
                if exclude_regions and proxy.country in exclude_regions:
                    continue
                    
                # Calculate score and add to candidates
                score = metrics.calculate_score()
                candidates.append((proxy, metrics, score))
            
            if not candidates:
                logger.warning("No suitable proxies available")
                return None
            
            # Sort by score and apply rotation strategy
            candidates.sort(key=lambda x: x[2], reverse=True)
            
            if self.adaptive_rotation:
                # Weighted random selection from top candidates
                top_candidates = candidates[:min(5, len(candidates))]
                weights = [score for _, _, score in top_candidates]
                selected = random.choices(top_candidates, weights=weights, k=1)[0]
                return selected[0]
            else:
                # Return best proxy
                return candidates[0][0]
    
    async def get_proxy_for_target(self, target_host: str) -> Optional[ProxyConfig]:
        """Get optimal proxy for specific target with intelligent routing"""
        
        # Analyze target
        target_region = await self._get_target_region(target_host)
        
        # Select proxy strategy based on target
        if target_region:
            # Prefer proxies from different regions to avoid geographic blocking
            exclude_regions = [target_region]
            proxy = await self.get_optimal_proxy(exclude_regions=exclude_regions)
            
            if proxy:
                return proxy
        
        # Fallback to general optimal proxy
        return await self.get_optimal_proxy()
    
    async def _get_target_region(self, host: str) -> Optional[str]:
        """Determine target's geographic region"""
        if host in self.geolocation_cache:
            return self.geolocation_cache[host]
        
        try:
            # Try to resolve IP and geolocate
            ip = socket.gethostbyname(host)
            
            async with aiohttp.ClientSession() as session:
                async with session.get(f'http://ip-api.com/json/{ip}?fields=country') as response:
                    if response.status == 200:
                        data = await response.json()
                        country = data.get('country')
                        self.geolocation_cache[host] = country
                        return country
        except:
            pass
        
        return None
    
    def record_success(self, proxy_identifier: str, response_time: float = 0):
        """Record successful proxy usage"""
        with self._stats_lock:
            if proxy_identifier in self.metrics:
                metrics = self.metrics[proxy_identifier]
                metrics.success_count += 1
                metrics.last_used = time.time()
                if response_time > 0:
                    # Update rolling average
                    metrics.response_time = (metrics.response_time + response_time) / 2
                
                # Update success rate
                total = metrics.success_count + metrics.failure_count
                metrics.success_rate = metrics.success_count / total if total > 0 else 0
                
                # Remove from blacklist if performance improves
                if proxy_identifier in self.blacklist and metrics.success_rate > 0.5:
                    self.blacklist.remove(proxy_identifier)
                    logger.info(f"Proxy {proxy_identifier} removed from blacklist")
    
    def record_failure(self, proxy_identifier: str, error: str = ""):
        """Record proxy failure"""
        with self._stats_lock:
            if proxy_identifier in self.metrics:
                metrics = self.metrics[proxy_identifier]
                metrics.failure_count += 1
                
                # Update success rate
                total = metrics.success_count + metrics.failure_count
                metrics.success_rate = metrics.success_count / total if total > 0 else 0
                
                # Blacklist if too many failures
                if metrics.failure_count >= self.max_failures:
                    self.blacklist.add(proxy_identifier)
                    self.circuit_breakers[proxy_identifier] = time.time()
                    logger.warning(f"Proxy {proxy_identifier} blacklisted due to failures")
    
    async def _health_monitor(self):
        """Background health monitoring"""
        while not self._shutdown_flag:
            try:
                await asyncio.sleep(self.health_check_interval)
                
                if self._shutdown_flag:
                    break
                
                # Check blacklisted proxies for recovery
                current_time = time.time()
                recovered = []
                
                for proxy_id in list(self.blacklist):
                    if (proxy_id in self.circuit_breakers and 
                        current_time - self.circuit_breakers[proxy_id] > self.retry_blacklist_after):
                        
                        # Test if proxy recovered
                        if proxy_id in self.proxies:
                            if await self._test_proxy_advanced(self.proxies[proxy_id]):
                                recovered.append(proxy_id)
                
                # Remove recovered proxies from blacklist
                for proxy_id in recovered:
                    self.blacklist.remove(proxy_id)
                    del self.circuit_breakers[proxy_id]
                    self.metrics[proxy_id].failure_count = 0
                    logger.info(f"Proxy {proxy_id} recovered and restored")
                
            except asyncio.CancelledError:
                logger.info("Health monitor cancelled")
                break
            except Exception as e:
                logger.error(f"Health monitor error: {e}")
                if self._shutdown_flag:
                    break
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive proxy statistics"""
        with self._stats_lock:
            total_proxies = len(self.proxies)
            healthy_proxies = total_proxies - len(self.blacklist)
            
            if not self.metrics:
                return {
                    'total_proxies': total_proxies,
                    'healthy_proxies': healthy_proxies,
                    'blacklisted_proxies': len(self.blacklist),
                    'average_response_time': 0,
                    'average_success_rate': 0
                }
            
            response_times = [m.response_time for m in self.metrics.values() if m.response_time > 0]
            success_rates = [m.success_rate for m in self.metrics.values() if m.success_count + m.failure_count > 0]
            
            return {
                'total_proxies': total_proxies,
                'healthy_proxies': healthy_proxies,
                'blacklisted_proxies': len(self.blacklist),
                'average_response_time': sum(response_times) / len(response_times) if response_times else 0,
                'average_success_rate': sum(success_rates) / len(success_rates) if success_rates else 0,
                'proxy_regions': self._get_region_distribution(),
                'top_performers': self._get_top_performers()
            }
    
    def _get_region_distribution(self) -> Dict[str, int]:
        """Get proxy distribution by region"""
        regions = defaultdict(int)
        for proxy in self.proxies.values():
            region = proxy.country or 'Unknown'
            regions[region] += 1
        return dict(regions)
    
    def _get_top_performers(self) -> List[Dict]:
        """Get top performing proxies"""
        performers = []
        for identifier, metrics in self.metrics.items():
            if identifier not in self.blacklist:
                proxy = self.proxies.get(identifier)
                if proxy:
                    performers.append({
                        'proxy': f"{proxy.host}:{proxy.port}",
                        'country': proxy.country,
                        'score': metrics.calculate_score(),
                        'success_rate': metrics.success_rate,
                        'response_time': metrics.response_time
                    })
        
        performers.sort(key=lambda x: x['score'], reverse=True)
        return performers[:10]
    
    async def emergency_stop(self):
        """Emergency shutdown - immediately stop all operations"""
        logger.warning("Emergency stop initiated - shutting down all proxy operations")
        
        # Cancel health monitor immediately
        if self._health_monitor_task:
            self._health_monitor_task.cancel()
        
        # Clear all proxy data
        self.proxies.clear()
        self.blacklist.clear()
        self.metrics.clear()
        
        # Force close all connections
        for pool in self.connection_pools.values():
            if hasattr(pool, 'close'):
                try:
                    await pool.close()
                except:
                    pass
        
        logger.info("Emergency stop completed - all proxy operations halted")
    
    def enable_direct_mode(self):
        """Fallback to direct connections (no proxies)"""
        logger.warning("Enabling direct connection mode - bypassing all proxies")
        self._direct_mode = True
        return None
    
    def disable_direct_mode(self):
        """Re-enable proxy usage"""
        logger.info("Re-enabling proxy mode")
        self._direct_mode = False
    
    async def get_safe_proxy(self, max_retries: int = 3) -> Optional[ProxyConfig]:
        """Get proxy with safe fallback to direct connection"""
        if hasattr(self, '_direct_mode') and self._direct_mode:
            return None  # Direct connection
        
        for attempt in range(max_retries):
            try:
                proxy = await self.get_optimal_proxy()
                if proxy:
                    return proxy
                else:
                    logger.warning(f"No proxies available on attempt {attempt + 1}")
            except Exception as e:
                logger.error(f"Proxy selection failed on attempt {attempt + 1}: {e}")
        
        # Fallback to direct connection after max retries
        logger.warning("All proxy attempts failed - falling back to direct connection")
        return None
    
    async def close(self):
        """Graceful shutdown with cleanup"""
        logger.info("Initiating graceful proxy manager shutdown")
        
        # Save current state before shutdown
        await self._save_state()
        
        # Cancel health monitor gracefully
        if self._health_monitor_task:
            self._health_monitor_task.cancel()
            try:
                await asyncio.wait_for(self._health_monitor_task, timeout=5.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                logger.debug("Health monitor task cancelled/timed out")
        
        # Close all connection pools gracefully
        close_tasks = []
        for pool in self.connection_pools.values():
            if hasattr(pool, 'close'):
                close_tasks.append(asyncio.create_task(pool.close()))
        
        if close_tasks:
            try:
                await asyncio.wait_for(asyncio.gather(*close_tasks, return_exceptions=True), timeout=10.0)
            except asyncio.TimeoutError:
                logger.warning("Connection pool cleanup timed out")
        
        logger.info("Proxy manager shutdown completed")
    
    async def _save_state(self):
        """Save current proxy state for recovery"""
        try:
            state = {
                'metrics': {k: asdict(v) for k, v in self.metrics.items()},
                'blacklist': list(self.blacklist),
                'timestamp': time.time()
            }
            
            state_file = Path('proxy_state.json')
            with open(state_file, 'w') as f:
                json.dump(state, f, indent=2)
                
            logger.debug(f"Proxy state saved to {state_file}")
        except Exception as e:
            logger.error(f"Failed to save proxy state: {e}")
    
    async def _restore_state(self):
        """Restore previous proxy state"""
        try:
            state_file = Path('proxy_state.json')
            if state_file.exists():
                with open(state_file, 'r') as f:
                    state = json.load(f)
                
                # Restore metrics
                for proxy_id, metrics_data in state.get('metrics', {}).items():
                    if proxy_id in self.proxies:
                        self.metrics[proxy_id] = ProxyMetrics(**metrics_data)
                
                # Restore blacklist
                self.blacklist.update(state.get('blacklist', []))
                
                logger.info("Proxy state restored from previous session")
        except Exception as e:
            logger.error(f"Failed to restore proxy state: {e}")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    async def __aenter__(self):
        """Async context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        if exc_type:
            logger.error(f"Exception during proxy operations: {exc_val}")
        # Note: Can't call async close() in sync context
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if exc_type:
            logger.error(f"Exception during proxy operations: {exc_val}")
        await self.close()

# Convenience functions for backward compatibility
async def create_advanced_proxy_manager(proxy_sources: List[str], config: Optional[Dict] = None) -> AdvancedProxyManager:
    """Create and initialize advanced proxy manager"""
    manager = AdvancedProxyManager(config)
    await manager.initialize(proxy_sources)
    return manager

def validate_proxy(proxy_string: str) -> Optional[ProxyConfig]:
    """Validate proxy string and return ProxyConfig"""
    manager = AdvancedProxyManager()
    return manager._parse_proxy_url(proxy_string) if '://' in proxy_string else None
