"""
Alive Endpoint Filter
Filters discovered endpoints to only include those that are alive (status 200-399)
Critical component for eliminating dead endpoints from output, testing, and reports
"""

import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, Dict, List, Tuple
from urllib.parse import urlparse, urljoin
from config import (
    DEFAULT_THREADS, DEFAULT_TIMEOUT, MAX_RETRIES, RETRY_DELAY,
    USER_AGENT, ALIVE_STATUS_CODES, VERIFY_SSL
)
import time


class AliveFilter:
    """Filter endpoints to return only alive (responding) URLs"""
    
    def __init__(self, timeout=DEFAULT_TIMEOUT, threads=DEFAULT_THREADS, verbose=False):
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.alive_urls = set()
        self.dead_urls = set()
        self.alive_endpoints = {}  # endpoint -> {status_code, content_length}
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
        self.cache = {}  # URL -> (is_alive, status_code)
    
    def check_url_alive(self, url: str) -> Tuple[bool, int, int]:
        """
        Check if a URL is alive (returns status 200-399)
        Returns: (is_alive, status_code, content_length)
        """
        # Check cache first
        if url in self.cache:
            return self.cache[url]
        
        retries = 0
        while retries < MAX_RETRIES:
            try:
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=VERIFY_SSL,
                    allow_redirects=True
                )
                
                is_alive = response.status_code in ALIVE_STATUS_CODES
                content_length = int(response.headers.get('Content-Length', 0))
                
                # Cache result
                result = (is_alive, response.status_code, content_length)
                with self.lock:
                    self.cache[url] = result
                
                return result
                
            except requests.exceptions.RequestException:
                retries += 1
                if retries < MAX_RETRIES:
                    time.sleep(RETRY_DELAY)
        
        # Failed after retries - mark as dead
        result = (False, 0, 0)
        with self.lock:
            self.cache[url] = result
        return result
    
    def check_endpoint_alive(self, base_url: str, endpoint: str) -> Tuple[str, bool, int]:
        """
        Check if an endpoint is alive
        Returns: (endpoint, is_alive, status_code)
        """
        # Build full URL
        if endpoint.startswith('http'):
            full_url = endpoint
        else:
            full_url = urljoin(base_url, endpoint)
        
        is_alive, status_code, _ = self.check_url_alive(full_url)
        
        if self.verbose and is_alive:
            print(f"    [ALIVE] {endpoint} ({status_code})")
        elif self.verbose:
            print(f"    [DEAD]  {endpoint}")
        
        return (endpoint, is_alive, status_code)
    
    def filter_urls(self, urls: Set[str]) -> Set[str]:
        """
        Filter a set of URLs to return only alive ones
        Uses multi-threading for performance
        """
        print(f"[*] Filtering {len(urls)} URLs for alive endpoints...")
        
        alive_urls = set()
        dead_count = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.check_url_alive, url): url
                for url in urls
            }
            
            for future in as_completed(futures):
                url = futures[future]
                try:
                    is_alive, status_code, _ = future.result()
                    
                    if is_alive:
                        alive_urls.add(url)
                        with self.lock:
                            self.alive_urls.add(url)
                    else:
                        dead_count += 1
                        with self.lock:
                            self.dead_urls.add(url)
                            
                except Exception:
                    dead_count += 1
        
        print(f"[*] Alive filtering complete: {len(alive_urls)} alive, {dead_count} dead")
        return alive_urls
    
    def filter_endpoints(self, base_url: str, endpoints: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        """
        Filter endpoints dictionary to return only alive endpoints
        Returns: filtered endpoints dict with only alive endpoints
        """
        print(f"[*] Filtering {len(endpoints)} endpoints for alive status...")
        
        filtered_endpoints = {}
        alive_count = 0
        dead_count = 0
        
        # Flatten endpoints for parallel checking
        all_endpoints = list(endpoints.keys())
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.check_endpoint_alive, base_url, ep): ep
                for ep in all_endpoints
            }
            
            for future in as_completed(futures):
                endpoint = futures[future]
                try:
                    ep, is_alive, status_code = future.result()
                    
                    if is_alive:
                        # Keep this endpoint with its parameters
                        filtered_endpoints[ep] = endpoints[ep]
                        with self.lock:
                            self.alive_endpoints[ep] = {
                                'status_code': status_code,
                                'params': list(endpoints[ep])
                            }
                        alive_count += 1
                    else:
                        dead_count += 1
                        
                except Exception:
                    dead_count += 1
        
        print(f"[*] Endpoint filtering complete: {alive_count} alive, {dead_count} dead")
        return filtered_endpoints
    
    def filter_subdomains(self, subdomains: Set[str]) -> Set[str]:
        """
        Filter subdomains to return only those with alive web servers
        """
        print(f"[*] Checking {len(subdomains)} subdomains for alive web servers...")
        
        alive_subdomains = set()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            
            for subdomain in subdomains:
                # Try HTTPS first, then HTTP
                https_url = f"https://{subdomain}"
                futures[executor.submit(self.check_url_alive, https_url)] = (subdomain, 'https')
            
            for future in as_completed(futures):
                subdomain, protocol = futures[future]
                try:
                    is_alive, status_code, _ = future.result()
                    
                    if is_alive:
                        alive_subdomains.add(subdomain)
                        if self.verbose:
                            print(f"    [ALIVE] {subdomain} ({protocol}, {status_code})")
                    else:
                        # Try HTTP if HTTPS failed
                        http_url = f"http://{subdomain}"
                        http_alive, http_status, _ = self.check_url_alive(http_url)
                        if http_alive:
                            alive_subdomains.add(subdomain)
                            if self.verbose:
                                print(f"    [ALIVE] {subdomain} (http, {http_status})")
                        elif self.verbose:
                            print(f"    [DEAD]  {subdomain}")
                            
                except Exception:
                    pass
        
        print(f"[*] Subdomain filtering complete: {len(alive_subdomains)} alive")
        return alive_subdomains
    
    def get_alive_urls(self) -> Set[str]:
        """Return all discovered alive URLs"""
        return self.alive_urls
    
    def get_dead_urls(self) -> Set[str]:
        """Return all discovered dead URLs"""
        return self.dead_urls
    
    def get_alive_endpoints(self) -> Dict[str, Dict]:
        """Return alive endpoints with metadata"""
        return self.alive_endpoints
    
    def get_statistics(self) -> Dict:
        """Return filtering statistics"""
        total = len(self.alive_urls) + len(self.dead_urls)
        alive_pct = (len(self.alive_urls) / total * 100) if total > 0 else 0
        
        return {
            'total_checked': total,
            'alive_count': len(self.alive_urls),
            'dead_count': len(self.dead_urls),
            'alive_percentage': round(alive_pct, 1),
            'endpoints_alive': len(self.alive_endpoints)
        }
