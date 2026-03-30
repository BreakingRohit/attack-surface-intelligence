"""
Subdomain Discovery Engine
Performs DNS brute force with multi-threaded resolution
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, List
import dns.resolver
import dns.exception
from config import (
    DEFAULT_THREADS, DEFAULT_TIMEOUT, COMMON_SUBDOMAINS,
    DEFAULT_SUB_WORDLIST
)

class SubdomainDiscovery:
    def __init__(self, timeout=DEFAULT_TIMEOUT, threads=DEFAULT_THREADS):
        self.timeout = timeout
        self.threads = threads
        self.discovered_subdomains = set()
        self.lock = threading.Lock()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def load_wordlist(self, wordlist_path) -> List[str]:
        """Load subdomain wordlist from file"""
        try:
            with open(wordlist_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] Wordlist not found: {wordlist_path}, using default list")
            return COMMON_SUBDOMAINS

    def resolve_subdomain(self, subdomain: str, domain: str) -> bool:
        """Attempt DNS resolution of a subdomain"""
        try:
            full_domain = f"{subdomain}.{domain}"
            self.resolver.resolve(full_domain, 'A')
            return True
        except (dns.exception.DNSException, Exception):
            return False

    def discover(self, domain: str, wordlist_path=None) -> Set[str]:
        """
        Discover subdomains for target domain
        Uses wordlist + common subdomains
        """
        print(f"[*] Starting subdomain discovery for {domain}...")
        
        # Load wordlist
        if wordlist_path:
            subdomains = self.load_wordlist(wordlist_path)
        else:
            subdomains = COMMON_SUBDOMAINS.copy()
        
        # Multi-threaded brute force
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.resolve_subdomain, sub, domain): sub
                for sub in subdomains
            }
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                subdomain = futures[future]
                try:
                    if future.result():
                        full_domain = f"{subdomain}.{domain}"
                        with self.lock:
                            self.discovered_subdomains.add(full_domain)
                        print(f"[+] Found: {full_domain}")
                except Exception as e:
                    pass
        
        print(f"[*] Subdomain discovery complete. Found {len(self.discovered_subdomains)} subdomains")
        return self.discovered_subdomains

    def get_results(self) -> Set[str]:
        """Return discovered subdomains"""
        return self.discovered_subdomains
