"""
Directory Discovery Engine
Smart wordlist-based directory/path discovery
"""

import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, List
from config import (
    DEFAULT_THREADS, DEFAULT_TIMEOUT, COMMON_DIRECTORIES,
    DEFAULT_DIR_WORDLIST, USER_AGENT
)

class DirectoryDiscovery:
    def __init__(self, timeout=DEFAULT_TIMEOUT, threads=DEFAULT_THREADS):
        self.timeout = timeout
        self.threads = threads
        self.discovered_directories = set()
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
        self.status_codes = set()

    def load_wordlist(self, wordlist_path) -> List[str]:
        """Load directory wordlist"""
        try:
            with open(wordlist_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] Directory wordlist not found, using defaults")
            return COMMON_DIRECTORIES

    def check_directory(self, base_url: str, directory: str) -> bool:
        """Check if directory exists via HTTP request"""
        url = f"{base_url.rstrip('/')}/{directory.lstrip('/')}"
        
        try:
            response = self.session.head(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            
            # Status codes indicating found directory
            if response.status_code in [200, 301, 302, 304]:
                return True
        except:
            pass
        
        return False

    def discover(self, base_url: str, wordlist_path=None) -> Set[str]:
        """Discover directories/paths"""
        print(f"[*] Starting directory discovery for {base_url}...")
        
        # Load wordlist
        if wordlist_path:
            directories = self.load_wordlist(wordlist_path)
        else:
            directories = COMMON_DIRECTORIES.copy()
        
        # Multi-threaded directory checking
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.check_directory, base_url, d): d
                for d in directories
            }
            
            for future in as_completed(futures):
                directory = futures[future]
                try:
                    if future.result():
                        full_path = f"{base_url.rstrip('/')}/{directory}"
                        with self.lock:
                            self.discovered_directories.add(full_path)
                        print(f"[+] Found directory: {full_path}")
                except Exception as e:
                    pass
        
        print(f"[*] Directory discovery complete. Found {len(self.discovered_directories)} directories")
        return self.discovered_directories

    def get_results(self) -> Set[str]:
        """Return discovered directories"""
        return self.discovered_directories
