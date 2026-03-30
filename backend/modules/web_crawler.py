"""
Smart Web Crawler
Crawls website, extracts URLs and links with depth control
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Set, Tuple
import threading
from config import (
    USER_AGENT, MAX_CRAWL_DEPTH, DEFAULT_TIMEOUT,
    FOLLOW_REDIRECTS, VERIFY_SSL, MAX_REQUESTS_PER_DOMAIN
)

class WebCrawler:
    def __init__(self, timeout=DEFAULT_TIMEOUT):
        self.timeout = timeout
        self.visited_urls = set()
        self.discovered_urls = set()
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
        self.request_count = 0
        self.max_requests = MAX_REQUESTS_PER_DOMAIN
        self.static_extensions = {
            '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot', '.otf', '.mp4', '.webm',
            '.mp3', '.pdf', '.zip', '.rar', '.7z'
        }

    def is_valid_url(self, url: str, domain: str) -> bool:
        """Check if URL belongs to target domain"""
        try:
            parsed = urlparse(url)
            return domain in parsed.netloc and parsed.scheme in ['http', 'https']
        except:
            return False

    def _should_follow_url(self, url: str) -> bool:
        """Avoid low-value static asset crawling while preserving JS discovery."""
        path = urlparse(url).path.lower()
        for ext in self.static_extensions:
            if path.endswith(ext):
                return False
        return True

    def extract_links(self, html: str, base_url: str, domain: str) -> Set[str]:
        """Extract all links from HTML including form actions"""
        links = set()
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Extract from <a> tags
            for link in soup.find_all('a', href=True):
                url = urljoin(base_url, link['href'])
                if self.is_valid_url(url, domain) and self._should_follow_url(url):
                    links.add(url.split('#')[0])  # Remove fragments
            
            # Extract from script src
            for script in soup.find_all('script', src=True):
                url = urljoin(base_url, script['src'])
                if self.is_valid_url(url, domain):
                    links.add(url)
            
            # Extract from link href
            for link in soup.find_all('link', href=True):
                url = urljoin(base_url, link['href'])
                if self.is_valid_url(url, domain) and self._should_follow_url(url):
                    links.add(url)
            
            # FIX #1: Extract from form actions (with parameters)
            for form in soup.find_all('form', action=True):
                action_url = urljoin(base_url, form['action'])
                if self.is_valid_url(action_url, domain):
                    # Build URL with form input names as params
                    params = []
                    for input_tag in form.find_all(['input', 'select', 'textarea'], attrs={'name': True}):
                        name = input_tag.get('name', '')
                        if name:
                            params.append(f"{name}=test")
                    if params:
                        action_url = f"{action_url.split('?')[0]}?{'&'.join(params)}"
                    if self._should_follow_url(action_url):
                        links.add(action_url)
            
            # Extract from img src (might reveal paths)
            for img in soup.find_all('img', src=True):
                url = urljoin(base_url, img['src'])
                if self.is_valid_url(url, domain) and '/api/' in url:
                    links.add(url)
        
        except Exception as e:
            pass
        
        return links

    def crawl_url(self, url: str, domain: str, depth: int = 0) -> None:
        """Crawl a single URL"""
        if depth > MAX_CRAWL_DEPTH or self.request_count > self.max_requests:
            return
        
        with self.lock:
            if url in self.visited_urls:
                return
            self.visited_urls.add(url)
            self.request_count += 1
        
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=VERIFY_SSL,
                allow_redirects=FOLLOW_REDIRECTS
            )
            
            with self.lock:
                self.discovered_urls.add(url)
            
            print(f"[+] Crawled: {url}")
            
            # Extract links from HTML
            if 'text/html' in response.headers.get('Content-Type', ''):
                links = self.extract_links(response.text, url, domain)
                
                # Recursively crawl discovered links
                for link in links:
                    if self.request_count < self.max_requests:
                        self.crawl_url(link, domain, depth + 1)
        
        except requests.exceptions.RequestException as e:
            pass

    def crawl(self, start_url: str, domain: str) -> Set[str]:
        """Start crawling from initial URL"""
        print(f"[*] Starting web crawler for {domain}...")
        self.crawl_url(start_url, domain, depth=0)
        print(f"[*] Crawling complete. Discovered {len(self.discovered_urls)} URLs")
        return self.discovered_urls

    def get_results(self) -> Set[str]:
        """Return discovered URLs"""
        return self.discovered_urls
