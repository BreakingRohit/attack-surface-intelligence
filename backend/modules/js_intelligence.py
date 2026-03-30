"""
JavaScript Intelligence Engine
Extracts and analyzes JavaScript files for hidden endpoints and APIs
"""

import re
import requests
from typing import Set, Dict, List
from urllib.parse import urljoin
import threading
from config import USER_AGENT, DEFAULT_TIMEOUT

class JSIntelligence:
    def __init__(self, timeout=DEFAULT_TIMEOUT):
        self.timeout = timeout
        self.js_cache = {}
        self.extracted_endpoints = set()
        self.extracted_parameters = set()
        self.api_endpoints = set()
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})

    def download_js(self, url: str) -> str:
        """Download JavaScript file"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                return response.text
        except:
            pass
        return ""

    def extract_api_calls(self, js_content: str) -> Set[str]:
        """Extract API endpoints from JavaScript"""
        endpoints = set()

        def is_valid_endpoint(candidate: str) -> bool:
            return isinstance(candidate, str) and candidate.startswith('/') and len(candidate) > 3
        
        # Pattern for fetch/axios calls
        patterns = [
            r"(?:fetch|axios|http\.(?:get|post|put|delete|patch))\(['\"]([^'\"]+)['\"]",
            r"(?:fetch|axios|http\.(?:get|post|put|delete|patch))\(`([^`]+)`",
            r"('(/api/[^'\"]+)')",
            r'(\"(/api/[^"]+)\")',
            r"('(/v\d+/[^'\"]+)')",
            r'(\"(/v\d+/[^"]+)\")',
            r"(?:url|URL|endpoint|ENDPOINT)\s*[:=]\s*['\"]([^'\"]+)['\"]",
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                value = match[1] if isinstance(match, tuple) else match
                if value and is_valid_endpoint(value):
                    endpoints.add(value)
        
        return endpoints

    def extract_parameters(self, js_content: str) -> Set[str]:
        """
        FIX #5: Enhanced parameter extraction from JavaScript
        Extracts parameters from:
        - URL query patterns: ?param= or &param=
        - JSON key patterns: "param": or 'param':
        - Object property access: params.xxx, query.xxx
        - URLSearchParams usage
        - FormData append
        """
        parameters = set()
        
        # Pattern for parameter usage
        patterns = [
            # Object property access
            r"params\.([a-zA-Z_][a-zA-Z0-9_]*)",
            r"query\.([a-zA-Z_][a-zA-Z0-9_]*)",
            r"data\.([a-zA-Z_][a-zA-Z0-9_]*)",
            r"body\.([a-zA-Z_][a-zA-Z0-9_]*)",
            r"request\.([a-zA-Z_][a-zA-Z0-9_]*)",
            r"req\.([a-zA-Z_][a-zA-Z0-9_]*)",
            
            # FIX #5: URL query parameter patterns
            r"[?&]([a-zA-Z_][a-zA-Z0-9_]*)=",
            
            # FIX #5: JSON key patterns
            r"['\"]([a-zA-Z_][a-zA-Z0-9_]*)['\"]:\s*",
            
            # Bracket notation
            r"\[['\"](.*?)['\"]\](?=\s*[=:])",
            
            # Named parameter declarations
            r"(?:param|parameter|key|field):\s*['\"]([^'\"]+)['\"]",
            
            # FIX #5: URLSearchParams.get()
            r"\.get\(['\"]([a-zA-Z_][a-zA-Z0-9_]*)['\"]\)",
            
            # FIX #5: FormData.append()
            r"\.append\(['\"]([a-zA-Z_][a-zA-Z0-9_]*)['\"]\s*,",
            
            # FIX #5: axios/fetch request params
            r"params:\s*\{[^}]*['\"]([a-zA-Z_][a-zA-Z0-9_]*)['\"]",
            
            # FIX #5: GraphQL variables
            r"\$([a-zA-Z_][a-zA-Z0-9_]*)",
        ]
        
        for pattern in patterns:
            try:
                matches = re.findall(pattern, js_content)
                for match in matches:
                    if match and len(match) > 1 and len(match) < 30:
                        # Filter out common JS keywords
                        if match.lower() not in ['function', 'return', 'const', 'let', 'var', 'if', 'else', 'for', 'while', 'true', 'false', 'null', 'undefined', 'this', 'new', 'class', 'export', 'import', 'default', 'async', 'await']:
                            parameters.add(match)
            except Exception:
                continue
        
        return parameters

    def extract_hidden_paths(self, js_content: str) -> Set[str]:
        """Extract hidden paths and routes from JS"""
        paths = set()
        
        patterns = [
            r"(?:href|src|action)=['\"]([/][^'\"]+)['\"]",
            r"href:\s*['\"]([/][^'\"]+)['\"]",
            r"route\(['\"]([/][^'\"]+)['\"]",
            r"path:\s*['\"]([/][^'\"]+)['\"]"
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if match:
                    paths.add(match)
        
        return paths

    def analyze_js_file(self, js_url: str, domain: str) -> Dict:
        """Analyze a single JS file"""
        # Check cache first
        if js_url in self.js_cache:
            return self.js_cache[js_url]
        
        print(f"[*] Analyzing: {js_url}")
        
        js_content = self.download_js(js_url)
        if not js_content:
            return {}
        
        analysis = {
            'url': js_url,
            'endpoints': self.extract_api_calls(js_content),
            'parameters': self.extract_parameters(js_content),
            'paths': self.extract_hidden_paths(js_content)
        }
        
        with self.lock:
            self.js_cache[js_url] = analysis
            self.extracted_endpoints.update(analysis['endpoints'])
            self.extracted_parameters.update(analysis['parameters'])
        
        return analysis

    def analyze_js_from_urls(self, urls: Set[str], domain: str) -> Dict:
        """Extract and analyze all JS files from discovered URLs"""
        print("[*] Extracting JavaScript files...")
        
        js_files = set()
        
        # Extract .js file references from URLs
        for url in urls:
            if url.endswith('.js'):
                js_files.add(url)
        
        print(f"[*] Found {len(js_files)} JavaScript files")
        
        results = {}
        for js_file in js_files:
            result = self.analyze_js_file(js_file, domain)
            if result:
                results[js_file] = result
        
        print(f"[*] JS analysis complete. Found {len(self.extracted_endpoints)} endpoints")
        return results

    def get_endpoints(self) -> Set[str]:
        """Return extracted endpoints"""
        return self.extracted_endpoints

    def get_parameters(self) -> Set[str]:
        """Return extracted parameters"""
        return self.extracted_parameters
