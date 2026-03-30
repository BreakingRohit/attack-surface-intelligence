"""
Endpoint & Parameter Extraction Engine
Extracts endpoints and parameters from URLs, HTML forms, and JavaScript
Includes parameter guessing for modern web apps (React/Next.js)
"""

import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode
from typing import Set, Dict, List, Tuple
from bs4 import BeautifulSoup
from config import USER_AGENT, DEFAULT_TIMEOUT

# Common parameters to guess for modern web apps (React/Next.js/SPA)
GUESSED_PARAMS = [
    "id", "user_id", "q", "search", "page", "limit", "offset",
    "sort", "order", "filter", "category", "type", "token",
    "callback", "redirect", "url", "file", "path", "action"
]


class EndpointExtraction:
    def __init__(self, timeout=DEFAULT_TIMEOUT):
        self.endpoints = set()
        self.parameters = {}  # endpoint -> set of parameters
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
        
        # FIX #3: Static file extensions to filter
        self.static_extensions = {
            '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.webp',
            '.svg', '.woff', '.woff2', '.ttf', '.eot', '.otf',
            '.ico', '.map', '.mp3', '.mp4', '.webm', '.avi', '.mov',
            '.zip', '.tar', '.gz', '.rar', '.7z', '.exe', '.dll',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.txt', '.csv'
        }
        self.max_params_per_endpoint = 5

    def extract_path(self, url: str) -> str:
        """Extract path from URL"""
        try:
            parsed = urlparse(url)
            path = parsed.path
            return path if path else "/"
        except:
            return "/"

    def extract_query_params(self, url: str) -> Set[str]:
        """Extract query parameters from URL"""
        params = set()
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            params.update(query_params.keys())
        except:
            pass
        return params

    def extract_params_from_html(self, html_content: str) -> Set[str]:
        """
        FIX #1: Extract parameters from HTML forms
        - input fields (name attribute)
        - textarea fields
        - select fields
        - hidden fields
        """
        params = set()
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract from <input> tags
            for input_tag in soup.find_all('input', attrs={'name': True}):
                name = input_tag.get('name', '').strip()
                if name and len(name) > 1:
                    params.add(name)
            
            # Extract from <textarea> tags
            for textarea in soup.find_all('textarea', attrs={'name': True}):
                name = textarea.get('name', '').strip()
                if name and len(name) > 1:
                    params.add(name)
            
            # Extract from <select> tags
            for select in soup.find_all('select', attrs={'name': True}):
                name = select.get('name', '').strip()
                if name and len(name) > 1:
                    params.add(name)
            
            # Extract from data-* attributes that might contain param names
            for tag in soup.find_all(attrs={'data-param': True}):
                name = tag.get('data-param', '').strip()
                if name and len(name) > 1:
                    params.add(name)
            
            # Extract form action URLs and their potential params
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action and '?' in action:
                    url_params = self.extract_query_params(action)
                    params.update(url_params)
                    
        except Exception:
            pass
        
        return params

    def extract_params_from_js(self, js_content: str) -> Set[str]:
        """
        FIX #5: Extract parameters from JavaScript content
        - URL query patterns: ?param= or &param=
        - JSON key patterns: "param": or 'param':
        - Object access patterns: params.name, query.name, data.name
        """
        params = set()
        
        # Pattern 1: URL query parameters (?param= or &param=)
        url_param_pattern = r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)='
        matches = re.findall(url_param_pattern, js_content)
        for match in matches:
            if len(match) > 1 and len(match) < 30:
                params.add(match)
        
        # Pattern 2: JSON key patterns - "param": or 'param':
        json_key_pattern = r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']:\s*'
        matches = re.findall(json_key_pattern, js_content)
        for match in matches:
            if len(match) > 1 and len(match) < 30:
                params.add(match)
        
        # Pattern 3: Object property access - params.xxx, query.xxx, data.xxx, body.xxx
        object_access_pattern = r'(?:params|query|data|body|request|req)\.([a-zA-Z_][a-zA-Z0-9_]*)'
        matches = re.findall(object_access_pattern, js_content)
        for match in matches:
            if len(match) > 1 and len(match) < 30:
                params.add(match)
        
        # Pattern 4: URLSearchParams usage
        search_params_pattern = r'\.get\(["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\)'
        matches = re.findall(search_params_pattern, js_content)
        for match in matches:
            if len(match) > 1 and len(match) < 30:
                params.add(match)
        
        # Pattern 5: FormData append
        formdata_pattern = r'\.append\(["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\s*,'
        matches = re.findall(formdata_pattern, js_content)
        for match in matches:
            if len(match) > 1 and len(match) < 30:
                params.add(match)
        
        return params

    def _is_static_file(self, endpoint: str) -> bool:
        """FIX #3: Check if endpoint is a static file"""
        endpoint_lower = endpoint.lower()
        
        # Check if extension matches static file patterns
        for ext in self.static_extensions:
            if endpoint_lower.endswith(ext):
                return True
        
        # Check for CDN/asset paths
        if any(x in endpoint_lower for x in ['/cdn/', '/assets/', '/dist/', '/static/', '/public/', '/vendor/']):
            return True
        
        return False

    def _is_high_value_endpoint(self, endpoint: str) -> bool:
        """
        Keep API and dynamic/form endpoints, drop low-value static-like routes.
        """
        endpoint_lower = endpoint.lower()
        if endpoint_lower in {'/', ''}:
            return True
        if any(k in endpoint_lower for k in ['/api/', '/v1/', '/v2/', '/v3/', 'graphql', 'auth', 'login', 'admin']):
            return True
        return not self._is_static_file(endpoint)

    def _is_tracking_endpoint(self, endpoint: str) -> bool:
        """Drop analytics/tracking style endpoints to reduce noise."""
        endpoint_lower = endpoint.lower()
        tracking_markers = [
            'analytics', 'tracking', 'collect', 'pixel', 'telemetry',
            'metrics', 'segment', 'amplitude', 'mixpanel', 'gtm', 'ga'
        ]
        return any(marker in endpoint_lower for marker in tracking_markers)
    
    def normalize_endpoint(self, endpoint: str) -> str:
        """Normalize endpoint path"""
        # Remove query strings
        endpoint = endpoint.split('?')[0]
        # Remove fragments
        endpoint = endpoint.split('#')[0]
        # Remove trailing slashes (except root)
        if endpoint != '/' and endpoint.endswith('/'):
            endpoint = endpoint[:-1]
        return endpoint

    def normalize_parameter(self, param: str) -> str:
        """Normalize parameter name - strip whitespace and convert to lowercase for comparison"""
        return param.strip().lower()

    def _clean_parameter_set(self, params: Set[str]) -> Set[str]:
        """Apply parameter quality controls and cap per endpoint."""
        normalized = {}
        for param in params:
            cleaned = param.strip()
            if not cleaned or len(cleaned) < 2:
                continue
            if cleaned.startswith("__"):
                continue
            normalized_name = self.normalize_parameter(cleaned)
            if normalized_name not in normalized:
                normalized[normalized_name] = cleaned

        # Keep strongest candidates first
        prioritized = sorted(
            normalized.values(),
            key=lambda p: (0 if any(k in p.lower() for k in ['id', 'user', 'search', 'file', 'url', 'token']) else 1, len(p))
        )
        return set(prioritized[:self.max_params_per_endpoint])

    def extract_from_urls(self, urls: Set[str]) -> Dict[str, Set[str]]:
        """Extract endpoints and parameters from discovered URLs"""
        print("[*] Extracting endpoints and parameters from URLs...")
        
        endpoint_params = {}
        static_filtered = 0
        
        for url in urls:
            # Extract path
            path = self.extract_path(url)
            normalized_path = self.normalize_endpoint(path)
            
            # FIX #3: Skip static files
            if self._is_static_file(normalized_path):
                static_filtered += 1
                continue
            if not self._is_high_value_endpoint(normalized_path):
                static_filtered += 1
                continue
            if self._is_tracking_endpoint(normalized_path):
                static_filtered += 1
                continue
            
            # Extract query parameters
            params = self.extract_query_params(url)
            
            if normalized_path not in endpoint_params:
                endpoint_params[normalized_path] = set()
            
            endpoint_params[normalized_path].update(self._clean_parameter_set(params))
            self.endpoints.add(normalized_path)
        
        self.parameters = endpoint_params
        
        print(f"[*] Extracted {len(self.endpoints)} unique endpoints from URLs (filtered: {static_filtered} static files)")
        print(f"[*] Extracted {sum(len(p) for p in self.parameters.values())} parameters from URL queries")
        
        return endpoint_params

    def extract_from_page_content(self, url: str, html_content: str = None, js_content: str = None) -> Set[str]:
        """
        FIX #1 & #5: Extract parameters from page HTML and JavaScript
        """
        all_params = set()
        
        # Extract from HTML forms
        if html_content:
            html_params = self.extract_params_from_html(html_content)
            all_params.update(html_params)
        
        # Extract from inline/linked JavaScript
        if js_content:
            js_params = self.extract_params_from_js(js_content)
            all_params.update(js_params)
        
        return all_params

    def fetch_and_extract_params(self, url: str) -> Set[str]:
        """Fetch a URL and extract parameters from its HTML and JS"""
        params = set()
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                
                if 'text/html' in content_type:
                    # Extract from HTML
                    params.update(self.extract_params_from_html(response.text))
                    
                    # Also extract inline JS
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for script in soup.find_all('script'):
                        if script.string:
                            params.update(self.extract_params_from_js(script.string))
                
                elif 'javascript' in content_type or url.endswith('.js'):
                    # Extract from JS file
                    params.update(self.extract_params_from_js(response.text))
        except Exception:
            pass
        
        return params

    def guess_parameters_for_endpoint(self, endpoint: str) -> Set[str]:
        """
        FIX #2: Parameter guessing engine for modern web apps
        If no parameters found, suggest common ones based on endpoint type
        """
        guessed = set()
        endpoint_lower = endpoint.lower()
        
        # Always add common params
        guessed.update(['id', 'q', 'page'])
        
        # Context-aware guessing based on endpoint
        if any(x in endpoint_lower for x in ['user', 'profile', 'account']):
            guessed.update(['user_id', 'id', 'username', 'email'])
        
        if any(x in endpoint_lower for x in ['search', 'find', 'query']):
            guessed.update(['q', 'query', 'search', 'keyword', 'term'])
        
        if any(x in endpoint_lower for x in ['product', 'item', 'order']):
            guessed.update(['product_id', 'item_id', 'order_id', 'id', 'sku'])
        
        if any(x in endpoint_lower for x in ['api', 'v1', 'v2', 'graphql']):
            guessed.update(['token', 'api_key', 'callback', 'format'])
        
        if any(x in endpoint_lower for x in ['login', 'auth', 'signin']):
            guessed.update(['username', 'email', 'password', 'redirect', 'next'])
        
        if any(x in endpoint_lower for x in ['file', 'download', 'upload', 'doc']):
            guessed.update(['file', 'filename', 'path', 'type'])
        
        if any(x in endpoint_lower for x in ['list', 'results', 'data']):
            guessed.update(['page', 'limit', 'offset', 'sort', 'order', 'filter'])
        
        if any(x in endpoint_lower for x in ['redirect', 'return', 'callback']):
            guessed.update(['url', 'redirect', 'redirect_url', 'return_url', 'next'])
        
        return guessed

    def combine_with_js(self, js_endpoints: Set[str], js_params: Set[str] = None) -> Dict[str, Set[str]]:
        """Combine crawler endpoints with JS-extracted endpoints and parameters"""
        print("[*] Combining crawler and JS endpoints...")
        
        combined_endpoints = {}
        static_filtered = 0
        
        # Add crawler endpoints
        for endpoint, params in self.parameters.items():
            combined_endpoints[endpoint] = params.copy()
        
        # Add JS endpoints
        for endpoint in js_endpoints:
            normalized = self.normalize_endpoint(endpoint)
            # FIX #3: Skip static files from JS too
            if self._is_static_file(normalized):
                static_filtered += 1
                continue
            if not self._is_high_value_endpoint(normalized):
                static_filtered += 1
                continue
            if self._is_tracking_endpoint(normalized):
                static_filtered += 1
                continue
            if normalized not in combined_endpoints:
                combined_endpoints[normalized] = set()
        
        # FIX #5: Add JS-extracted parameters to relevant endpoints
        if js_params:
            # Distribute JS params to API endpoints that might use them
            for endpoint in combined_endpoints:
                if any(x in endpoint.lower() for x in ['api', 'v1', 'v2', 'graphql', 'service']):
                    combined_endpoints[endpoint].update(self._clean_parameter_set(js_params))
        
        self.endpoints.update(combined_endpoints.keys())
        self.parameters = combined_endpoints
        
        print(f"[*] Total endpoints after combining: {len(self.endpoints)}")
        
        return combined_endpoints

    def enrich_with_guessed_params(self) -> Dict[str, Set[str]]:
        """
        FIX #2: Add guessed parameters to endpoints that have none or few
        """
        print("[*] Enriching endpoints with guessed parameters...")
        
        enriched_count = 0
        for endpoint in self.parameters:
            existing_params = self.parameters[endpoint]
            
            # If endpoint has few or no params, add guessed ones
            if len(existing_params) < 2:
                guessed = self.guess_parameters_for_endpoint(endpoint)
                self.parameters[endpoint].update(self._clean_parameter_set(guessed))
                enriched_count += 1
            else:
                self.parameters[endpoint] = self._clean_parameter_set(existing_params)
        
        print(f"[*] Enriched {enriched_count} endpoints with guessed parameters")
        return self.parameters

    def deduplicate(self) -> Dict[str, Set[str]]:
        """Remove duplicate endpoints and normalize parameters"""
        print("[*] Deduplicating and normalizing endpoints...")
        
        deduplicated = {}
        
        for endpoint, params in self.parameters.items():
            normalized_endpoint = self.normalize_endpoint(endpoint)
            
            if normalized_endpoint not in deduplicated:
                deduplicated[normalized_endpoint] = set()
            
            # Deduplicate parameters (case-insensitive merge)
            seen_params = {}
            for param in params:
                normalized = self.normalize_parameter(param)
                if normalized not in seen_params:
                    seen_params[normalized] = param  # Keep original case

            cleaned = self._clean_parameter_set(set(seen_params.values()))
            deduplicated[normalized_endpoint].update(cleaned)
        
        self.endpoints = set(deduplicated.keys())
        self.parameters = deduplicated
        
        total_params = sum(len(p) for p in self.parameters.values())
        print(f"[*] Final: {len(self.endpoints)} endpoints with {total_params} total parameters")
        
        return deduplicated

    def get_endpoints(self) -> Set[str]:
        """Return all endpoints"""
        return self.endpoints

    def get_parameters(self) -> Dict[str, Set[str]]:
        """Return endpoint -> parameters mapping"""
        return self.parameters

    def get_endpoints_with_params(self) -> List[Dict]:
        """Return structured endpoint data"""
        results = []
        for endpoint, params in self.parameters.items():
            results.append({
                'endpoint': endpoint,
                'parameters': list(params),
                'param_count': len(params)
            })
        return sorted(results, key=lambda x: x['param_count'], reverse=True)
