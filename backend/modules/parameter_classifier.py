"""
Smart Parameter Classification Engine
Classifies parameters by risk level and maps to vulnerability types
Enhanced with comprehensive parameter -> vulnerability mappings
"""

from typing import Dict, List, Set
from config import HIGH_RISK_PARAMS, MEDIUM_RISK_PARAMS, PARAM_VULN_MAPPING


class ParameterClassifier:
    """Classifies parameters based on vulnerability susceptibility"""
    
    def __init__(self):
        self.classifications = {}
        self.param_vuln_map = PARAM_VULN_MAPPING
        
        # FIX #2: Parameters to filter (framework-generated, framework internals)
        self.filtered_params = {
            # ASP.NET framework parameters
            '__VIEWSTATE',
            '__EVENTTARGET',
            '__EVENTARGUMENT',
            '__EVENTVALIDATION',
            '__REQUESTDIGEST',
            '__WEBFORMPOSTBACKCONTROL',
            '__SCROLLPOSITIONX',
            '__SCROLLPOSITIONY',
            'VIEWSTATEGENERATOR',
            'ASP.NET_SESSIONID',
            '__RequestVerificationToken',
            '__prev_path',
            '__CULTURE',
            '__UICULTURE',
            
            # Common empty/noise parameters
            '',
            'null',
            'undefined',
            'none',
            'empty',
            
            # UI framework parameters
            '_ts',  # timestamp
            '_nonce',  # nonce tokens
            '__g',  # Google Analytics
            '_ga',  # Google Analytics
            '__utma',  # Google Analytics
            '__utmz',  # Google Analytics
            '_gid',  # Google Analytics
            'fbclid',  # Facebook click ID
            'gclid',  # Google Click ID
            'msclkid',  # Microsoft Click ID
            
            # Common utility parameters
            'ref',
            'referrer',
            'utm_source',
            'utm_medium',
            'utm_campaign',
            'utm_content',
            'utm_term',
            'sort',
            'order',
            'asc',
            'desc',
            'page',  # Pagination often safe
            'limit',
            'offset',
            'per_page',
        }
        self.filtered_params_lower = {p.lower() for p in self.filtered_params}
        
        # Extended vulnerability type mappings based on parameter patterns
        self.pattern_mappings = {
            # ID-based parameters -> SQLi, IDOR
            'id': ['SQLi', 'IDOR'],
            'uid': ['SQLi', 'IDOR'],
            'pid': ['SQLi', 'IDOR'],
            'oid': ['SQLi', 'IDOR'],
            '_id': ['SQLi', 'IDOR'],
            'num': ['SQLi', 'IDOR'],
            'no': ['SQLi', 'IDOR'],
            'number': ['SQLi', 'IDOR'],
            
            # Search/Query parameters -> XSS
            'search': ['XSS'],
            'query': ['XSS'],
            'keyword': ['XSS'],
            'term': ['XSS'],
            'text': ['XSS'],
            'content': ['XSS'],
            'message': ['XSS'],
            'comment': ['XSS'],
            'title': ['XSS'],
            'name': ['XSS'],
            'value': ['XSS'],
            'input': ['XSS'],
            'data': ['XSS'],
            
            # File-based parameters -> LFI
            'file': ['LFI'],
            'path': ['LFI'],
            'template': ['LFI'],
            'include': ['LFI'],
            'page': ['LFI', 'SQLi'],
            'document': ['LFI'],
            'folder': ['LFI'],
            'dir': ['LFI'],
            'root': ['LFI'],
            'load': ['LFI'],
            'read': ['LFI'],
            'view': ['LFI'],
            
            # URL-based parameters -> SSRF, Open Redirect
            'url': ['SSRF', 'Open Redirect'],
            'uri': ['SSRF', 'Open Redirect'],
            'link': ['SSRF', 'Open Redirect'],
            'redirect': ['Open Redirect'],
            'return': ['Open Redirect'],
            'next': ['Open Redirect'],
            'goto': ['Open Redirect'],
            'dest': ['SSRF', 'Open Redirect'],
            'destination': ['SSRF', 'Open Redirect'],
            'target': ['SSRF'],
            'host': ['SSRF', 'Command Injection'],
            'domain': ['SSRF'],
            'callback': ['SSRF'],
            'webhook': ['SSRF'],
            
            # Command parameters -> Command Injection
            'cmd': ['Command Injection'],
            'command': ['Command Injection'],
            'exec': ['Command Injection'],
            'execute': ['Command Injection'],
            'ping': ['Command Injection'],
            'ip': ['Command Injection'],
            'shell': ['Command Injection'],
            'run': ['Command Injection'],
            
            # Auth parameters -> HIGH RISK
            'token': ['Credential Exposure'],
            'auth': ['Credential Exposure'],
            'key': ['Credential Exposure'],
            'apikey': ['Credential Exposure'],
            'api_key': ['Credential Exposure'],
            'secret': ['Credential Exposure'],
            'password': ['Credential Exposure'],
            'passwd': ['Credential Exposure'],
            'pwd': ['Credential Exposure'],
            'session': ['Credential Exposure'],
            'jwt': ['Credential Exposure'],
            'bearer': ['Credential Exposure'],
            'access_token': ['Credential Exposure'],
            'refresh_token': ['Credential Exposure'],
        }
    
    def _should_filter_parameter(self, param_name: str) -> bool:
        """FIX #2: Check if parameter should be filtered out"""
        if not param_name:
            return True

        clean_name = param_name.strip()
        if len(clean_name) < 2:
            return True
        
        # Filter framework parameters
        if clean_name in self.filtered_params or clean_name.lower() in self.filtered_params_lower:
            return True
        
        # Filter parameters starting with '__'
        if clean_name.startswith('__'):
            return True
        
        # Filter common framework prefixes
        if param_name.startswith('_') and len(param_name) < 4:
            # Single underscore + 2-3 chars are usually framework internals
            return False  # Actually keep these for now, too broad
        
        return False

    def _sanitize_endpoint_params(self, params: Set[str], max_params: int = 5) -> List[str]:
        """
        Normalize, deduplicate, and cap parameter volume per endpoint.
        Keeps signal-rich parameters first.
        """
        normalized = {}
        for param in params:
            if self._should_filter_parameter(param):
                continue
            normalized_name = self.normalize_param(param)
            if normalized_name and normalized_name not in normalized:
                normalized[normalized_name] = param.strip()

        # Prioritize by known signal and then by name length (stable, deterministic)
        ranked = sorted(
            normalized.values(),
            key=lambda p: (
                0 if p.lower() in self.param_vuln_map else 1,
                0 if p.lower() in HIGH_RISK_PARAMS else 1,
                len(p)
            )
        )
        return ranked[:max_params]

    def normalize_param(self, param_name: str) -> str:
        """Normalize parameter for deduplication."""
        return param_name.strip().lower()
    
    def _get_vuln_types(self, param_name: str) -> List[str]:
        """Get vulnerability types for a parameter based on name patterns"""
        param_lower = param_name.lower()
        vuln_types = set()
        
        # Check exact match in config mapping
        if param_lower in self.param_vuln_map:
            vuln_types.update(self.param_vuln_map[param_lower])
        
        # Check pattern mappings
        for pattern, vulns in self.pattern_mappings.items():
            if pattern in param_lower:
                vuln_types.update(vulns)
        
        return list(vuln_types)
    
    def _calculate_risk_level(self, param_name: str, vuln_types: List[str]) -> str:
        """Conservative risk calibration to avoid over-hyping parameters."""
        param_lower = param_name.lower()

        if param_lower in {'password', 'token', 'api_key', 'auth'}:
            return 'HIGH'

        if param_lower in {'id', 'user_id', 'page', 'query'}:
            return 'MEDIUM'

        return 'LOW'
    
    def _calculate_confidence(self, param_name: str, vuln_types: List[str]) -> int:
        """Calculate confidence score (0-10) for classification"""
        param_lower = param_name.lower()
        confidence = 5  # Base confidence
        
        # Exact match in known mappings increases confidence
        if param_lower in self.param_vuln_map:
            confidence += 3
        
        # More vulnerability types = higher confidence it's interesting
        confidence += min(len(vuln_types), 2)
        
        # Known high-risk params
        if param_lower in HIGH_RISK_PARAMS:
            confidence += 2
        
        return min(confidence, 10)
    
    def classify_parameter(self, param_name: str) -> Dict:
        """Classify a single parameter"""
        vuln_types = self._get_vuln_types(param_name)
        risk_level = self._calculate_risk_level(param_name, vuln_types)
        confidence = self._calculate_confidence(param_name, vuln_types)
        
        return {
            'name': param_name,
            'risk_level': risk_level,
            'vulnerability_types': vuln_types,
            'confidence': confidence,
            'test_priority': self._get_test_priority(risk_level, vuln_types)
        }
    
    def _get_test_priority(self, risk_level: str, vuln_types: List[str]) -> int:
        """Get testing priority (1=highest, 5=lowest)"""
        if risk_level == 'CRITICAL':
            return 1
        if risk_level == 'HIGH':
            return 2
        if 'SQLi' in vuln_types or 'IDOR' in vuln_types:
            return 2
        if risk_level == 'MEDIUM':
            return 3
        return 4
    
    def classify_parameters(self, endpoints: Dict[str, Set[str]]) -> Dict[str, List[Dict]]:
        """Classify all parameters across endpoints"""
        print("[*] Classifying parameters by risk and vulnerability type...")
        
        classified = {}
        stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        filtered_count = 0
        
        for endpoint, params in endpoints.items():
            classified[endpoint] = []

            sanitized_params = self._sanitize_endpoint_params(params, max_params=5)
            filtered_count += max(0, len(params) - len(sanitized_params))

            for param in sanitized_params:
                classification = self.classify_parameter(param)
                classified[endpoint].append(classification)
                stats[classification['risk_level']] += 1
        
        self.classifications = classified
        
        # Print summary
        total_params = sum(stats.values()) + filtered_count
        print(f"[*] Parameter classification complete:")
        print(f"    Total parameters: {total_params} (filtered: {filtered_count})")
        print(f"    CRITICAL: {stats['CRITICAL']}, HIGH: {stats['HIGH']}, MEDIUM: {stats['MEDIUM']}, LOW: {stats['LOW']}")
        
        return classified
    
    def get_high_risk_parameters(self) -> List[Dict]:
        """Get all HIGH and CRITICAL risk parameters"""
        high_risk = []
        
        for endpoint, params in self.classifications.items():
            for param in params:
                if param['risk_level'] in ['HIGH', 'CRITICAL']:
                    high_risk.append({
                        'endpoint': endpoint,
                        'parameter': param['name'],
                        'risk_level': param['risk_level'],
                        'vulnerability_types': param['vulnerability_types'],
                        'confidence': param['confidence']
                    })
        
        # Sort by risk level and confidence
        risk_order = {'CRITICAL': 0, 'HIGH': 1}
        high_risk.sort(key=lambda x: (risk_order.get(x['risk_level'], 2), -x['confidence']))
        
        return high_risk
    
    def get_parameters_by_vuln_type(self, vuln_type: str) -> List[Dict]:
        """Get parameters susceptible to a specific vulnerability type"""
        results = []
        
        for endpoint, params in self.classifications.items():
            for param in params:
                if vuln_type in param['vulnerability_types']:
                    results.append({
                        'endpoint': endpoint,
                        'parameter': param['name'],
                        'risk_level': param['risk_level'],
                        'confidence': param['confidence']
                    })
        
        return sorted(results, key=lambda x: -x['confidence'])
    
    def get_test_queue(self) -> List[Dict]:
        """Get prioritized list of parameters for vulnerability testing"""
        queue = []
        
        for endpoint, params in self.classifications.items():
            for param in params:
                if param['vulnerability_types']:  # Only params with identified vuln types
                    queue.append({
                        'endpoint': endpoint,
                        'parameter': param['name'],
                        'vulnerability_types': param['vulnerability_types'],
                        'priority': param['test_priority'],
                        'risk_level': param['risk_level']
                    })
        
        # Sort by priority
        return sorted(queue, key=lambda x: x['priority'])
    
    def get_classifications(self) -> Dict:
        """Return all classifications"""
        return self.classifications
    
    def get_summary(self) -> Dict:
        """Get classification summary statistics"""
        stats = {
            'total_endpoints': len(self.classifications),
            'total_parameters': 0,
            'by_risk_level': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'by_vuln_type': {}
        }
        
        for endpoint, params in self.classifications.items():
            for param in params:
                stats['total_parameters'] += 1
                stats['by_risk_level'][param['risk_level']] += 1
                
                for vtype in param['vulnerability_types']:
                    stats['by_vuln_type'][vtype] = stats['by_vuln_type'].get(vtype, 0) + 1
        
        return stats
