"""
Enhanced Attack Path Generation Engine
Generates attacker-style attack chains with logical progression
Format: Source -> Endpoint -> Parameter -> Vulnerability (Severity)
"""

from typing import Dict, List, Set
from config import HIGH_RISK_ENDPOINT_KEYWORDS


class AttackPathEngine:
    """Generates intelligent attack paths from reconnaissance data"""
    
    def __init__(self):
        self.attack_paths = []
        self.path_templates = {
            'js_discovery': {
                'source': 'JavaScript Analysis',
                'description': 'Hidden endpoint discovered via JS analysis'
            },
            'api_abuse': {
                'source': 'API Enumeration',
                'description': 'API endpoint discovered for abuse testing'
            },
            'admin_bypass': {
                'source': 'Directory Discovery',
                'description': 'Admin panel discovered for authentication testing'
            },
            'idor_chain': {
                'source': 'Parameter Analysis',
                'description': 'ID parameter found for IDOR exploitation'
            },
            'injection_chain': {
                'source': 'Vulnerability Scan',
                'description': 'Injection point discovered'
            }
        }
    
    def _is_high_risk_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint contains high-risk keywords"""
        endpoint_lower = endpoint.lower()
        return any(keyword in endpoint_lower for keyword in HIGH_RISK_ENDPOINT_KEYWORDS)
    
    def _get_severity_weight(self, severity: str) -> int:
        """Get numeric weight for severity"""
        weights = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        return weights.get(severity, 0)

    def _parameter_risk_level(self, param: str) -> str:
        """Heuristic parameter risk to suppress weak attack-path signals."""
        p = (param or "").lower()
        if p in {'password', 'token', 'api_key', 'auth'}:
            return 'HIGH'
        if p in {'id', 'user_id', 'page', 'query'}:
            return 'MEDIUM'
        return 'LOW'

    def _params_as_list(self, params) -> List[str]:
        """Normalize endpoint parameters to a stable list (handles set/list/tuple)."""
        if not params:
            return []
        if isinstance(params, set):
            return sorted(list(params))
        if isinstance(params, (list, tuple)):
            return list(params)
        return [str(params)]
    
    def _generate_path_from_vuln(self, vuln: Dict, js_endpoints: Set[str]) -> Dict:
        """Generate attack path from a vulnerability finding"""
        endpoint = vuln.get('endpoint', 'Unknown')
        param = vuln.get('parameter', 'Unknown')
        vuln_type = vuln.get('type', 'Unknown')
        potential_vuln_type = f"Potential {vuln_type}"
        severity = vuln.get('severity', 'MEDIUM')
        confidence = vuln.get('confidence', 'Medium')

        # Only produce realistic paths from strong evidence and meaningful params.
        if confidence != 'High':
            return {}
        if not param or param == 'Unknown':
            return {}
        if self._parameter_risk_level(param) not in {'HIGH', 'MEDIUM'}:
            return {}
        
        # Determine source based on endpoint characteristics
        if endpoint in js_endpoints or any(js in endpoint for js in ['.js', 'api/', '/v1/', '/v2/']):
            source = 'JS'
        elif '/api' in endpoint.lower():
            source = 'API Discovery'
        elif any(kw in endpoint.lower() for kw in ['admin', 'dashboard', 'manage']):
            source = 'Directory Scan'
        else:
            source = 'Web Crawling'
        
        # Build attack chain string (attacker-style format)
        chain_str = f"{source} -> {endpoint} -> {param} -> {potential_vuln_type} -> {self._get_impact_description(vuln_type)}"
        
        # FIX #9: Add exploit steps and impact
        exploit_steps = self._get_exploit_steps(vuln_type)
        impact = self._get_impact_description(vuln_type)
        
        return {
            'chain_string': chain_str,
            'chain': [
                source,
                f'Found Endpoint: {endpoint}',
                f'Parameter: {param}',
                f'Vulnerability: {potential_vuln_type}'
            ],
            'source': source,
            'endpoint': endpoint,
            'parameter': param,
            'attack_type': potential_vuln_type,
            'severity': 'INFO',
            'confidence': confidence,
            'steps': 4,
            'exploitability': self._calculate_exploitability(vuln_type, confidence),
            'exploit_methodology': exploit_steps,
            'business_impact': impact,
            'reasoning': vuln.get('reasoning', f'{potential_vuln_type} discovered through parameter-driven testing on {param}.'),
            'risk_chain': f"{severity} {potential_vuln_type} on {endpoint} via {param}"
        }
    
    def _calculate_exploitability(self, vuln_type: str, confidence: str) -> str:
        """Calculate exploitability rating"""
        high_exploit_vulns = ['SQLi', 'Command Injection', 'LFI', 'IDOR']
        
        if vuln_type in high_exploit_vulns and confidence == 'High':
            return 'Easy'
        elif vuln_type in high_exploit_vulns:
            return 'Moderate'
        elif confidence == 'High':
            return 'Moderate'
        else:
            return 'Complex'
    
    def _get_exploit_steps(self, vuln_type: str) -> List[str]:
        """FIX #9: Get exploit methodology for vulnerability type"""
        exploit_steps = {
            'SQLi': [
                '1. Identify vulnerable parameter accepting user input',
                '2. Test with SQL meta-characters (", \', --)',
                '3. Confirm injection by observing error messages or behavior changes',
                '4. Execute database queries to extract sensitive data',
                '5. Escalate to full database compromise or RCE'
            ],
            'XSS': [
                '1. Identify parameter that reflects user input in HTML',
                '2. Test with JavaScript payload (<script>alert()</script>)',
                '3. Confirm execution by observing JavaScript execution',
                '4. Steal user sessions and cookies',
                '5. Phish users or perform malicious actions on their behalf'
            ],
            'IDOR': [
                '1. Identify endpoint with ID parameter',
                '2. Note the ID value for current user resource',
                '3. Attempt to access other user IDs (1, 2, 3, etc.)',
                '4. If accessible, extract unauthorized user data',
                '5. Modify/delete other user resources if writable'
            ],
            'LFI': [
                '1. Identify file parameter in endpoint',
                '2. Test path traversal with ../ sequences',
                '3. Access sensitive files like /etc/passwd',
                '4. Extract configuration files with credentials',
                '5. Gain system access through revealed information'
            ],
            'SSRF': [
                '1. Identify URL parameter in application',
                '2. Supply internal IP address or internal domain',
                '3. Bypass firewall to access internal services',
                '4. Query internal metadata services (AWS metadata)',
                '5. Escalate to internal system compromise'
            ],
            'Command Injection': [
                '1. Identify parameter passed to system commands',
                '2. Test with command separators (;, |, &, ||)',
                '3. Execute arbitrary system commands',
                '4. Gain shell access to server',
                '5. Complete system compromise'
            ],
            'Open Redirect': [
                '1. Identify redirect parameter in endpoint',
                '2. Inject external URL',
                '3. Create legitimate-looking phishing URL',
                '4. Trick users into clicking malicious link',
                '5. Steal credentials via fake login page'
            ]
        }
        return exploit_steps.get(vuln_type, ['1. Test parameter for vulnerability', '2. Confirm with payloads', '3. Determine severity'])
    
    def _get_impact_description(self, vuln_type: str) -> str:
        """FIX #9: Get business impact description"""
        impacts = {
            'SQLi': 'Attacker can read, modify, or delete database contents. Potential for full system compromise.',
            'XSS': 'Attacker can steal user sessions, credentials, and perform unauthorized actions. Phishing attacks possible.',
            'IDOR': 'Attacker can access or modify other users\' private data without authorization.',
            'LFI': 'Attacker can read sensitive files including configuration and credentials leading to system access.',
            'SSRF': 'Attacker can access internal services and cloud metadata, potentially leading to lateral movement.',
            'Command Injection': 'Attacker can execute arbitrary system commands and gain complete control of the server.',
            'Open Redirect': 'Attacker can trick users into visiting malicious sites via trusted domain. Used for phishing.'
        }
        return impacts.get(vuln_type, 'Vulnerability allows attacker to compromise security.')
    
    def _generate_api_paths(self, endpoints: Dict[str, List[str]]) -> List[Dict]:
        """Generate attack paths for API endpoints"""
        paths = []
        
        api_endpoints = [ep for ep in endpoints.keys() if '/api' in ep.lower()]
        
        for api in api_endpoints[:5]:  # Limit for performance
            params = self._params_as_list(endpoints.get(api, []))
            
            path = {
                'chain_string': f"API Discovery -> {api} -> Enumerate -> API Abuse/IDOR",
                'chain': [
                    'API Discovery',
                    f'API Endpoint: {api}',
                    f'Parameters: {", ".join(params[:3]) if params else "None"}',
                    'Test for API Abuse / IDOR'
                ],
                'source': 'API Discovery',
                'endpoint': api,
                'parameter': params[0] if params else 'N/A',
                'attack_type': 'API Abuse',
                'severity': 'HIGH',
                'confidence': 'Medium',
                'steps': 4,
                'exploitability': 'Moderate',
                'exploit_methodology': ['1. Enumerate API object IDs', '2. Probe authorization boundaries', '3. Chain with sensitive actions'],
                'business_impact': 'Unauthorized API data exposure and privilege misuse.',
                'reasoning': 'API endpoints with parameters are high-value abuse targets.'
            }
            paths.append(path)
        
        return paths
    
    def _generate_admin_paths(self, endpoints: Dict[str, List[str]]) -> List[Dict]:
        """Generate attack paths for admin/sensitive endpoints"""
        paths = []
        
        admin_keywords = ['admin', 'dashboard', 'manage', 'panel', 'console', 'portal']
        admin_endpoints = [
            ep for ep in endpoints.keys()
            if any(kw in ep.lower() for kw in admin_keywords)
        ]
        
        for admin in admin_endpoints[:3]:
            path = {
                'chain_string': f"Directory Scan -> {admin} -> Potential Auth Bypass -> Unauthorized Access",
                'chain': [
                    'Directory Discovery',
                    f'Admin Panel: {admin}',
                    'Attempt Potential Authentication Bypass',
                    'Gain Unauthorized Access'
                ],
                'source': 'Directory Discovery',
                'endpoint': admin,
                'parameter': 'N/A',
                'attack_type': 'Authentication Bypass',
                'severity': 'CRITICAL',
                'confidence': 'Medium',
                'steps': 4,
                'exploitability': 'Moderate',
                'exploit_methodology': ['1. Validate auth workflow', '2. Probe session controls', '3. Attempt forced browsing'],
                'business_impact': 'Admin or privileged access bypass can result in full application compromise.',
                'reasoning': 'Administrative endpoints represent direct high-impact attack surface.'
            }
            paths.append(path)
        
        return paths
    
    def _generate_idor_paths(self, endpoints: Dict[str, List[str]]) -> List[Dict]:
        """Generate attack paths for potential IDOR"""
        paths = []
        
        id_params = []
        for ep, params in endpoints.items():
            for p in params:
                if 'id' in p.lower():
                    id_params.append((ep, p))
        
        for endpoint, param in id_params[:5]:
            path = {
                'chain_string': f"Parameter Analysis -> {endpoint} -> {param} -> IDOR",
                'chain': [
                    'Endpoint Discovery',
                    f'Found ID Parameter: {param}',
                    f'Endpoint: {endpoint}',
                    'Test IDOR / Privilege Escalation'
                ],
                'source': 'Parameter Analysis',
                'endpoint': endpoint,
                'parameter': param,
                'attack_type': 'IDOR',
                'severity': 'HIGH',
                'confidence': 'Medium',
                'steps': 4,
                'exploitability': 'Easy',
                'exploit_methodology': ['1. Change object identifiers', '2. Compare responses', '3. Access unauthorized resources'],
                'business_impact': 'Cross-tenant data exposure and account takeover pathways.',
                'reasoning': 'ID-like parameters are typical IDOR pivot points.'
            }
            paths.append(path)
        
        return paths
    
    def _generate_js_intel_paths(self, endpoints: Dict[str, List[str]], 
                                  js_endpoints: Set[str]) -> List[Dict]:
        """Generate attack paths from JavaScript intelligence"""
        paths = []
        
        # Find endpoints that were discovered via JS
        js_discovered = [ep for ep in endpoints.keys() if ep in js_endpoints]
        
        for js_ep in js_discovered[:3]:
            params = self._params_as_list(endpoints.get(js_ep, []))
            
            path = {
                'chain_string': f"JS -> {js_ep} -> {params[0] if params else 'explore'} -> Hidden API",
                'chain': [
                    'JavaScript Analysis',
                    f'Hidden Endpoint: {js_ep}',
                    f'Parameters: {", ".join(params[:2]) if params else "Enumerate"}',
                    'Test Hidden Functionality'
                ],
                'source': 'JavaScript Analysis',
                'endpoint': js_ep,
                'parameter': params[0] if params else 'N/A',
                'attack_type': 'Hidden API Abuse',
                'severity': 'HIGH',
                'confidence': 'Medium',
                'steps': 4,
                'exploitability': 'Moderate',
                'exploit_methodology': ['1. Replay hidden endpoint calls', '2. Fuzz parameters', '3. Validate auth bypass edge cases'],
                'business_impact': 'Undocumented functionality can bypass intended controls.',
                'reasoning': 'JavaScript-discovered endpoints are often less monitored and less hardened.'
            }
            paths.append(path)
        
        return paths
    
    def generate_paths(
        self,
        endpoints: Dict[str, List[str]],
        vulnerabilities: List[Dict],
        js_endpoints: Set[str]
    ) -> List[Dict]:
        """
        Generate comprehensive attack paths from reconnaissance data
        Prioritizes paths based on vulnerabilities found
        """
        print("[*] Generating attack paths...")
        
        paths = []
        
        # 1. Generate paths from discovered vulnerabilities (highest priority)
        for vuln in vulnerabilities:
            path = self._generate_path_from_vuln(vuln, js_endpoints)
            if path:
                paths.append(path)
        
        # Deduplicate paths based on chain_string
        seen = set()
        unique_paths = []
        for path in paths:
            if path['chain_string'] not in seen:
                seen.add(path['chain_string'])
                unique_paths.append(path)
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        unique_paths.sort(key=lambda x: severity_order.get(x['severity'], 4))
        
        self.attack_paths = unique_paths
        
        print(f"[*] Generated {len(unique_paths)} unique attack paths")
        
        return unique_paths
    
    def prioritize_paths(self) -> List[Dict]:
        """Return paths sorted by severity and exploitability"""
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        exploit_order = {'Easy': 0, 'Moderate': 1, 'Complex': 2}
        
        return sorted(
            self.attack_paths,
            key=lambda x: (
                severity_order.get(x['severity'], 4),
                exploit_order.get(x['exploitability'], 3)
            )
        )
    
    def get_paths_by_type(self, attack_type: str) -> List[Dict]:
        """Get attack paths by vulnerability type"""
        return [p for p in self.attack_paths if p['attack_type'] == attack_type]
    
    def get_paths_by_severity(self, severity: str) -> List[Dict]:
        """Get attack paths by severity"""
        return [p for p in self.attack_paths if p['severity'] == severity]
    
    def get_critical_paths(self) -> List[Dict]:
        """Get CRITICAL and HIGH severity paths"""
        return [p for p in self.attack_paths if p['severity'] in ['CRITICAL', 'HIGH']]
    
    def get_attack_paths(self) -> List[Dict]:
        """Return all attack paths"""
        return self.attack_paths
    
    def get_summary(self) -> Dict:
        """Get attack path summary statistics"""
        summary = {
            'total_paths': len(self.attack_paths),
            'by_severity': {},
            'by_type': {},
            'by_source': {}
        }
        
        for path in self.attack_paths:
            # By severity
            sev = path['severity']
            summary['by_severity'][sev] = summary['by_severity'].get(sev, 0) + 1
            
            # By type
            atype = path['attack_type']
            summary['by_type'][atype] = summary['by_type'].get(atype, 0) + 1
            
            # By source
            src = path['source']
            summary['by_source'][src] = summary['by_source'].get(src, 0) + 1
        
        return summary
