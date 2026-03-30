"""
Risk Scoring Engine
Assigns risk scores and levels to endpoints and findings

FIX #4: Added RISK_MAP to convert string risk levels to numeric values
for proper comparison operations (fixes '>=' not supported error)
"""

from typing import Dict, List

# FIX #4: Risk level to numeric mapping (prevents string vs int comparison errors)
RISK_MAP = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

# Reverse mapping for display
RISK_LEVELS = {v: k for k, v in RISK_MAP.items()}


class RiskScoring:
    def __init__(self):
        self.scored_endpoints = []

    def score_endpoint(self, endpoint: str, parameters: List[Dict]) -> Dict:
        """Score an endpoint based on parameters and characteristics"""
        base_score = 1
        endpoint_lower = endpoint.lower()
        
        # Analyze endpoint characteristics
        if any(k in endpoint_lower for k in ['/admin', 'admin', 'login', 'auth', 'signin', 'oauth']):
            base_score += 5
        if '/api' in endpoint_lower or any(k in endpoint_lower for k in ['/v1/', '/v2/', 'graphql']):
            base_score += 4
        if any(k in endpoint_lower for k in ['/user', '/profile', 'account', 'settings']):
            base_score += 2
        
        # Count high-risk parameters
        high_risk_param_count = 0
        medium_risk_param_count = 0
        
        for param in parameters:
            p_lower = param.lower()
            if any(k in p_lower for k in ['id', 'user_id', 'account_id', 'order_id']):
                high_risk_param_count += 1
            elif any(k in p_lower for k in ['search', 'query', 'keyword', 'q']):
                medium_risk_param_count += 1
        
        # Increase score based on parameters
        base_score += (high_risk_param_count * 2)
        base_score += (medium_risk_param_count * 1)
        
        # Determine risk level
        if base_score >= 10:
            risk_level = 'CRITICAL'
        elif base_score >= 7:
            risk_level = 'HIGH'
        elif base_score >= 4:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'endpoint': endpoint,
            'score': base_score,
            'risk_level': risk_level,
            'parameter_count': len(parameters),
            'high_risk_params': high_risk_param_count,
            'confidence': min(10, 4 + high_risk_param_count + (2 if '/api' in endpoint_lower else 0))
        }

    def score_endpoints(self, endpoints: Dict[str, List[str]]) -> List[Dict]:
        """Score all endpoints"""
        print("[*] Scoring endpoints by risk...")
        
        scored = []
        
        for endpoint, parameters in endpoints.items():
            score = self.score_endpoint(endpoint, parameters)
            scored.append(score)
        
        # Sort by score (highest risk first)
        scored = sorted(scored, key=lambda x: x['score'], reverse=True)
        
        self.scored_endpoints = scored
        
        # Print summary
        high_count = sum(1 for s in scored if s['risk_level'] in ['HIGH', 'CRITICAL'])
        medium_count = sum(1 for s in scored if s['risk_level'] == 'MEDIUM')
        
        print(f"[*] Risk scoring complete: {high_count} HIGH, {medium_count} MEDIUM")
        
        return scored

    def score_vulnerability(self, vulnerability: Dict) -> Dict:
        """
        Score a detected vulnerability
        FIX #4: Ensure all score comparisons use numeric values
        """
        # Get confidence - handle both string and numeric
        confidence_raw = vulnerability.get('confidence', 'Medium')
        if isinstance(confidence_raw, str):
            confidence_map = {'Low': 3, 'Medium': 5, 'High': 8}
            base_score = confidence_map.get(confidence_raw, 5)
        else:
            base_score = int(confidence_raw) if confidence_raw else 5
        
        vuln_type = vulnerability.get('type', '')
        
        # Severity multipliers for vulnerability types
        severity_map = {
            'SQLi': 1.5,
            'XSS': 1.3,
            'Reflected XSS': 1.3,
            'IDOR': 1.4,
            'LFI': 1.8,
            'SSRF': 1.6,
            'Command Injection': 2.0,
            'Open Redirect': 1.2,
            'Credential Exposure': 2.0
        }
        
        if vuln_type in severity_map:
            base_score *= severity_map[vuln_type]
        
        # FIX #4: Use numeric comparison for risk level determination
        if base_score >= 10:
            risk_level = 'CRITICAL'
            risk_numeric = RISK_MAP['CRITICAL']
        elif base_score >= 7:
            risk_level = 'HIGH'
            risk_numeric = RISK_MAP['HIGH']
        elif base_score >= 4:
            risk_level = 'MEDIUM'
            risk_numeric = RISK_MAP['MEDIUM']
        else:
            risk_level = 'LOW'
            risk_numeric = RISK_MAP['LOW']
        
        return {
            **vulnerability,
            'final_score': round(base_score, 2),
            'risk_level': risk_level,
            'risk_numeric': risk_numeric  # For numeric comparisons
        }

    def score_findings(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Score all vulnerability findings
        FIX #4: Sort by numeric score to avoid string comparison errors
        """
        print("[*] Scoring vulnerability findings...")
        
        scored_findings = []
        
        for vuln in vulnerabilities:
            scored = self.score_vulnerability(vuln)
            scored_findings.append(scored)
        
        # FIX #4: Sort by numeric final_score (always a float/int)
        scored_findings = sorted(
            scored_findings,
            key=lambda x: (x.get('risk_numeric', 0), x.get('final_score', 0)),
            reverse=True
        )
        
        # Print summary
        critical = sum(1 for f in scored_findings if f.get('risk_level') == 'CRITICAL')
        high = sum(1 for f in scored_findings if f.get('risk_level') == 'HIGH')
        
        if critical > 0 or high > 0:
            print(f"[!] Found {critical} CRITICAL and {high} HIGH severity vulnerabilities")
        
        return scored_findings

    def get_high_risk_endpoints(self) -> List[Dict]:
        """Return HIGH-risk endpoints"""
        return [e for e in self.scored_endpoints if e['risk_level'] == 'HIGH']

    def get_scored_endpoints(self) -> List[Dict]:
        """Return all scored endpoints"""
        return self.scored_endpoints
