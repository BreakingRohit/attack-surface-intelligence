"""
Correlation Engine
Correlates all findings and creates unified intelligence report
"""

from typing import Dict, List, Set

class CorrelationEngine:
    def __init__(self):
        self.correlated_findings = {}

    def correlate_all_findings(
        self,
        subdomains: Set[str],
        urls: Set[str],
        endpoints: Dict[str, List[str]],
        vulnerabilities: List[Dict],
        scored_endpoints: List[Dict],
        attack_paths: List[Dict]
    ) -> Dict:
        """Correlate all findings into unified intelligence"""
        print("[*] Correlating all findings...")
        
        correlation = {
            'attack_surface_summary': {
                'total_subdomains': len(subdomains),
                'total_urls': len(urls),
                'total_endpoints': len(endpoints),
                'total_parameters': sum(len(p) for p in endpoints.values())
            },
            'security_findings': {
                'total_vulnerabilities': len(vulnerabilities),
                'critical_endpoints': len([e for e in scored_endpoints if e['risk_level'] in ['HIGH', 'CRITICAL']]),
                'attack_paths_identified': len(attack_paths)
            },
            'priority_targets': [],
            'critical_findings': [],
            'recommendations': []
        }
        
        # Identify priority targets (high-risk endpoints)
        priority_targets = [
            e for e in scored_endpoints if e['risk_level'] == 'HIGH'
        ][:5]
        correlation['priority_targets'] = priority_targets
        
        # Identify critical findings
        critical_vulns = [v for v in vulnerabilities if v.get('risk_level') == 'CRITICAL']
        correlation['critical_findings'] = critical_vulns
        
        # Generate recommendations
        if vulnerability_count := len(vulnerabilities):
            correlation['recommendations'].append(
                f"Found {vulnerability_count} potential vulnerabilities with supporting evidence - remediation recommended"
            )
        else:
            correlation['recommendations'].append(
                f"No confirmed vulnerabilities, but {len(attack_paths)} potential attack vectors were identified"
            )
        
        if high_risk := len(priority_targets):
            correlation['recommendations'].append(
                f"Identified {high_risk} high-risk endpoints - prioritize security review"
            )
        
        if len(subdomains) > 10:
            correlation['recommendations'].append(
                "Large attack surface detected - consider segmentation and access controls"
            )
        
        correlation['recommendations'].append(
            "Implement Web Application Firewall (WAF) to protect against identified attack vectors"
        )
        
        self.correlated_findings = correlation
        
        print("[*] Correlation complete")
        
        return correlation

    def get_correlation_report(self) -> Dict:
        """Return full correlation report"""
        return self.correlated_findings
