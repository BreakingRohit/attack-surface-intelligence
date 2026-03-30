"""
Report generation in multiple formats
"""

import logging
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates security reports in various formats"""
    
    def __init__(self):
        self.surface = None
    
    def generate_text_report(self, results: Dict[str, Any]) -> str:
        """Generate text/console report from reconnaissance results"""
        self.surface = results
        
        report = []
        report.append("=" * 80)
        report.append("ATTACK SURFACE INTELLIGENCE SYSTEM - SECURITY REPORT")
        report.append("=" * 80)
        report.append(f"\nTarget: {results.get('target', 'Unknown')}")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Summary
        report.append("\n" + "=" * 80)
        report.append("EXECUTIVE SUMMARY")
        report.append("=" * 80)
        
        subdomains = results.get('subdomains', set())
        urls = results.get('urls', set())
        endpoints = results.get('endpoints', {})
        vulnerabilities = results.get('vulnerabilities', [])
        scored_endpoints = results.get('scored_endpoints', [])
        
        report.append(f"\nAttack Surface Size:")
        report.append(f"  • Subdomains: {len(subdomains)}")
        report.append(f"  • URLs: {len(urls)}")
        report.append(f"  • Endpoints: {len(endpoints)}")
        
        high_conf_vulns = len([v for v in vulnerabilities if v.get('confidence', 0) >= 0.8])
        high_risk_eps = len([e for e in scored_endpoints if e.get('risk_level') == 'HIGH'])
        critical_count = len([v for v in vulnerabilities if v.get('risk_level') == 'CRITICAL'])
        
        report.append(f"\nSecurity Findings:")
        report.append(f"  • Total Vulnerabilities: {len(vulnerabilities)}")
        report.append(f"  • Critical Severity: {critical_count}")
        report.append(f"  • High Confidence: {high_conf_vulns}")
        report.append(f"  • High Risk Endpoints: {high_risk_eps}")
        
        # Risk Distribution
        report.append("\n" + "=" * 80)
        report.append("RISK DISTRIBUTION")
        report.append("=" * 80)
        
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for endpoint in scored_endpoints:
            risk_level = endpoint.get('risk_level', 'LOW')
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
        
        report.append("\nBy Risk Level:")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = risk_counts.get(level, 0)
            report.append(f"  • {level}: {count}")
        
        # Top Vulnerabilities
        report.append("\n" + "=" * 80)
        report.append("TOP FINDINGS")
        report.append("=" * 80)
        
        vulns_by_type = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in vulns_by_type:
                vulns_by_type[vuln_type] = []
            vulns_by_type[vuln_type].append(vuln)
        
        for vuln_type, vulns in sorted(vulns_by_type.items()):
            report.append(f"\n{vuln_type} ({len(vulns)} findings):")
            for vuln in vulns[:5]:  # Top 5 per type
                report.append(f"  • Endpoint: {vuln.get('endpoint', 'N/A')}")
                report.append(f"    Parameter: {vuln.get('parameter') or 'N/A'}")
                report.append(f"    Confidence: {vuln.get('confidence', 0):.0%}")
                report.append(f"    Risk: {vuln.get('risk_level', 'UNKNOWN')}")
        
        # High Risk Endpoints
        report.append("\n" + "=" * 80)
        report.append("HIGH RISK ENDPOINTS")
        report.append("=" * 80)
        
        high_risk = [e for e in scored_endpoints if e.get('risk_level') in ['HIGH', 'CRITICAL']]
        report.append(f"\nTotal: {len(high_risk)}\n")
        
        for endpoint in high_risk[:10]:
            report.append(f"  • {endpoint.get('endpoint', '/')}")
            report.append(f"    Risk Level: {endpoint.get('risk_level', 'UNKNOWN')}")
            report.append(f"    Risk Score: {endpoint.get('score', 'N/A')}")
            report.append(f"    Parameters: {endpoint.get('parameter_count', 0)}")
        
        # Sensitive Parameters
        report.append("\n" + "=" * 80)
        report.append("SENSITIVE PARAMETERS")
        report.append("=" * 80)
        
        all_params = []
        for ep in endpoints.values():
            for param in ep.get('parameters', []):
                if param not in all_params:
                    all_params.append(param)
        
        report.append(f"\nTotal Unique Parameters: {len(all_params)}\n")
        
        for param in all_params[:10]:
            report.append(f"  • {param}")
        
        # Recommendations
        report.append("\n" + "=" * 80)
        report.append("RECOMMENDATIONS")
        report.append("=" * 80)
        
        report.append("""
1. INPUT VALIDATION & OUTPUT ENCODING
   - Implement strict input validation for all parameters
   - Use parameterized queries to prevent SQLi
   - Properly encode output to prevent XSS

2. ACCESS CONTROL
   - Implement proper authorization checks for sensitive endpoints
   - Use role-based access control (RBAC)
   - Verify user permissions before returning object data

3. CONFIGURATION HARDENING
   - Remove debug endpoints and test paths
   - Disable error messages revealing system info
   - Review and restrict directory access

4. MONITORING & DETECTION
   - Implement WAF rules for detected vulnerability types
   - Log and monitor access to high-risk endpoints
   - Set up alerts for suspicious parameter values

5. VULNERABILITY MANAGEMENT
   - Prioritize fixing high-confidence, critical-risk findings
   - Implement penetration testing program
   - Regular security code reviews
        """)
        
        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def generate_summary(self, results: Dict[str, Any]) -> str:
        """Generate brief summary from results dictionary"""
        subdomains = results.get('subdomains', set())
        urls = results.get('urls', set())
        endpoints = results.get('endpoints', {})
        vulnerabilities = results.get('vulnerabilities', [])
        scored_endpoints = results.get('scored_endpoints', [])
        
        lines = [
            f"Target: {results.get('target', 'Unknown')}",
            f"Subdomains: {len(subdomains)}",
            f"URLs: {len(urls)}",
            f"Endpoints: {len(endpoints)}",
            f"Vulnerabilities: {len(vulnerabilities)}",
            f"High Confidence: {len([v for v in vulnerabilities if v.get('confidence', 0) >= 0.8])}",
            f"High Risk Endpoints: {len([e for e in scored_endpoints if e.get('risk_level') == 'HIGH'])}",
        ]
        
        return "\n".join(lines)
