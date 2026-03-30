"""
Professional Output Formatter
Generates clean, structured CLI output and reports
Designed for attacker-style readability with clear sections
"""

import json
from typing import Dict, List, Set
from datetime import datetime
from pathlib import Path
from config import REPORTS_DIR, COLORS, SEVERITY_COLORS, HIGH_RISK_ENDPOINT_KEYWORDS


class OutputFormatter:
    """Formats and displays reconnaissance results in clean CLI format"""
    
    def __init__(self, use_colors: bool = True, verbose: bool = False):
        self.timestamp = datetime.now().isoformat()
        self.use_colors = use_colors
        self.verbose = verbose
    
    def _color(self, text: str, color_key: str) -> str:
        """Apply color to text if colors are enabled"""
        if not self.use_colors:
            return text
        color = COLORS.get(color_key, '')
        reset = COLORS.get('RESET', '')
        return f"{color}{text}{reset}"
    
    def _severity_color(self, text: str, severity: str) -> str:
        """Apply severity-based color to text"""
        if not self.use_colors:
            return text
        color = SEVERITY_COLORS.get(severity, '')
        reset = COLORS.get('RESET', '')
        return f"{color}{text}{reset}"
    
    def _header(self, title: str, width: int = 70) -> str:
        """Generate a section header"""
        line = "=" * width
        return f"\n{self._color(line, 'CYAN')}\n{self._color(title, 'BOLD')}\n{self._color(line, 'CYAN')}"
    
    def _subheader(self, title: str, width: int = 70) -> str:
        """Generate a subsection header"""
        line = "-" * width
        return f"\n{self._color(title, 'BOLD')}\n{self._color(line, 'GREY')}"
    
    def _is_high_risk_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint is high-risk based on keywords"""
        endpoint_lower = endpoint.lower()
        return any(kw in endpoint_lower for kw in HIGH_RISK_ENDPOINT_KEYWORDS)
    
    def print_banner(self) -> None:
        """Print application banner"""
        banner = """
    ╔═══════════════════════════════════════════════════════════════════╗
    ║         ATTACK SURFACE INTELLIGENCE SYSTEM                        ║
    ║         Production-Grade Recon & Vulnerability Framework          ║
    ╚═══════════════════════════════════════════════════════════════════╝
        """
        print(self._color(banner, 'CYAN'))
    
    def print_attack_surface(
        self,
        subdomains: Set[str],
        urls: Set[str],
        endpoints: Dict[str, Set[str]],
        alive_count: int = None
    ) -> None:
        """Print attack surface summary"""
        print(self._header("[ATTACK SURFACE]"))
        
        total_params = sum(len(p) for p in endpoints.values())
        
        print(f"\n  {self._color('Subdomains Found:', 'BOLD')}    {len(subdomains)}")
        print(f"  {self._color('URLs Discovered:', 'BOLD')}     {len(urls)}")
        print(f"  {self._color('Unique Endpoints:', 'BOLD')}    {len(endpoints)}")
        if alive_count is not None:
            print(f"  {self._color('Alive Endpoints:', 'BOLD')}     {self._color(str(alive_count), 'GREEN')}")
        print(f"  {self._color('Parameters Found:', 'BOLD')}    {total_params}")
        
        # Show subdomains (if verbose)
        if self.verbose and subdomains:
            print(self._subheader("  Subdomains:"))
            for sub in sorted(list(subdomains))[:10]:
                print(f"    - {sub}")
            if len(subdomains) > 10:
                print(f"    ... and {len(subdomains) - 10} more")
    
    def print_high_risk_endpoints(
        self,
        endpoints: Dict[str, Set[str]],
        scored_endpoints: List[Dict] = None
    ) -> None:
        """Print high-risk endpoints section"""
        print(self._header("[HIGH-RISK ENDPOINTS]"))
        
        # Get high-risk from scoring if available
        if scored_endpoints:
            high_risk = [e for e in scored_endpoints if e.get('risk_level') in ['CRITICAL', 'HIGH']]
        else:
            # Fallback to keyword-based detection
            high_risk = [
                {'endpoint': ep, 'params': list(params)}
                for ep, params in endpoints.items()
                if self._is_high_risk_endpoint(ep)
            ]
        
        if not high_risk:
            print(f"\n  {self._color('No high-risk endpoints identified', 'GREY')}")
            return
        
        print()
        for item in high_risk[:15]:
            endpoint = item.get('endpoint', item.get('path', ''))
            params = item.get('params', item.get('parameters', []))
            score = item.get('score', '')
            
            # Format endpoint
            ep_display = f"  * {self._color(endpoint, 'YELLOW')}"
            
            if score:
                ep_display += f"  {self._color(f'(Score: {score}/10)', 'GREY')}"
            
            print(ep_display)
            
            # Show parameters if verbose
            if self.verbose and params:
                params_list = params if isinstance(params, list) else list(params)
                if params_list:
                    print(f"    Parameters: {', '.join(params_list[:5])}")
        
        if len(high_risk) > 15:
            print(f"\n  {self._color(f'... and {len(high_risk) - 15} more high-risk endpoints', 'GREY')}")
    
    def print_vulnerabilities(self, vulnerabilities: List[Dict], endpoints_tested: int = 0, potential_vectors: int = 0) -> None:
        """
        Print vulnerabilities section
        FIX #10: Show meaningful output even if no vulnerabilities confirmed
        """
        print(self._header("[VULNERABILITIES]"))
        
        if not vulnerabilities:
            # FIX #10: More informative message instead of just "No vulnerabilities"
            vectors = potential_vectors or endpoints_tested
            print(f"\n  {self._color('No confirmed vulnerabilities, but potential attack vectors were analyzed', 'GREY')}")
            if endpoints_tested > 0:
                print(f"  {self._color(f'({endpoints_tested} endpoints tested with strict parameter-driven checks)', 'GREY')}")
                print(f"\n  {self._color('Recommendations:', 'BOLD')}")
                print(f"    - Manual testing recommended for high-risk endpoints")
                print(f"    - Review JavaScript files for hidden API endpoints")
                print(f"    - Check authentication and authorization controls")
            return
        
        # Group by severity
        by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for vuln in vulnerabilities:
            sev = vuln.get('severity', vuln.get('risk_level', 'MEDIUM'))
            if sev in by_severity:
                by_severity[sev].append(vuln)
        
        print()
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            vulns = by_severity[severity]
            if not vulns:
                continue
            
            print(f"  {self._severity_color(f'{severity} ({len(vulns)})', severity)}")
            
            for vuln in vulns[:5]:  # Limit per severity for readability
                vuln_type = vuln.get('type', 'Unknown')
                endpoint = vuln.get('endpoint', 'Unknown')
                param = vuln.get('parameter', '')
                confidence = vuln.get('confidence', 'Medium')
                
                # Build display line
                if param:
                    line = f"    - {vuln_type} -> {endpoint}?{param}"
                else:
                    line = f"    - {vuln_type} -> {endpoint}"
                
                line += f"  ({confidence})"
                print(self._severity_color(line, severity))
                if vuln.get('reasoning'):
                    print(f"      Reasoning: {vuln.get('reasoning')}")
            
            if len(vulns) > 5:
                print(f"    {self._color(f'... and {len(vulns) - 5} more {severity} findings', 'GREY')}")
            print()
    
    def print_attack_paths(self, attack_paths: List[Dict]) -> None:
        """Print attack paths section"""
        print(self._header("[ATTACK PATHS]"))
        
        if not attack_paths:
            print(f"\n  {self._color('No attack paths generated', 'GREY')}")
            return
        
        # Display generated paths (already filtered by engine confidence rules)
        prioritized = attack_paths
        
        print()
        displayed = 0
        for path in prioritized[:10]:
            chain_str = path.get('chain_string', '')
            severity = path.get('severity', 'MEDIUM')
            exploit = path.get('exploitability', 'Moderate')
            
            # Format: Source -> Endpoint -> Param -> Vuln (Severity)
            line = f"  * {chain_str}"
            severity_tag = f" ({severity})"
            
            print(f"{self._severity_color(line, severity)}{self._color(severity_tag, 'GREY')}")
            
            displayed += 1
        
        # Show remaining count
        remaining = len(attack_paths) - displayed
        if remaining > 0:
            print(f"\n  {self._color(f'... and {remaining} more attack paths', 'GREY')}")
    def print_summary(
        self,
        target: str,
        subdomains_count: int,
        alive_count: int,
        vulns_count: int,
        high_risk_count: int,
        paths_count: int,
        elapsed_time: float
    ) -> None:
        """Print final summary with contextual reasoning."""
        print(self._header("[SUMMARY]"))

        print(f"""
  Target:              {self._color(target, 'BOLD')}
  Scan Time:           {elapsed_time:.2f} seconds

  Attack Surface:
    - Subdomains:      {subdomains_count}
    - Alive Endpoints: {alive_count}

  Security Findings:
    - Vulnerabilities: {self._color(str(vulns_count), 'RED' if vulns_count > 0 else 'GREEN')}
    - High-Risk Items: {self._color(str(high_risk_count), 'YELLOW' if high_risk_count > 0 else 'GREEN')}
    - Attack Paths:    {paths_count}
""")

        print(self._header("[ASSESSMENT]", 70))
        if vulns_count == 0:
            print(f"\n  {self._color('No confirmed vulnerabilities detected.', 'GREEN')}")
            print(f"  However, {alive_count} endpoints were analyzed for potential attack vectors.")
            print(f"  Further manual testing may be necessary to confirm security posture.")
        elif vulns_count > 10:
            print(f"\n  {self._color('WARNING: Significant number of vulnerabilities discovered!', 'RED')}")
            print(f"  {vulns_count} potential vulnerabilities require immediate remediation.")
            print(f"  High-risk endpoints should be patched before deployment.")
        else:
            print(f"\n  {self._color('CAUTION: Vulnerabilities identified.', 'YELLOW')}")
            print(f"  {vulns_count} findings require attention to secure the application.")

        print(f"\n  {self._color('Recommendations:', 'BOLD')}")
        if high_risk_count > 0:
            print(f"    1. {self._color('URGENT', 'RED')}: Patch {high_risk_count} high-risk endpoints")
        if vulns_count > 0:
            print(f"    2. Review and test fixes for all {vulns_count} findings")
        print(f"    3. Implement security testing in CI/CD pipeline")
        print(f"    4. Enable Web Application Firewall (WAF) rules")
        print(f"    5. Regular security audits (quarterly or as needed)")
    def print_console_report(
        self,
        target: str,
        subdomains: Set[str],
        urls: Set[str],
        endpoints: Dict[str, Set[str]],
        vulnerabilities: List[Dict],
        scored_endpoints: List[Dict],
        attack_paths: List[Dict],
        correlation: Dict,
        elapsed_time: float,
        alive_count: int = None,
        sensitive_files: List[Dict] = None,
        tested_endpoints: int = 0,
        candidate_endpoints: int = 0
    ) -> None:
        """Print full console report with clean formatting"""
        self.print_banner()
        
        # Attack Surface Section
        self.print_attack_surface(subdomains, urls, endpoints, alive_count)
        
        # High-Risk Endpoints Section
        self.print_high_risk_endpoints(endpoints, scored_endpoints)
        
        # Vulnerabilities Section
        self.print_vulnerabilities(
            vulnerabilities,
            endpoints_tested=tested_endpoints or len(scored_endpoints),
            potential_vectors=len(attack_paths)
        )
        alive_total = alive_count if alive_count is not None else len(endpoints)
        tested_safe = min(tested_endpoints, alive_total)
        print(f"  {self._color(f'Tested Endpoints: {tested_safe} / {alive_total}', 'BOLD')}")
        
        # Attack Paths Section
        self.print_attack_paths(attack_paths)
        
        # Summary Section
        high_risk_count = len([e for e in scored_endpoints if e.get('risk_level') in ['CRITICAL', 'HIGH']])
        
        self.print_summary(
            target=target,
            subdomains_count=len(subdomains),
            alive_count=alive_count or len(endpoints),
            vulns_count=len(vulnerabilities),
            high_risk_count=high_risk_count,
            paths_count=len(attack_paths),
            elapsed_time=elapsed_time
        )
    
    def generate_json_report(
        self,
        target: str,
        subdomains: Set[str],
        urls: Set[str],
        endpoints: Dict[str, Set[str]],
        vulnerabilities: List[Dict],
        scored_endpoints: List[Dict],
        attack_paths: List[Dict],
        correlation: Dict,
        sensitive_files: List[Dict] = None
    ) -> Dict:
        """Generate comprehensive JSON report"""
        # Convert sets to lists for JSON serialization
        endpoints_serializable = {k: list(v) for k, v in endpoints.items()}
        
        report = {
            'metadata': {
                'target': target,
                'scan_date': self.timestamp,
                'version': '2.0'
            },
            'attack_surface': {
                'subdomains': sorted(list(subdomains)),
                'subdomains_count': len(subdomains),
                'urls_discovered': len(urls),
                'endpoints': endpoints_serializable,
                'endpoints_count': len(endpoints),
                'total_parameters': sum(len(p) for p in endpoints.values())
            },
            'high_risk_endpoints': [
                e for e in scored_endpoints if e.get('risk_level') in ['CRITICAL', 'HIGH']
            ],
            'security_findings': {
                'vulnerabilities': vulnerabilities,
                'vulnerabilities_count': len(vulnerabilities),
                'by_severity': self._count_by_severity(vulnerabilities),
                'sensitive_files': sensitive_files or [],
                'scored_endpoints': scored_endpoints
            },
            'attack_paths': attack_paths,
            'correlation': correlation,
            'summary': {
                'total_attack_surface': len(subdomains) + len(urls),
                'total_vulnerabilities': len(vulnerabilities),
                'critical_vulns': len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL']),
                'high_vulns': len([v for v in vulnerabilities if v.get('severity') == 'HIGH']),
                'risk_summary': correlation.get('risk_summary', 'N/A')
            }
        }
        
        return report
    
    def _count_by_severity(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in vulnerabilities:
            sev = vuln.get('severity', vuln.get('risk_level', 'MEDIUM'))
            if sev in counts:
                counts[sev] += 1
        return counts
    
    def generate_text_report(
        self,
        target: str,
        subdomains: Set[str],
        urls: Set[str],
        endpoints: Dict[str, Set[str]],
        vulnerabilities: List[Dict],
        scored_endpoints: List[Dict],
        attack_paths: List[Dict],
        correlation: Dict,
        sensitive_files: List[Dict] = None
    ) -> str:
        """Generate human-readable text report (no colors)"""
        lines = []
        
        lines.append("=" * 70)
        lines.append("ATTACK SURFACE INTELLIGENCE REPORT")
        lines.append("=" * 70)
        lines.append(f"Target: {target}")
        lines.append(f"Scan Date: {self.timestamp}")
        lines.append("")
        
        # Attack Surface
        lines.append("[ATTACK SURFACE]")
        lines.append("-" * 70)
        lines.append(f"  Subdomains Found:    {len(subdomains)}")
        lines.append(f"  URLs Discovered:     {len(urls)}")
        lines.append(f"  Unique Endpoints:    {len(endpoints)}")
        lines.append(f"  Total Parameters:    {sum(len(p) for p in endpoints.values())}")
        lines.append("")
        
        # High-Risk Endpoints
        lines.append("[HIGH-RISK ENDPOINTS]")
        lines.append("-" * 70)
        high_risk = [e for e in scored_endpoints if e.get('risk_level') in ['CRITICAL', 'HIGH']]
        if high_risk:
            for item in high_risk[:15]:
                lines.append(f"  * {item.get('endpoint', '')}")
        else:
            lines.append("  No high-risk endpoints identified")
        lines.append("")
        
        # Vulnerabilities
        lines.append("[VULNERABILITIES]")
        lines.append("-" * 70)
        if vulnerabilities:
            for vuln in vulnerabilities[:10]:
                vtype = vuln.get('type', 'Unknown')
                endpoint = vuln.get('endpoint', '')
                param = vuln.get('parameter', '')
                severity = vuln.get('severity', 'MEDIUM')
                confidence = vuln.get('confidence', 'Medium')
                
                if param:
                    lines.append(f"  * {vtype} -> {endpoint}?{param} ({severity}, {confidence})")
                else:
                    lines.append(f"  * {vtype} -> {endpoint} ({severity}, {confidence})")
        else:
            lines.append("  No confirmed vulnerabilities, but potential attack vectors were analyzed")
        lines.append("")

        # Sensitive files
        lines.append("[SENSITIVE FILES]")
        lines.append("-" * 70)
        if sensitive_files:
            for finding in sensitive_files[:10]:
                lines.append(f"  * {finding.get('file', '')} ({finding.get('risk_level', 'LOW')})")
        else:
            lines.append("  No exposed sensitive files confirmed")
        lines.append("")
        
        # Attack Paths
        lines.append("[ATTACK PATHS]")
        lines.append("-" * 70)
        if attack_paths:
            for path in attack_paths[:10]:
                chain_str = path.get('chain_string', '')
                severity = path.get('severity', 'MEDIUM')
                lines.append(f"  * {chain_str} ({severity})")
        else:
            lines.append("  No attack paths generated")
        lines.append("")
        
        # Summary
        lines.append("[SUMMARY]")
        lines.append("-" * 70)
        lines.append(f"  Risk Level: {correlation.get('risk_summary', 'N/A')}")
        lines.append("")
        
        # Recommendations
        lines.append("[RECOMMENDATIONS]")
        lines.append("-" * 70)
        for rec in correlation.get('recommendations', []):
            lines.append(f"  - {rec}")
        lines.append("")
        
        lines.append("=" * 70)
        lines.append("END OF REPORT")
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    def save_report(self, target: str, report_data: str, report_type: str, 
                    output_path: str = None) -> str:
        """Save report to file"""
        # Sanitize target for filename
        safe_target = target.replace('.', '_').replace('/', '_').replace(':', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if output_path:
            path = Path(output_path)
        else:
            ext = 'json' if report_type == 'json' else 'txt'
            path = REPORTS_DIR / f"{safe_target}_{timestamp}.{ext}"
        
        # Ensure directory exists
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write report
        with open(path, 'w') as f:
            if report_type == 'json':
                json.dump(report_data, f, indent=2, default=str)
            else:
                f.write(report_data)
        
        print(f"\n[+] Report saved: {path}")
        return str(path)
    
    def save_reports(
        self,
        target: str,
        json_report: Dict,
        text_report: str,
        json_path: str = None,
        text_path: str = None
    ) -> tuple:
        """Save both JSON and text reports"""
        json_file = self.save_report(target, json_report, 'json', json_path)
        text_file = self.save_report(target, text_report, 'text', text_path)
        return json_file, text_file

