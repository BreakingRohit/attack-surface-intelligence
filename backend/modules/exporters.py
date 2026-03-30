"""
Export findings to various formats (JSON, HTML, etc.)
"""

import json
import logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)


class JSONExporter:
    """Export to JSON format"""
    
    @staticmethod
    def export(results: Dict[str, Any]) -> str:
        """Export results to JSON format"""
        
        subdomains = results.get('subdomains', set())
        urls = results.get('urls', set())
        endpoints = results.get('endpoints', {})
        vulnerabilities = results.get('vulnerabilities', [])
        scored_endpoints = results.get('scored_endpoints', [])
        attack_paths = results.get('attack_paths', [])
        
        # Convert sets to lists for JSON serialization
        data = {
            "metadata": {
                "target": results.get('target', 'Unknown'),
                "generated_at": datetime.now().isoformat(),
                "version": "2.0"
            },
            "assets": {
                "subdomains_count": len(subdomains),
                "subdomains": sorted(list(subdomains))[:100],
                "urls_count": len(urls),
                "endpoints_count": len(endpoints),
                "endpoints": list(endpoints.keys())[:50]
            },
            "findings": {
                "vulnerabilities_count": len(vulnerabilities),
                "vulnerabilities": vulnerabilities[:100],
                "critical_count": len([v for v in vulnerabilities if v.get('risk_level') == 'CRITICAL']),
                "high_count": len([v for v in vulnerabilities if v.get('risk_level') == 'HIGH']),
                "attack_paths_count": len(attack_paths),
                "attack_paths": attack_paths[:20]
            },
            "statistics": {
                "total_endpoints": len(endpoints),
                "high_risk_endpoints": len([e for e in scored_endpoints if e.get('risk_level') == 'HIGH']),
                "critical_endpoints": len([e for e in scored_endpoints if e.get('risk_level') == 'CRITICAL']),
                "scan_time": results.get('scan_time', 0)
            }
        }
        
        return json.dumps(data, indent=2, default=str)


class HTMLExporter:
    """Export to HTML format"""
    
    @staticmethod
    def export(results: Dict[str, Any]) -> str:
        """Export results to HTML format"""
        
        target = results.get('target', 'Unknown')
        subdomains = results.get('subdomains', set())
        urls = results.get('urls', set())
        endpoints = results.get('endpoints', {})
        vulnerabilities = results.get('vulnerabilities', [])
        scored_endpoints = results.get('scored_endpoints', [])
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ASIS Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 20px; border-radius: 8px; margin-bottom: 30px; }}
        h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .meta {{ opacity: 0.9; font-size: 0.9em; }}
        .section {{ background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h2 {{ color: #667eea; border-bottom: 2px solid #667eea; padding-bottom: 10px; margin-bottom: 15px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .stat-card {{ background: #f9f9f9; padding: 15px; border-radius: 6px; border-left: 4px solid #667eea; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #667eea; }}
        .stat-label {{ color: #666; font-size: 0.9em; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th {{ background: #f0f0f0; padding: 10px; text-align: left; font-weight: 600; }}
        td {{ padding: 10px; border-bottom: 1px solid #eee; }}
        tr:hover {{ background: #f9f9f9; }}
        .critical {{ background: #ffebee; color: #c62828; }}
        .high {{ background: #fff3e0; color: #e65100; }}
        .medium {{ background: #f3e5f5; color: #6a1b9a; }}
        .low {{ background: #e8f5e9; color: #2e7d32; }}
        .info {{ background: #e3f2fd; color: #1565c0; }}
        .risk-badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: 600; }}
        .footer {{ text-align: center; color: #999; margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Attack Surface Intelligence Report</h1>
            <p class="meta">Target: <strong>{target}</strong></p>
            <p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="grid">
                <div class="stat-card">
                    <div class="stat-value">{len(subdomains)}</div>
                    <div class="stat-label">Subdomains</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{len(endpoints)}</div>
                    <div class="stat-label">Endpoints</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{len(urls)}</div>
                    <div class="stat-label">URLs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{len(vulnerabilities)}</div>
                    <div class="stat-label">Vulnerabilities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{len([v for v in vulnerabilities if v.get('confidence', 0) >= 0.8])}</div>
                    <div class="stat-label">High Confidence</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{len([e for e in scored_endpoints if e.get('risk_level') == 'HIGH'])}</div>
                    <div class="stat-label">High Risk Endpoints</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🎯 Top Findings</h2>
            <table>
                <tr>
                    <th>Type</th>
                    <th>Endpoint</th>
                    <th>Parameter</th>
                    <th>Confidence</th>
                    <th>Risk Level</th>
                </tr>
"""
        
        for vuln in vulnerabilities[:10]:
            risk_class = vuln.get('risk_level', 'low').lower()
            html += f"""                <tr class="{risk_class}">
                    <td>{vuln.get('type', 'Unknown')}</td>
                    <td><code>{vuln.get('endpoint', 'N/A')}</code></td>
                    <td>{vuln.get('parameter') or 'N/A'}</td>
                    <td>{vuln.get('confidence', 0):.0%}</td>
                    <td><span class="risk-badge">{vuln.get('risk_level', 'UNKNOWN')}</span></td>
                </tr>
"""
        
        html += """            </table>
        </div>
        
        <div class="section">
            <h2>⚠️ High Risk Endpoints</h2>
            <table>
                <tr>
                    <th>Endpoint</th>
                    <th>Method</th>
                    <th>Risk Level</th>
                </tr>
"""
        
        high_risk = [e for e in scored_endpoints if e.get('risk_level') in ['HIGH', 'CRITICAL']]
        for endpoint in high_risk[:10]:
            risk_class = endpoint.get('risk_level', 'low').lower()
            html += f"""                <tr>
                    <td><code>{endpoint.get('endpoint', '/')}</code></td>
                    <td>Risk Score: {endpoint.get('score', 'N/A')}</td>
                    <td><span class="risk-badge {risk_class}">{endpoint.get('risk_level', 'UNKNOWN')}</span></td>
                </tr>
"""
        
        html += """            </table>
        </div>
        
        <div class="footer">
            <p>Attack Surface Intelligence System • Comprehensive Security Assessment</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
