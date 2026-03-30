#!/usr/bin/env python3
"""
Attack Surface Intelligence System v2.0
Production-grade recon and vulnerability assessment framework

Features:
  - Alive endpoint filtering (200-399 status codes only)
  - Clean CLI output with structured sections
  - Advanced vulnerability detection (SQLi, XSS, IDOR, LFI, SSRF, etc.)
  - Intelligent attack path generation
  - Optional report generation (--report, --json)
  - Verbose mode (--verbose)

Usage:
    python main.py --target example.com
    python main.py --target example.com --verbose
    python main.py --target example.com --report output.txt --json output.json
"""

import argparse
import sys
import time
import warnings
import tldextract
from pathlib import Path

# Suppress SSL warnings
warnings.filterwarnings('ignore')

# Import all modules
from modules.subdomain_discovery import SubdomainDiscovery
from modules.web_crawler import WebCrawler
from modules.js_intelligence import JSIntelligence
from modules.endpoint_extraction import EndpointExtraction
from modules.directory_discovery import DirectoryDiscovery
from modules.parameter_classifier import ParameterClassifier
from modules.vulnerability_detection import VulnerabilityDetection
from modules.risk_scoring import RiskScoring
from modules.attack_paths import AttackPathEngine
from modules.correlation import CorrelationEngine
from modules.output_formatter import OutputFormatter
from modules.alive_filter import AliveFilter
from modules.sensitive_files import SensitiveFileDetector
from config import DEFAULT_THREADS, DEFAULT_TIMEOUT


class AttackSurfaceIntelligence:
    """Main orchestrator for attack surface reconnaissance"""
    
    def __init__(self, target, threads=DEFAULT_THREADS, timeout=DEFAULT_TIMEOUT, 
                 verbose=False, sub_wordlist=None, dir_wordlist=None):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.sub_wordlist = sub_wordlist
        self.dir_wordlist = dir_wordlist
        self.domain = self.extract_domain(target)
        self.base_url = f"https://www.{self.domain}"
        
        # Initialize formatter
        self.formatter = OutputFormatter(use_colors=True, verbose=verbose)
        
        if verbose:
            print(f"[*] Initializing Attack Surface Intelligence System")
            print(f"[*] Target: {self.target}")
            print(f"[*] Domain: {self.domain}")
            print(f"[*] Threads: {self.threads}, Timeout: {self.timeout}s")
            print()
    
    @staticmethod
    def extract_domain(target):
        """Extract domain from target"""
        extracted = tldextract.extract(target)
        return f"{extracted.domain}.{extracted.suffix}"
    
    def run_reconnaissance(self):
        """Execute full reconnaissance pipeline with alive filtering"""
        start_time = time.time()
        
        # FIX #6: Initialize unified scan_data dictionary
        scan_data = {
            'target': self.target,
            'domain': self.domain,
            'base_url': self.base_url,
            'subdomains': set(),
            'alive_subdomains': set(),
            'urls': set(),
            'alive_endpoints': {},
            'endpoints': {},
            'parameters': {},
            'sensitive_files': [],
            'vulnerabilities': [],
            'attack_paths': [],
            'scored_endpoints': [],
            'js_analysis': {},
            'correlation': {},
            'tested_endpoints': 0,
            'candidate_endpoints': 0,
            'start_time': start_time
        }
        
        # Print banner
        self.formatter.print_banner()
        
        # ================================================================
        # Stage 1: Subdomain Discovery
        # ================================================================
        if self.verbose:
            print("\n[STAGE 1] SUBDOMAIN DISCOVERY")
            print("=" * 70)
        else:
            print("\n[*] Discovering subdomains...")
        
        subdomain_disco = SubdomainDiscovery(self.timeout, self.threads)
        subdomains = subdomain_disco.discover(self.domain, self.sub_wordlist)
        scan_data['subdomains'] = subdomains
        
        # ================================================================
        # Stage 2: Filter Alive Subdomains
        # ================================================================
        if self.verbose:
            print("\n[STAGE 2] FILTERING ALIVE SUBDOMAINS")
            print("=" * 70)
        else:
            print("[*] Filtering alive subdomains...")
        
        alive_filter = AliveFilter(self.timeout, self.threads, self.verbose)
        alive_subdomains = alive_filter.filter_subdomains(subdomains)
        scan_data['alive_subdomains'] = alive_subdomains
        
        # ================================================================
        # Stage 3: Web Crawling (alive subdomains only)
        # ================================================================
        if self.verbose:
            print("\n[STAGE 3] WEB CRAWLING")
            print("=" * 70)
        else:
            print("[*] Crawling web pages...")
        
        crawler = WebCrawler(self.timeout)
        
        all_urls = set()
        crawled_roots = set()
        # Crawl alive subdomains (limit for performance)
        for subdomain in list(alive_subdomains)[:5]:
            try:
                root_url = f"https://{subdomain}"
                if root_url in crawled_roots:
                    continue
                crawled_roots.add(root_url)
                urls = crawler.crawl(root_url, self.domain)
                all_urls.update(urls)
            except Exception:
                pass
        
        # Also crawl primary domain
        try:
            if self.base_url not in crawled_roots:
                urls = crawler.crawl(self.base_url, self.domain)
                all_urls.update(urls)
        except Exception:
            pass
        
        scan_data['urls'] = all_urls
        
        # ================================================================
        # Stage 4: JavaScript Analysis
        # ================================================================
        if self.verbose:
            print("\n[STAGE 4] JAVASCRIPT INTELLIGENCE")
            print("=" * 70)
        else:
            print("[*] Analyzing JavaScript files...")
        
        js_intel = JSIntelligence(self.timeout)
        js_results = js_intel.analyze_js_from_urls(all_urls, self.domain)
        scan_data['js_analysis'] = js_results
        
        # ================================================================
        # Stage 5: Endpoint Extraction (Enhanced)
        # ================================================================
        if self.verbose:
            print("\n[STAGE 5] ENDPOINT EXTRACTION")
            print("=" * 70)
        else:
            print("[*] Extracting endpoints and parameters...")
        
        endpoint_extract = EndpointExtraction(self.timeout)
        endpoints_dict = endpoint_extract.extract_from_urls(all_urls)
        
        # FIX #1 & #5: Combine with JS endpoints AND JS-extracted parameters
        endpoints_dict = endpoint_extract.combine_with_js(
            js_intel.get_endpoints(),
            js_intel.get_parameters()  # Also pass JS-extracted params
        )
        
        # FIX #2: Enrich endpoints with guessed parameters for modern web apps
        endpoints_dict = endpoint_extract.enrich_with_guessed_params()
        
        endpoints_dict = endpoint_extract.deduplicate()
        scan_data['endpoints'] = endpoints_dict
        
        # ================================================================
        # Stage 6: Directory Discovery
        # ================================================================
        if self.verbose:
            print("\n[STAGE 6] DIRECTORY DISCOVERY")
            print("=" * 70)
        else:
            print("[*] Discovering directories...")
        
        dir_disco = DirectoryDiscovery(self.timeout, self.threads)
        discovered_dirs = dir_disco.discover(self.base_url, self.dir_wordlist)
        
        # Add discovered directories to endpoints
        for dir_url in discovered_dirs:
            path = dir_url.replace(self.base_url, '')
            if path and path not in endpoints_dict:
                endpoints_dict[path] = set()
        
        # ================================================================
        # Stage 7: ALIVE ENDPOINT FILTERING (CRITICAL)
        # ================================================================
        if self.verbose:
            print("\n[STAGE 7] ALIVE ENDPOINT FILTERING")
            print("=" * 70)
        else:
            print("[*] Filtering alive endpoints (200-399)...")
        
        alive_endpoints = alive_filter.filter_endpoints(self.base_url, endpoints_dict)
        alive_count = len(alive_endpoints)
        scan_data['alive_endpoints'] = alive_endpoints
        
        if self.verbose:
            print(f"[*] Endpoints reduced: {len(endpoints_dict)} -> {alive_count} (alive only)")
        
        # Use only alive endpoints from here
        endpoints_dict = alive_endpoints
        scan_data['endpoints'] = endpoints_dict
        
        # ================================================================
        # Stage 8: Parameter Classification
        # ================================================================
        if self.verbose:
            print("\n[STAGE 8] PARAMETER CLASSIFICATION")
            print("=" * 70)
        else:
            print("[*] Classifying parameters...")
        
        param_classifier = ParameterClassifier()
        classified_params = param_classifier.classify_parameters(endpoints_dict)
        scan_data['parameters'] = classified_params
        
        # ================================================================
        # Stage 8.5: Risk Scoring (for priority) - FIX #4
        # ================================================================
        if self.verbose:
            print("\n[STAGE 8.5] ENDPOINT RISK SCORING")
            print("=" * 70)
        else:
            print("[*] Scoring endpoints for priority...")
        
        risk_scorer = RiskScoring()
        scored_endpoints = risk_scorer.score_endpoints(endpoints_dict)
        
        # FIX #4: Sort endpoints by risk level for priority-based scanning
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_endpoints = sorted(
            scored_endpoints,
            key=lambda x: (priority_order.get(x.get('risk_level'), 5), -x.get('confidence', 0))
        )
        
        # Priority-based execution: scan only top HIGH/CRITICAL endpoints (5-15 cap)
        filtered_ranked = [ep for ep in sorted_endpoints if ep.get('risk_level') in ['CRITICAL', 'HIGH']]
        if len(filtered_ranked) < 5:
            # Controlled fallback: include strongest MEDIUM entries to reach minimum coverage
            medium_ranked = [ep for ep in sorted_endpoints if ep.get('risk_level') == 'MEDIUM']
            filtered_ranked.extend(medium_ranked[: max(0, 5 - len(filtered_ranked))])

        max_endpoints = min(len(filtered_ranked), 15)
        priority_endpoint_classifications = {
            ep['endpoint']: classified_params.get(ep['endpoint'], [])
            for ep in filtered_ranked[:max_endpoints]
            if classified_params.get(ep['endpoint'], [])
        }
        
        if self.verbose:
            print(f"[*] Prioritized {len(priority_endpoint_classifications)} endpoints for vulnerability testing")
        scan_data['candidate_endpoints'] = len(priority_endpoint_classifications)

        # ================================================================
        # Stage 8.7: Sensitive File Discovery
        # ================================================================
        if self.verbose:
            print("\n[STAGE 8.7] SENSITIVE FILE DISCOVERY")
            print("=" * 70)
        else:
            print("[*] Discovering sensitive files...")

        sensitive_detector = SensitiveFileDetector(self.timeout, self.threads)
        sensitive_findings = sensitive_detector.discover_sensitive_files(self.base_url)
        scan_data['sensitive_files'] = sensitive_findings
        
        # ================================================================
        # Stage 9: Vulnerability Detection (alive endpoints only, priority order)
        # ================================================================
        if self.verbose:
            print("\n[STAGE 9] VULNERABILITY DETECTION")
            print("=" * 70)
        else:
            print("[*] Detecting vulnerabilities...")
        
        vuln_detector = VulnerabilityDetection(self.timeout, self.threads, self.verbose)
        vulnerabilities = vuln_detector.detect_vulnerabilities(
            self.base_url,
            priority_endpoint_classifications,
            max_endpoints=max_endpoints
        )
        scan_data['vulnerabilities'] = vulnerabilities
        scan_data['tested_endpoints'] = vuln_detector.tested_count
        
        # ================================================================
        # Stage 10: Score Vulnerabilities
        # ================================================================
        if self.verbose:
            print("\n[STAGE 10] VULNERABILITY SCORING")
            print("=" * 70)
        else:
            print("[*] Scoring findings...")
        
        # Re-score with complete endpoint set
        all_scored_endpoints = risk_scorer.score_endpoints(endpoints_dict)
        scored_vulns = risk_scorer.score_findings(vulnerabilities)
        scan_data['scored_endpoints'] = all_scored_endpoints
        
        # ================================================================
        # Stage 11: Attack Path Generation
        # ================================================================
        if self.verbose:
            print("\n[STAGE 11] ATTACK PATH GENERATION")
            print("=" * 70)
        else:
            print("[*] Generating attack paths...")
        
        attack_path_engine = AttackPathEngine()
        attack_paths = attack_path_engine.generate_paths(
            endpoints_dict,  # All endpoints, not just tested
            scored_vulns,
            js_intel.get_endpoints()
        )
        scan_data['attack_paths'] = attack_paths
        
        # ================================================================
        # Stage 12: Correlation
        # ================================================================
        if self.verbose:
            print("\n[STAGE 12] CORRELATION")
            print("=" * 70)
        else:
            print("[*] Correlating findings...")
        
        correlation_engine = CorrelationEngine()
        correlation = correlation_engine.correlate_all_findings(
            alive_subdomains,
            all_urls,
            endpoints_dict,
            scored_vulns,
            scored_endpoints,
            attack_paths
        )
        scan_data['correlation'] = correlation
        
        # Calculate elapsed time
        elapsed_time = time.time() - start_time
        scan_data['elapsed_time'] = elapsed_time
        
        # Return results
        return scan_data


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Attack Surface Intelligence System v2.0 - Professional Recon Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python main.py --target example.com
  python main.py --target example.com --verbose
  python main.py --target example.com --report report.txt
  python main.py --target example.com --json report.json
  python main.py --target example.com --threads 15 --timeout 10
        '''
    )
    
    parser.add_argument(
        '--target', '-t',
        required=True,
        help='Target domain or URL'
    )
    parser.add_argument(
        '--threads',
        type=int,
        default=DEFAULT_THREADS,
        help=f'Number of threads (default: {DEFAULT_THREADS})'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f'Request timeout in seconds (default: {DEFAULT_TIMEOUT})'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--report',
        metavar='FILE',
        help='Save text report to file (e.g., --report report.txt)'
    )
    parser.add_argument(
        '--json',
        metavar='FILE',
        help='Save JSON report to file (e.g., --json report.json)'
    )
    parser.add_argument(
        '--sub-wordlist',
        metavar='FILE',
        help='Custom subdomain wordlist'
    )
    parser.add_argument(
        '--dir-wordlist',
        metavar='FILE',
        help='Custom directory wordlist'
    )
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    args = parser.parse_args()
    
    try:
        # Run reconnaissance
        asi = AttackSurfaceIntelligence(
            args.target,
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose,
            sub_wordlist=args.sub_wordlist,
            dir_wordlist=args.dir_wordlist
        )
        results = asi.run_reconnaissance()
        
        # Initialize formatter for output
        formatter = OutputFormatter(
            use_colors=not args.no_color,
            verbose=args.verbose
        )
        
        # ================================================================
        # Print Console Report (always)
        # ================================================================
        formatter.print_console_report(
            target=results['target'],
            subdomains=results['subdomains'],
            urls=results['urls'],
            endpoints=results['endpoints'],
            vulnerabilities=results['vulnerabilities'],
            scored_endpoints=results['scored_endpoints'],
            attack_paths=results['attack_paths'],
            correlation=results['correlation'],
            elapsed_time=results['elapsed_time'],
            alive_count=len(results.get('alive_endpoints', {})),
            sensitive_files=results.get('sensitive_files', []),
            tested_endpoints=results.get('tested_endpoints', 0),
            candidate_endpoints=len(results.get('alive_endpoints', {}))
        )
        
        # ================================================================
        # Save Reports (only if explicitly requested)
        # ================================================================
        if args.report:
            text_report = formatter.generate_text_report(
                target=results['target'],
                subdomains=results['subdomains'],
                urls=results['urls'],
                endpoints=results['endpoints'],
                vulnerabilities=results['vulnerabilities'],
                scored_endpoints=results['scored_endpoints'],
                attack_paths=results['attack_paths'],
                correlation=results['correlation'],
                sensitive_files=results.get('sensitive_files', [])
            )
            formatter.save_report(results['target'], text_report, 'text', args.report)
        
        if args.json:
            json_report = formatter.generate_json_report(
                target=results['target'],
                subdomains=results['subdomains'],
                urls=results['urls'],
                endpoints=results['endpoints'],
                vulnerabilities=results['vulnerabilities'],
                scored_endpoints=results['scored_endpoints'],
                attack_paths=results['attack_paths'],
                correlation=results['correlation'],
                sensitive_files=results.get('sensitive_files', [])
            )
            formatter.save_report(results['target'], json_report, 'json', args.json)
        
        # Print completion message
        print(f"\n[+] Reconnaissance complete in {results['elapsed_time']:.2f} seconds")
        
        if not args.report and not args.json:
            print("[*] Use --report or --json to save reports to file")
        
        return 0
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
