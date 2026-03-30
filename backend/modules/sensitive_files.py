"""
Sensitive File Discovery Engine
Detects exposure of configuration files, backups, and credentials
FIX #5: New module for discovering sensitive files
"""

import requests
import re
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import DEFAULT_TIMEOUT, USER_AGENT, DEFAULT_THREADS


class SensitiveFileDetector:
    """Detects exposed sensitive files and configuration"""
    
    def __init__(self, timeout=DEFAULT_TIMEOUT, threads=DEFAULT_THREADS):
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
        self.findings = []
        
        # Sensitive files and their indicators
        self.sensitive_files = {
            # Configuration files
            '.env': ['DATABASE_', 'API_KEY', 'SECRET', 'PASSWORD'],
            '.env.local': ['DATABASE_', 'API_KEY', 'SECRET'],
            '.env.backup': ['DATABASE_', 'API_KEY', 'SECRET'],
            'web.config': ['connectionString', 'password', 'apiKey'],
            'config.php': ['database', 'password', 'api_key', 'secret'],
            'settings.py': ['DATABASES', 'SECRET_KEY', 'API_KEY'],
            'appsettings.json': ['ConnectionStrings', 'ApiKey', 'Secret'],
            'application.properties': ['spring.datasource', 'api.key'],
            'application.yml': ['spring.datasource', 'api.key'],
            '.htaccess': ['RewriteRule', 'Deny from'],
            'web.xml': ['param-name', 'param-value'],
            'pom.xml': ['artifactId', 'version'],
            'package.json': ['dependencies', 'devDependencies'],
            'requirements.txt': ['Flask', 'Django', 'requests'],
            'docker-compose.yml': ['environment', 'password'],
            'docker-compose.yaml': ['environment', 'password'],
            'Dockerfile': ['ENV', 'RUN', 'EXPOSE'],
            '.dockerignore': [],
            '.gitignore': [],
            '.git/config': ['url', 'fetch'],
            '.git/HEAD': [],
            
            # Backup files
            'backup.zip': [],
            'backup.tar': [],
            'backup.tar.gz': [],
            'db.backup': [],
            'database.backup': [],
            'database.sql': [],
            'dump.sql': [],
            '.sql': [],
            '.bak': [],
            '.backup': [],
            '.old': [],
            '.copy': [],
            
            # Debug/test files
            'phpinfo.php': ['PHP Version', 'System'],
            'info.php': ['PHP Version'],
            'test.php': [],
            'debug.php': [],
            'admin.php': [],
            'wp-config.php': ['DB_NAME', 'DB_PASSWORD'],
            'config.inc.php': [],
            
            # AWS/Cloud
            '.aws/credentials': ['aws_access_key_id'],
            '.aws/config': ['region', 'output'],
            '.s3cfg': ['access_key'],
            
            # Sensitive directories
            '/backup': [],
            '/backups': [],
            '/dump': [],
            '/sql': [],
            '/.env': [],
            '/config': [],
            '/private': [],
            '/secret': [],
            '/admin': [],
            '/database': [],
        }
    
    def _make_request(self, url: str) -> Dict:
        """Make request and return response data"""
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            return {
                'status': response.status_code,
                'content': response.text,
                'headers': response.headers,
                'success': True
            }
        except Exception:
            return {'status': 0, 'content': '', 'headers': {}, 'success': False}
    
    def _extract_credentials(self, content: str) -> List[str]:
        """Extract potential credentials from content"""
        credentials = []
        
        # API Keys
        api_key_pattern = r'(?:api[_-]?key|apikey|api_token|token)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?'
        matches = re.findall(api_key_pattern, content, re.IGNORECASE)
        credentials.extend([f"API Key: {m}" for m in matches])
        
        # Passwords
        password_pattern = r'(?:password|passwd|pwd)\s*[=:]\s*["\']?([^"\'\s,;]{6,})["\']?'
        matches = re.findall(password_pattern, content, re.IGNORECASE)
        credentials.extend([f"Password: {m}" for m in matches])
        
        # Database URLs
        db_pattern = r'(?:mysql|postgresql|mongodb|redis)://[^"\'<>\s]+'
        matches = re.findall(db_pattern, content, re.IGNORECASE)
        credentials.extend([f"DB URL: {m}" for m in matches])
        
        # AWS Keys
        aws_pattern = r'AKIA[0-9A-Z]{16}'
        matches = re.findall(aws_pattern, content)
        credentials.extend([f"AWS Key: {m}" for m in matches])
        
        return credentials
    
    def _analyze_file_content(self, file_path: str, content: str) -> Dict:
        """Analyze file content for sensitive data"""
        finding = {
            'file': file_path,
            'indicators': [],
            'credentials': [],
            'risk_level': 'LOW'
        }
        
        # Check for sensitive keywords
        sensitive_keywords = [
            'password', 'secret', 'api_key', 'token', 'database_url',
            'db_host', 'db_user', 'db_password', 'private_key',
            'access_key', 'secret_key', 'auth', 'credential'
        ]
        
        content_lower = content.lower()
        for keyword in sensitive_keywords:
            if keyword in content_lower:
                finding['indicators'].append(keyword)
                finding['risk_level'] = 'HIGH'
        
        # Try to extract credentials
        creds = self._extract_credentials(content)
        if creds:
            finding['credentials'] = creds
            finding['risk_level'] = 'CRITICAL'
        
        return finding
    
    def check_sensitive_file(self, base_url: str, file_path: str) -> Dict:
        """Check if a sensitive file is accessible"""
        if not base_url.endswith('/'):
            base_url += '/'
        
        test_url = base_url.rstrip('/') + file_path
        
        response_data = self._make_request(test_url)
        
        if not response_data['success']:
            return None
        
        # File found (200 status)
        if response_data['status'] == 200:
            analysis = self._analyze_file_content(file_path, response_data['content'])
            analysis['url'] = test_url
            analysis['status'] = response_data['status']
            
            return {
                'file': file_path,
                'url': test_url,
                'status': response_data['status'],
                'found': True,
                'risk_level': analysis['risk_level'],
                'indicators': analysis['indicators'],
                'credentials': analysis['credentials'],
                'content_preview': response_data['content'][:200]
            }
        
        return None
    
    def discover_sensitive_files(self, base_url: str, additional_files: List[str] = None) -> List[Dict]:
        """
        Discover exposed sensitive files
        FIX #5: Main discovery method
        """
        print("[*] Scanning for exposed sensitive files...")
        
        files_to_check = list(self.sensitive_files.keys())
        if additional_files:
            files_to_check.extend(additional_files)
        
        findings = []
        
        # Parallel file checking
        with ThreadPoolExecutor(max_workers=min(5, self.threads)) as executor:
            futures = {
                executor.submit(self.check_sensitive_file, base_url, fpath): fpath
                for fpath in files_to_check
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)
        
        self.findings = findings
        
        print(f"[*] Sensitive file scan complete. Found: {len(findings)} files")
        for finding in findings:
            risk = finding['risk_level']
            print(f"    [{risk}] {finding['file']} ({finding['status']})")
        
        return findings
    
    def get_findings(self) -> List[Dict]:
        """Get all discovered sensitive files"""
        return self.findings
    
    def get_findings_by_risk(self, risk_level: str) -> List[Dict]:
        """Get findings by risk level"""
        return [f for f in self.findings if f['risk_level'] == risk_level]
    
    def get_critical_findings(self) -> List[Dict]:
        """Get critical findings (CRITICAL risk)"""
        return self.get_findings_by_risk('CRITICAL')


